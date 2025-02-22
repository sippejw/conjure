package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/refraction-networking/conjure/application/log"
)

const proxyStallTimeout = 30 * time.Second

var (
	// errConnReset replaces the reset error in the halfpipe to remove ips and extra bytes
	errConnReset = errors.New("rst")

	// errConnTimeout replaces the ip.timeout error in the halfpipe to remove ips and extra bytes
	errConnTimeout = errors.New("timeout")

	// errBrokenPipe replaces the write: broken pipe error to prevent client IP logging
	errBrokenPipe = errors.New("broken_pipe")

	// replaces refused error to prevent client IP logging
	errConnRefused = errors.New("refused")

	// errUnreachable replaces unreachable error to prevent client IP logging
	errUnreachable = errors.New("unreachable")

	// errConnAborted replaces aborted error to prevent client IP logging
	errConnAborted = errors.New("aborted")
)

func generalizeErr(err error) error {
	if err == nil {
		return nil
	} else if errors.Is(err, net.ErrClosed) {
		return nil
	} else if errors.Is(err, io.EOF) {
		return nil
	} else if errors.Is(err, syscall.ECONNRESET) {
		return errConnReset
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		return errConnRefused
	} else if errors.Is(err, syscall.ECONNABORTED) {
		return errConnAborted
	} else if errors.Is(err, syscall.EPIPE) {
		return errBrokenPipe
	} else if errors.Is(err, syscall.EHOSTUNREACH) {
		return errUnreachable
	} else if errN, ok := err.(net.Error); ok && errN.Timeout() {
		return errConnTimeout
	}

	// if it is not a well known error, return it
	return err
}

// this function is kinda ugly, uses undecorated logger, and passes things around it doesn't have to pass around
// TODO: refactor
func halfPipe(src net.Conn, dst net.Conn,
	wg *sync.WaitGroup,
	oncePrintErr *sync.Once,
	logger *log.Logger,
	tag string, stats *tunnelStats) {

	var proxyStartTime = time.Now()
	isUpload := strings.HasPrefix(tag, "Up")

	// Set deadlines in case either side disappears.
	err := src.SetDeadline(time.Now().Add(proxyStallTimeout))
	if err != nil {
		logger.Errorln("error setting deadline for src conn: ", tag)
	}
	err = dst.SetDeadline(time.Now().Add(proxyStallTimeout))
	if err != nil {
		logger.Errorln("error setting deadline for dst conn: ", tag)
	}

	// using io.CopyBuffer doesn't let us see
	// bytes / second (until very end of connect, then only avg)
	// But io.CopyBuffer is very performant:
	// actually doesn't use a buffer at all, just splices sockets
	// together at the kernel level.
	//
	// We could try to use io.CopyN in a loop or something that
	// gives us occasional bytes. CopyN would not splice, though
	// (uses a LimitedReader that only calls Read)
	//buf := bufferPool.Get().([]byte)
	//written, err := io.CopyBuffer(dst, src, buf)

	// On closer examination, it seems this code below seems about
	// as performant. It's not using splice, but for CO comcast / curveball:
	//				io.CopyBuffer	Read/Write
	// curveball CPU	~2%				~2%
	// DL 40MB time		~11.5s			~11.6s
	// So while io.CopyBuffer is faster, it's not significantly faster

	// If we run into perf problems, we can revert

	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])

			// Update stats:
			stats.addBytes(int64(nw), isUpload)
			if isUpload {
				Stat().AddBytesUp(int64(nw))
			} else {
				Stat().AddBytesDown(int64(nw))
			}

			if ew == nil && nw != nr {
				ew = io.ErrShortWrite
			}

			if ew != nil {
				if e := generalizeErr(ew); e != nil {
					if isUpload {
						stats.CovertConnErr = e.Error()
					} else {
						stats.ClientConnErr = e.Error()
					}
				}
				break
			}

		}
		if er != nil {
			if e := generalizeErr(er); e != nil {
				if isUpload {
					stats.ClientConnErr = e.Error()
				} else {
					stats.CovertConnErr = e.Error()
				}
			}
			break
		}

		// refresh stall timeout - set both because it only happens on write
		// so if connection is sending traffic unidirectionally we prevent
		// the receiving side from timing out.
		err := src.SetDeadline(time.Now().Add(proxyStallTimeout))
		if err != nil {
			logger.Errorln("error setting deadline for src conn: ", tag)
		}
		err = dst.SetDeadline(time.Now().Add(proxyStallTimeout))
		if err != nil {
			logger.Errorln("error setting deadline for dst conn: ", tag)
		}
	}

	// Close dst
	errDst := dst.Close()
	if err = generalizeErr(errDst); err != nil {
		if errors.Is(err, errConnTimeout) {
			stats.CovertConnErr = err.Error()
			stats.ClientConnErr = err.Error()
		} else if isUpload {
			if stats.CovertConnErr == "" {
				stats.CovertConnErr = err.Error()
			}
		} else {
			if stats.ClientConnErr == "" {
				stats.ClientConnErr = err.Error()
			}
		}
	}

	// Close src
	errSrc := src.Close()
	if err = generalizeErr(errSrc); err != nil {
		if errors.Is(err, errConnTimeout) {
			stats.CovertConnErr = err.Error()
			stats.ClientConnErr = err.Error()
		} else if isUpload {
			if stats.ClientConnErr == "" {
				stats.ClientConnErr = err.Error()
			}
		} else {
			if stats.CovertConnErr == "" {
				stats.CovertConnErr = err.Error()
			}
		}
	}

	// Finalize tunnel stats
	proxyEndTime := time.Since(proxyStartTime)
	stats.duration(int64(proxyEndTime/time.Millisecond), isUpload)
	stats.completed(isUpload)
	wg.Done()
}

// Proxy take a registration and a net.Conn and forwards client traffic to the
// clients covert destination.
func Proxy(reg *DecoyRegistration, clientConn net.Conn, logger *log.Logger) {

	// New successful connection to station for this registration
	atomic.AddInt64(&reg.tunnelCount, 1)

	tunStats := &tunnelStats{
		proxyStats: getProxyStats(),

		PhantomAddr:    reg.PhantomIp.String(),
		PhantomDstPort: uint(reg.PhantomPort),

		TunnelCount: uint(atomic.LoadInt64(&reg.tunnelCount)),
		ASN:         reg.regASN,
		CC:          reg.regCC,
		Transport:   reg.Transport.String(),
		Registrar:   reg.RegistrationSource.String(),
		V6:          reg.PhantomIp.To4() == nil,
		LibVer:      uint(reg.clientLibVer),
		Gen:         uint(reg.DecoyListVersion),
	}

	covertConn, err := net.Dial("tcp", reg.Covert)
	if e := generalizeErr(err); e != nil {
		tunStats.CovertDialErr = e.Error()
	}

	// Any common error that is a non-station issue should have covert IP
	// removed.
	if tunStats.CovertDialErr != "" {
		tunStats.Print(logger)
		// logger.Errorf("failed to dial target: %s", err)
		return
	}

	defer covertConn.Close()

	if reg.Flags.GetProxyHeader() {
		err = writePROXYHeader(covertConn, clientConn.RemoteAddr().String())
		if err != nil {
			logger.Errorf("failed to send PROXY header: %s", err)
			return
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	getProxyStats().addSession()

	go halfPipe(clientConn, covertConn, &wg, &oncePrintErr, logger, "Up "+reg.IDString(), tunStats)
	go halfPipe(covertConn, clientConn, &wg, &oncePrintErr, logger, "Down "+reg.IDString(), tunStats)
	wg.Wait()
	getProxyStats().removeSession()

	tunStats.Print(logger)
}

func writePROXYHeader(conn net.Conn, originalIPPort string) error {

	if len(originalIPPort) == 0 {
		return errors.New("can't write PROXY header: empty IP")
	}
	transportProtocol := "TCP4"
	if !strings.Contains(originalIPPort, ".") {
		transportProtocol = "TCP6"
	}
	host, port, err := net.SplitHostPort(originalIPPort)
	if err != nil {
		return err
	}
	proxyHeader := fmt.Sprintf("PROXY %s %s 127.0.0.1 %s 1234\r\n", transportProtocol, host, port)
	_, err = conn.Write([]byte(proxyHeader))
	return err
}

type tunnelStats struct {
	proxyStats *ProxyStats

	Duration  int64
	BytesUp   int64
	BytesDown int64

	CovertDialErr string
	CovertConnErr string
	ClientConnErr string

	PhantomAddr    string
	PhantomDstPort uint

	TunnelCount   uint
	V6            bool
	ASN           uint   `json:",omitempty"`
	CC            string `json:",omitempty"`
	Transport     string `json:",omitempty"`
	Registrar     string `json:",omitempty"`
	LibVer        uint
	Gen           uint
	TransportOpts []string `json:",omitempty"`
	RegOpts       []string `json:",omitempty"`
	Tags          []string `json:",omitempty"`
}

func (ts *tunnelStats) Print(logger *log.Logger) {
	tunStatsStr, _ := json.Marshal(ts)
	logger.Printf("proxy closed %s", tunStatsStr)
}

func (ts *tunnelStats) completed(isUpload bool) {
	if isUpload {
		ts.proxyStats.addCompleted(ts.BytesUp, isUpload)
	} else {
		ts.proxyStats.addCompleted(ts.BytesDown, isUpload)
	}
}

func (ts *tunnelStats) duration(duration int64, isUpload bool) {
	// only set duration once, so that the first to close gives us the (real) lower bound on tunnel
	// duration.
	if atomic.LoadInt64(&ts.Duration) == 0 {
		atomic.StoreInt64(&ts.Duration, duration)
	}
}

func (ts *tunnelStats) addBytes(n int64, isUpload bool) {
	if isUpload {
		atomic.AddInt64(&ts.BytesUp, n)
	} else {
		atomic.AddInt64(&ts.BytesDown, n)
	}
	ts.proxyStats.addBytes(int64(n), isUpload)
}

// ProxyStats track metrics about byte transfer.
type ProxyStats struct {
	time.Time // epoch start time

	sessionsProxying int64 // Number of open Proxy connections (count - not reset)

	newBytesUp   int64 // Number of bytes transferred during epoch
	newBytesDown int64 // Number of bytes transferred during epoch

	completeBytesUp   int64 // number of bytes transferred through completed connections UP
	completeBytesDown int64 // number of bytes transferred through completed connections DOWN

	zeroByteTunnelsUp   int64 // number of closed tunnels that uploaded 0 bytes
	zeroByteTunnelsDown int64 // number of closed tunnels that downloaded 0 bytes
	completedSessions   int64 // number of completed sessions
}

// PrintAndReset implements the stats interface
func (s *ProxyStats) PrintAndReset(logger *log.Logger) {
	s.printStats(logger)
	s.reset()
}

func (s *ProxyStats) printStats(logger *log.Logger) {
	// prevent div by 0 if thread starvation happens
	var epochDur float64 = math.Max(float64(time.Since(s.Time).Milliseconds()), 1)

	// fmtStr := "proxy-stats: %d (%f/s) up %d (%f/s) down %d completed %d 0up %d 0down  %f avg-non-0-up, %f avg-non-0-down"
	fmtStr := "proxy-stats:%d %d %f %d %f %d %d %d %f %f"

	completedSessions := atomic.LoadInt64(&s.completedSessions)
	zbtu := atomic.LoadInt64(&s.zeroByteTunnelsUp)
	zbtd := atomic.LoadInt64(&s.zeroByteTunnelsDown)

	logger.Infof(fmtStr,
		atomic.LoadInt64(&s.sessionsProxying),
		atomic.LoadInt64(&s.newBytesUp),
		float64(atomic.LoadInt64(&s.newBytesUp))/epochDur*1000,
		atomic.LoadInt64(&s.newBytesDown),
		float64(atomic.LoadInt64(&s.newBytesDown))/epochDur*1000,
		completedSessions,
		zbtu,
		zbtd,
		float64(atomic.LoadInt64(&s.completeBytesUp))/math.Max(float64(completedSessions-zbtu), 1),
		float64(atomic.LoadInt64(&s.completeBytesDown))/math.Max(float64(completedSessions-zbtd), 1),
	)
}

// Reset implements the stats interface
func (s *ProxyStats) Reset() {
	s.reset()
}

func (s *ProxyStats) reset() {
	atomic.StoreInt64(&s.newBytesUp, 0)
	atomic.StoreInt64(&s.newBytesDown, 0)
	atomic.StoreInt64(&s.completeBytesUp, 0)
	atomic.StoreInt64(&s.completeBytesDown, 0)
	atomic.StoreInt64(&s.zeroByteTunnelsUp, 0)
	atomic.StoreInt64(&s.zeroByteTunnelsDown, 0)
	atomic.StoreInt64(&s.completedSessions, 0)
}

func (s *ProxyStats) addSession() {
	atomic.AddInt64(&s.sessionsProxying, 1)
}

func (s *ProxyStats) removeSession() {
	atomic.AddInt64(&s.sessionsProxying, -1)
}

func (s *ProxyStats) addCompleted(nb int64, isUpload bool) {
	if isUpload {
		atomic.AddInt64(&s.completeBytesUp, nb)
		if nb == 0 {
			atomic.AddInt64(&s.zeroByteTunnelsUp, 1)
		}

		// Only add to session count on closed upload stream to prevent double count
		atomic.AddInt64(&s.completedSessions, 1)
	} else {
		atomic.AddInt64(&s.completeBytesDown, nb)
		if nb == 0 {
			atomic.AddInt64(&s.zeroByteTunnelsDown, 1)
		}
	}

}

func (s *ProxyStats) addBytes(nb int64, isUpload bool) {
	if isUpload {
		atomic.AddInt64(&s.newBytesUp, nb)
	} else {
		atomic.AddInt64(&s.newBytesDown, nb)
	}
}

var proxyStatsInstance ProxyStats
var proxyStatsOnce sync.Once

func initProxyStats() {
	proxyStatsInstance = ProxyStats{}
}

// GetProxyStats returns our singleton for proxy stats
func GetProxyStats() *ProxyStats {
	return getProxyStats()
}

// getProxyStats returns our singleton for proxy stats
func getProxyStats() *ProxyStats {
	proxyStatsOnce.Do(initProxyStats)
	return &proxyStatsInstance
}

// // ProxyFactory returns an internal proxy
// func ProxyFactory(reg *DecoyRegistration, proxyProtocol uint) func(*DecoyRegistration, *net.TCPConn, net.IP) {
// 	switch proxyProtocol {
// 	case 0:
// 		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
// 			twoWayProxy(reg, clientConn, originalDstIP)
// 		}
// 	case 1:
// 		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
// 			threeWayProxy(reg, clientConn, originalDstIP)
// 		}
// 	case 2:
// 		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
// 			// Obfs4 handler
// 		}
// 	default:
// 		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
// 		}
// 	}
// }

/*
func twoWayProxy(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
	var err error
	originalDst := originalDstIP.String()
	notReallyOriginalSrc := clientConn.RemoteAddr().String()
	flowDescription := fmt.Sprintf("[%s -> %s (covert=%s)] ",
		notReallyOriginalSrc, originalDst, reg.Covert)
	logger := log.New(os.Stdout, "[2WP] "+flowDescription, log.Ldate|log.Lmicroseconds)
	logger.Debugln("new flow")

	covertConn, err := net.Dial("tcp", reg.Covert)
	if err != nil {
		logger.Errorf("failed to dial target: %s", err)
		return
	}
	defer covertConn.Close()

	if reg.Flags.GetProxyHeader() {
		err = writePROXYHeader(covertConn, clientConn.RemoteAddr().String())
		if err != nil {
			logger.Errorf("failed to send PROXY header to covert: %s", err)
			return
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	go halfPipe(clientConn, covertConn, &wg, &oncePrintErr, logger, "Up")
	go halfPipe(covertConn, clientConn, &wg, &oncePrintErr, logger, "Down")
	wg.Wait()
}
*/

/*

const (
	tlsRecordTypeChangeCipherSpec = byte(20)
	tlsRecordTypeHandshake        = byte(22)
	// tlsRecordTypeAlert            = byte(21)
	// tlsRecordTypeApplicationData  = byte(23)
	// tlsRecordTypeHearbeat         = byte(24)
)

const (
	TlsHandshakeTypeHelloRequest       = byte(0)
	TlsHandshakeTypeClientHello        = byte(1)
	TlsHandshakeTypeServerHello        = byte(2)
	TlsHandshakeTypeNewSessionTicket   = byte(4)
	TlsHandshakeTypeCertificate        = byte(11)
	TlsHandshakeTypeServerKeyExchange  = byte(12)
	TlsHandshakeTypeCertificateRequest = byte(13)
	TlsHandshakeTypeServerHelloDone    = byte(14)
	TlsHandshakeTypeCertificateVerify  = byte(15)
	TlsHandshakeTypeClientKeyExchange  = byte(16)
	TlsHandshakeTypeFinished           = byte(20)
	TlsHandshakeTypeCertificateStatus  = byte(22)
	TlsHandshakeTypeNextProtocol       = byte(67)
)

const (
	TdFlagUploadOnly  = uint8(1 << 7)
	TdFlagDarkDecoy   = uint8(1 << 6)
	TdFlagProxyHeader = uint8(1 << 1)
	TdFlagUseTIL      = uint8(1 << 0)
)

func threeWayProxy(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
	maskHostPort := reg.Mask
	targetHostPort := reg.Covert
	masterSecret := reg.Keys.MasterSecret[:]
	originalDst := originalDstIP.String()
	notReallyOriginalSrc := clientConn.LocalAddr().String()

	flowDescription := fmt.Sprintf("[%s -> %s(%v) -> %s] ",
		notReallyOriginalSrc, originalDst, maskHostPort, targetHostPort)
	logger := log.New(os.Stdout, "[3WP] "+flowDescription, log.Ldate|log.Lmicroseconds)

	if _, mPort, err := net.SplitHostPort(maskHostPort); err != nil {
		maskHostPort = net.JoinHostPort(maskHostPort, "443")
	} else {
		if mPort != "443" {
			logger.Errorf("port %v is not allowed in masked host", mPort)
			return
		}
	}
	logger.Debugln("new flow")

	maskedConn, err := net.DialTimeout("tcp", maskHostPort, time.Second*10)
	if err != nil {
		logger.Errorf("failed to dial masked host: %v", err)
		return
	}
	defer maskedConn.Close()

	// TODO: set timeouts

	var clientRandom, serverRandom [32]byte
	var cipherSuite uint16

	clientBufConn := makeBufferedReaderConn(clientConn, bufio.NewReader(clientConn))
	serverBufConn := makeBufferedReaderConn(maskedConn, bufio.NewReader(maskedConn))

	// readFromClientAndParse returns when handshake is over
	// returned error signals if there were any errors reading/writing
	// If readFromClientAndParse returns successfully, following variables will be set:
	//    clientRandom: Client Random
	//    clientBufferedRecordSize: size of TLS record(+header) that will be sitting in clientBufConn
	clientBufferedRecordSize := 0
	readFromClientAndParse := func() error {
		var clientRandomParsed bool
		for {
			const outerRecordHeaderLen = int(5)
			var outerTlsHeader []byte
			outerTlsHeader, err := clientBufConn.Peek(outerRecordHeaderLen)
			if err != nil {
				return err
			}
			outerRecordType := uint8(outerTlsHeader[0])
			// outerRecordTlsVersion := binary.BigEndian.Uint16(outerTlsHeader[1:3])
			outerRecordLength := int(binary.BigEndian.Uint16(outerTlsHeader[3:5]))

			if outerRecordType != tlsRecordTypeHandshake && outerRecordType != tlsRecordTypeChangeCipherSpec {
				clientBufferedRecordSize = outerRecordHeaderLen + outerRecordLength
				return nil
			}

			if outerRecordType == tlsRecordTypeHandshake && !clientRandomParsed {
				// next 38 bytes include type(1), length(3), version(2), clientRandom(32)
				innerTlsHeader, err := clientBufConn.Peek(outerRecordHeaderLen + 38)
				if err != nil {
					return err
				}
				// innerRecordType := uint8(innerTlsHeader[5])
				// innerRecordTlsLength := binary.BigEndian.Uint24(innerTlsHeader[6:9])
				// innerRecordVersion := binary.BigEndian.Uint16(innerTlsHeader[10:11])
				copy(clientRandom[:], innerTlsHeader[11:])
				clientRandomParsed = true
			}

			_, err = io.CopyN(serverBufConn, clientBufConn, int64(outerRecordHeaderLen+outerRecordLength))
			if err != nil {
				return err
			}
		}
	}

	// readFromServerAndParse returns when handshake is over
	// returned error signals if there were any errors reading/writing
	// may set serverRandom
	readFromServerAndParse := func() error {
		for {
			const outerRecordHeaderLen = 5
			tlsHeader, err := serverBufConn.Peek(outerRecordHeaderLen)
			if err != nil {
				return err
			}
			outerRecordType := uint8(tlsHeader[0])
			// outerRecordTlsVersion := binary.BigEndian.Uint16(tlsHeader[1:3])
			outerRecordLength := binary.BigEndian.Uint16(tlsHeader[3:5])

			if outerRecordType != tlsRecordTypeHandshake && outerRecordType != tlsRecordTypeChangeCipherSpec {
				return nil
			}

			if outerRecordLength >= 39 {
				// next 38 bytes are type(1), length(3), version(2), then serverRandom(32)
				tlsHeader, err = serverBufConn.Peek(outerRecordHeaderLen + 39)
				if err != nil {
					return err
				}
				innerRecordType := uint8(tlsHeader[5])
				// innerRecordTlsLength := binary.BigEndian.Uint24(tlsHeader[6:9])
				// innerRecordVersion := binary.BigEndian.Uint16(tlsHeader[10:11])

				if innerRecordType == TlsHandshakeTypeServerHello {
					copy(serverRandom[:], tlsHeader[11:43])
					sessionIdLen := int(tlsHeader[43])
					tlsHeader, err = serverBufConn.Peek(outerRecordHeaderLen + 39 + sessionIdLen + 2)
					if err != nil {
						return err
					}
					cipherSuite = binary.BigEndian.Uint16(tlsHeader[outerRecordHeaderLen+39+sessionIdLen : outerRecordHeaderLen+39+sessionIdLen+2])
				}
				// then goes compressionMethod(1), extensionsLen(2), extensions(extensionsLen)
			}

			_, err = io.CopyN(clientBufConn, serverBufConn, outerRecordHeaderLen+int64(outerRecordLength))
			if err != nil {
				return err
			}
		}
	}

	serverErrChan := make(chan error)
	go func() {
		_err := readFromServerAndParse()
		serverErrChan <- _err
	}()

	err = readFromClientAndParse()
	if err != nil {
		logger.Errorf("failed to readFromClientAndParse: %v", err)
		return
	}

	// at this point:
	//   readFromClientAndParse exited and there's unread non-handshake data in the conn
	//   readFromServerAndParse is still in Peek()
	firstAppData, err := clientBufConn.Peek(clientBufferedRecordSize)
	if err != nil {
		logger.Errorf("failed to peek into first app data: %v", err)
		return
	}

	p1, p2 := net.Pipe()

	inMemTlsConn := tls.MakeConnWithCompleteHandshake(
		p1, tls.VersionTLS12, // TODO: parse version!
		cipherSuite, masterSecret, clientRandom[:], serverRandom[:], false)

	go func() {
		_, err := p2.Write(firstAppData)
		logger.Errorf("error closing %s", err)

		p2.Close()
	}()

	var finalTargetConn net.Conn // either connection to the masked site or to real requested target
	var finalClientConn net.Conn // original conn or forgedTlsConn

	finalTargetConn = serverBufConn
	finalClientConn = clientBufConn

	decryptedFirstAppData, err := io.ReadAll(inMemTlsConn)
	if err != nil || len(decryptedFirstAppData) == 0 {
		logger.Debugf("not tagged: %s", err)
	} else {
		// almost success! now need to dial targetHostPort (TODO: do it in advance!)
		targetConn, err := net.Dial("tcp", targetHostPort)
		if err != nil {
			logger.Errorf("failed to dial target: %s", err)
		} else {
			logger.Debugf("flow is tagged")
			defer targetConn.Close()
			serverBufConn.Close()
			forgedTlsConn := tls.MakeConnWithCompleteHandshake(
				clientBufConn, tls.VersionTLS12,
				cipherSuite, masterSecret, clientRandom[:], serverRandom[:], false)
			finalClientConn = forgedTlsConn
			finalTargetConn = targetConn
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	go halfPipe(finalClientConn, finalTargetConn, &wg, &oncePrintErr, logger, "Up")

	go func() {
		// wait for readFromServerAndParse to exit first, as it probably haven't seen appdata yet
		select {
		case <-serverErrChan:
			halfPipe(finalClientConn, finalTargetConn, &wg, &oncePrintErr, logger, "Down")
		case <-time.After(10 * time.Second):
			finalClientConn.Close()
			wg.Done()
		}
	}()
	wg.Wait()
	// closes for all the things are deferred
}
*/
