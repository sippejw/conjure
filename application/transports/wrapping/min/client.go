package min

import (
	"fmt"

	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
type ClientTransport struct {
	// Parameters are fields that will be shared with the station in the registration
	Parameters *pb.GenericTransportParams

	// // state tracks fields internal to the registrar that survive for the lifetime
	// // of the transport session without being shared - i.e. local derived keys.
	// state any
}

// Name returns a string identifier for the Transport for logging
func (*ClientTransport) Name() string {
	return "min"
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (*ClientTransport) String() string {
	return "min"
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_Min
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() proto.Message {
	return t.Parameters
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *ClientTransport) SetParams(p any) error {
	params, ok := p.(*pb.GenericTransportParams)
	if !ok {
		return fmt.Errorf("unable to parse params")
	}
	t.Parameters = params

	return nil
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte, params any) (uint16, error) {
	if t.Parameters == nil || !t.Parameters.GetRandomizeDstPort() {
		return 443, nil
	}

	return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
}

// // Connect creates the connection to the phantom address negotiated in the registration phase of
// // Conjure connection establishment.
// func (t *ClientTransport) Connect(ctx context.Context, reg *cj.ConjureReg) (net.Conn, error) {
// 	// conn, err := reg.getFirstConnection(ctx, reg.TcpDialer, phantoms)
// 	// if err != nil {
// 	// 	return nil, err
// 	// }

// 	// // Send hmac(seed, str) bytes to indicate to station (min transport)
// 	// connectTag := conjureHMAC(reg.keys.SharedSecret, "MinTrasportHMACString")
// 	// conn.Write(connectTag)
// 	// return conn, nil
// 	return nil, nil
// }
