#![feature(ip)]
#![feature(let_chains)]
#![feature(associated_type_bounds)]
#![feature(path_file_prefix)]

extern crate libc;

#[macro_use]
extern crate log;
extern crate maxminddb;

mod common;
mod limit;
mod flows;
mod packet_handler;
mod ip;

use core::slice;
use std::{ffi::CStr, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, error::Error};

use common::{parse_asn_list, parse_cc_list, parse_targets, debug_warn};
use libc::{c_char, c_void, size_t};
use packet_handler::{PacketHandler};
use pcap_file::{pcapng::{PcapNgWriter, blocks::interface_description::InterfaceDescriptionBlock}, DataLink};
use std::fs::{File};
use flate2::write::GzEncoder;
use flate2::Compression;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use parse_duration::parse;

#[repr(C)]
pub struct RustGlobalsStruct
{
    flag: Arc<AtomicBool>,
    handler: Arc<Mutex<PacketHandler>>,
    arc_writer: Arc<Mutex<PcapNgWriter<GzEncoder<File>>>>,
    timeout: Option<std::time::Duration>,
    gre_offset: usize,
}

#[no_mangle]
pub extern "C" fn rust_init(asn_filter_ptr: *const c_char, cc_filter_ptr: *const c_char, t_ptr: *const c_char, lp_c: u64, lpa_c: u64, lpc_c: u64, lfa_c: u64, lfc_c: u64, lf_c: u64, ppf_c: u64, asn_db_ptr: *const c_char, cc_db_ptr: *const c_char, v4: bool, v6: bool, out_ptr: *const c_char, gre_offset: usize, timeout_ptr: *const c_char) -> RustGlobalsStruct {

    let lp = match lp_c {
        0 => None,
        _ => Some(lp_c)
    };
    let lpa = match lpa_c {
        0 => None,
        _ => Some(lpa_c)
    };
    let lpc = match lpc_c {
        0 => None,
        _ => Some(lpc_c)
    };
    let lfa = match lfa_c {
        0 => None,
        _ => Some(lfa_c)
    };
    let lfc = match lfc_c {
        0 => None,
        _ => Some(lfc_c)
    };
    let lf = match lf_c {
        0 => None,
        _ => Some(lf_c)
    };
    let ppf = match ppf_c {
        0 => None,
        _ => Some(ppf_c)
    };


    let flag = Arc::new(AtomicBool::new(false));

    let asn_filter_c_str: &CStr = unsafe { CStr::from_ptr(asn_filter_ptr) };
    let asn_filter_string: String = asn_filter_c_str.to_str().unwrap().to_owned();

    let cc_filter_c_str: &CStr = unsafe { CStr::from_ptr(cc_filter_ptr) };
    let cc_filter_string: String = cc_filter_c_str.to_str().unwrap().to_owned();

    let asn_list = parse_asn_list(Some(asn_filter_string));
    let cc_list = parse_cc_list(Some(cc_filter_string));

    #[cfg(not(debug_assertions))]
    simple_logger::init_with_level(log::Level::Warn).unwrap();

    #[cfg(debug_assertions)]
    debug_warn();

    trace!(
        "{:?}\n{asn_list:#?} {:?}\n{cc_list:#?} {:?}",
        lp,
        lpa,
        lpc
    );

    let key_list: Vec<limit::Hashable> = if lpa.is_some() || lfa.is_some() {
        asn_list.iter().map(limit::Hashable::from).collect()
    } else if lpc.is_some() || lfc.is_some() {
        cc_list.iter().map(limit::Hashable::from).collect()
    } else {
        vec![]
    };

    // let limiter = limit::build(
    let limits = flows::Limits {
        lpk: lpa.unwrap_or(lpc.unwrap_or(0)),
        lfk: lfa.unwrap_or(lfc.unwrap_or(0)),
        lp: lp.unwrap_or(0),
        lf: lf.unwrap_or(0),
        lppf: ppf.unwrap_or(0),
    };
    let unlimited = limits.is_unlimited();
    let limit_state = limits.into_limiter(key_list, Arc::clone(&flag));

    let t_c_str: &CStr = unsafe { CStr::from_ptr(t_ptr) };
    let t_string: String = t_c_str.to_str().unwrap().to_owned();

    let limiter = if unlimited { None } else { Some(limit_state) };
    let target_subnets = parse_targets(t_string);

    let asn_db_c_str: &CStr = unsafe { CStr::from_ptr(asn_db_ptr) };
    let asn_db_string: String = asn_db_c_str.to_str().unwrap().to_owned();

    let cc_db_c_str: &CStr = unsafe { CStr::from_ptr(cc_db_ptr) };
    let cc_db_string: String = cc_db_c_str.to_str().unwrap().to_owned();

    let handler = Arc::new(Mutex::new(PacketHandler::create(
        &asn_db_string,
        &cc_db_string,
        target_subnets,
        limiter,
        cc_list,
        asn_list,
        v4,
        v6,
    ).unwrap()));

    let out_c_str: &CStr = unsafe { CStr::from_ptr(out_ptr) };
    let out_string: String = out_c_str.to_str().unwrap().to_owned();

    let file = File::create(out_string).unwrap();
    let gzip_file = GzEncoder::new(file, Compression::default());
    let mut writer = PcapNgWriter::new(gzip_file).expect("failed to build writer");
    let ip4_iface = InterfaceDescriptionBlock {
        linktype: DataLink::IPV4,
        snaplen: 0xFFFF,
        options: vec![],
    };
    let ip6_iface = InterfaceDescriptionBlock {
        linktype: DataLink::IPV6,
        snaplen: 0xFFFF,
        options: vec![],
    };
    writer.write_pcapng_block(ip4_iface).unwrap();
    writer.write_pcapng_block(ip6_iface).unwrap();
    let arc_writer = Arc::new(Mutex::new(writer));

    if !flag.load(Ordering::Relaxed) {
        flag.store(true, Ordering::Relaxed);
    }

    let timeout_c_str: &CStr = unsafe { CStr::from_ptr(timeout_ptr) };
    let timeout_string: String = timeout_c_str.to_str().unwrap().to_owned();
    let timeout = Some(parse(&timeout_string).unwrap());

    RustGlobalsStruct {
        flag,
        handler,
        arc_writer,
        timeout,
        gre_offset,
    }
}

#[no_mangle]
pub extern "C" fn rust_process_packet(globals_ptr: *mut RustGlobalsStruct, raw_ethframe: *mut c_void, frame_len: size_t) {
    let globals = unsafe { &mut *globals_ptr };
    let rust_view = unsafe {
        slice::from_raw_parts_mut(raw_ethframe as *mut u8, frame_len as usize)
    };
    if globals.flag.load(Ordering::Relaxed) {
        return
    }
    match EthernetPacket::new(&rust_view[globals.gre_offset..]) {
        Some(pkt) => {
            let data = pkt.payload();
        }
        None => return,
    };
}
