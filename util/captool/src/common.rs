use ipnet::IpNet;
#[cfg(debug_assertions)]
use std::io::stdin;
use log::debug;

pub fn parse_asn_list(input: Option<String>) -> Vec<u32> {
    match input {
        None => vec![],
        Some(s) => {
            if s.is_empty() {
                vec![]
            } else {
                let mut out = vec![];
                for s in s.split(',') {
                    out.push(s.trim().parse().unwrap());
                }
                out
            }
        }
    }
}

pub fn parse_cc_list(input: Option<String>) -> Vec<String> {
    match input {
        None => vec![],
        Some(s) => {
            if s.is_empty() {
                vec![]
            } else {
                s.split(',').map(|s| s.trim().to_string()).collect()
            }
        }
    }
}

pub fn parse_targets(input: String) -> Vec<IpNet> {
    // vec!["192.122.190.0/24".parse()?]
    if input.is_empty() {
        return vec![];
    }

    let mut out = vec![];
    for s in input.split(',') {
        if let Ok(subnet) = s.trim().parse() {
            out.push(subnet);
            debug!("adding target: {subnet}");
        } else {
            warn!("failed to parse subnet: \"{s}\" continuing");
        }
    }
    out
}

#[cfg(debug_assertions)]
pub fn debug_warn() {
    println!("WARNING - running in debug mode. Press enter to continue:");
    let mut input_text = String::new();
    stdin()
        .read_line(&mut input_text)
        .expect("failed to read from stdin");

    simple_logger::init_with_level(log::Level::Debug).unwrap();
    debug!("Debug enabled")
}
