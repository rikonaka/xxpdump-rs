use bincode::Decode;
use bincode::Encode;
use chrono::Local;
use clap::Parser;
#[cfg(feature = "libpcap")]
use pcap::Device;
#[cfg(feature = "libpnet")]
use pcapture;
#[cfg(feature = "libpnet")]
use pcapture::Device;
#[cfg(feature = "libpnet")]
use pnet::ipnetwork::IpNetwork;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use prettytable::row;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::iter::zip;
#[cfg(feature = "libpcap")]
use std::net::IpAddr;
use std::sync::LazyLock;
use std::sync::Mutex;
use tracing::Level;
use tracing::debug;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

mod client;
mod local;
mod server;

use client::capture_remote_client;
use local::capture_local;
use server::capture_remote_server;

static PACKETS_CAPTURED: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));
static PACKETS_SERVER_RECVED: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));

// The default is 65535. This should always be larger than the snaplen.
const DEFAULT_BUFFER_SIZE: usize = 65535;
// The default is 65535.
const DEFAULT_SNAPLEN_SIZE: usize = 65535;

/// Next generation packet dump software.
#[derive(Parser, Debug)]
#[command(author = "RikoNaka", version, about, long_about = None)]
struct Args {
    /// The interface to capture, by default, this is 'any' which means pseudo-device that captures on all interfaces
    #[arg(short = 'i', long, default_value = "any")]
    interface: String,

    /// Exit after receiving 'count' packets
    #[arg(short = 'c', long, default_value_t = 0)]
    count: usize,

    /// Before writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.
    #[arg(short = 'C', long, default_value = "")]
    file_size: String, // 1MB, 1KB, 1GB .etc

    /// Before writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.
    #[arg(short = 'r', long, default_value = "")]
    rotate: String, // 1S, 1M, 1D .etc

    /// Set promiscuous mode on or off
    #[arg(short = 'p', long, action, default_value_t = true)]
    promisc: bool,

    /// Set the buffer size for incoming packet data
    #[arg(short = 'b', long, default_value_t = DEFAULT_BUFFER_SIZE)]
    buffer_size: usize,

    /// Set the snaplen size (the maximum length of a packet captured into the buffer), useful if you only want certain headers, but not the entire packet
    #[arg(short = 's', long, default_value_t = DEFAULT_SNAPLEN_SIZE)]
    snaplen: usize,

    /// Set immediate mode on or off, by default, this is on for fast capture
    #[arg(short = 'I', long, action)]
    immediate: bool,

    /// Set the read timeout for the capture, by default, this is 0 so it will block indefinitely
    #[arg(short = 't', long, default_value_t = 0.0)]
    timeout: f32,

    /// Set the filter when saving the packet, e.g. --filter ip=192.168.1.1 and port=80, please use --filter-examples to show more examples
    #[arg(short = 'f', long, default_value = "")]
    filter: String,

    /// Show the filter parameter more examples
    #[arg(long, alias = "fe", action, default_value_t = false)]
    filter_examples: bool,

    /// Show the filter valid protocol
    #[arg(long, alias = "fvp", action, default_value_t = false)]
    filter_valid_protocol: bool,

    /// Set the program work mode, by default, this is 'local' mode and save traffic file in local storege
    #[arg(short = 'm', long, default_value = "local")]
    mode: String,

    /// Print the list of the network interfaces available on the system
    #[arg(long, alias = "li", action, default_value_t = false)]
    list_interface: bool,

    /// Set the save file path
    #[arg(short = 'w', long, default_value = "xxpdump.pcapng")]
    write: String,

    /// Used in conjunction with the -C option, this will limit the number of files created to the specified number, and begin overwriting files from the beginning
    #[arg(short = 'F', long, alias = "fc", default_value_t = 0)]
    file_count: usize,

    /// Log display level
    #[arg(short = 'l', long, alias = "ll", default_value = "info")]
    log_level: String,

    /// Remote capture server listen addr
    #[arg(long, alias = "sa", default_value = "0.0.0.0:12345")]
    server_addr: String,

    /// Remote capture server password
    #[arg(long, alias = "sp", default_value = "123456")]
    server_passwd: String,

    /// Ignore capture server traffic (this is useful when the remote address is an IP address instead of a domain name, when the remote server is a domain name, please set the filter manually)
    #[arg(long, alias = "ist", action, default_value_t = true)]
    ignore_self_traffic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
enum PcapNgType {
    InterfaceDescriptionBlock,
    // PacketBlock,
    SimplePacketBlock,
    NameResolutionBlock,
    InterfaceStatisticsBlock,
    EnhancedPacketBlock,
    SectionHeaderBlock,
    // CustomBlock,
    // CustomBlock2,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct PcapNgTransport {
    pub p_type: PcapNgType,
    pub p_uuid: String,
    pub p_data: Vec<u8>,
}

fn gen_file_name_simple(path: &str, uuid: &str) -> String {
    let now = Local::now();
    let now_str = now.format(ROTATE_SEC_FORMAT);
    let uuid_split: Vec<&str> = uuid.split("-").collect();
    let filename = format!("{}.{}.{}", now_str, uuid_split[0], path);
    filename
}

/* SPLIT LINE */

fn update_captured_stat() {
    let mut p = match PACKETS_CAPTURED.lock() {
        Ok(p) => p,
        Err(e) => panic!("update PACKETS_CAPTURED failed: {}", e),
    };
    *p += 1;
}

fn update_server_recved_stat() {
    let mut p = match PACKETS_SERVER_RECVED.lock() {
        Ok(p) => p,
        Err(e) => panic!("update PACKETS_SERVER_RECVED failed: {}", e),
    };
    *p += 1;
}

fn init_log_level(log_level: &str) {
    let level = match log_level {
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        _ => panic!(
            "unknown log level [{}], valid parameters are 'info' and 'debug'",
            log_level
        ),
    };

    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");
}

#[cfg(feature = "libpnet")]
fn list_interface() {
    let devices = Device::list();
    debug!("init devices list done");

    let mut info_vec = Vec::new();
    for device in devices {
        let mut tmp_vec = Vec::new();
        tmp_vec.push(device.name.clone());
        match &device.desc {
            Some(desc) => tmp_vec.push((*desc).clone()),
            None => tmp_vec.push(String::from("NODESC")),
        }
        let mut ips = Vec::new();
        for ip in &device.ips {
            match ip {
                IpNetwork::V4(ipv4) => {
                    ips.push(ipv4.to_string());
                }
                IpNetwork::V6(ipv6) => {
                    ips.push(ipv6.to_string());
                }
            }
        }
        match device.mac {
            Some(mac) => {
                tmp_vec.push(mac.to_string());
            }
            None => tmp_vec.push(String::from("NOMAC")),
        }
        let info = vec![tmp_vec, ips];
        info_vec.push(info);
    }

    let mut table = Table::new();
    table.add_row(row!["ID", "NAME", "DESC", "MAC", "IP"]);

    for (ind, info) in info_vec.into_iter().enumerate() {
        let ind = ind + 1;
        let mut cells = vec![Cell::new(&ind.to_string())];
        let tmp_vec = &info[0];
        let ips = &info[1];
        for t in tmp_vec {
            cells.push(Cell::new(&t));
        }
        let ips_str = ips.join("\n");
        cells.push(Cell::new(&ips_str));
        let row = Row::new(cells);
        table.add_row(row);
    }
    table.printstd();
}

#[cfg(feature = "libpcap")]
fn list_interface() {
    let devices = Device::list().expect("get device from libpcap failed");
    debug!("init devices list done");

    let mut info_vec = Vec::new();
    for device in devices {
        let mut tmp_vec = Vec::new();
        tmp_vec.push(device.name.clone());
        match &device.desc {
            Some(desc) => tmp_vec.push((*desc).clone()),
            None => tmp_vec.push(String::from("NODESC")),
        }
        let mut ips = Vec::new();
        for address in &device.addresses {
            match address.addr {
                IpAddr::V4(ipv4) => {
                    ips.push(ipv4.to_string());
                }
                IpAddr::V6(ipv6) => {
                    ips.push(ipv6.to_string());
                }
            }
        }
        tmp_vec.push(String::from("LIBPCAP NOMAC"));
        let info = vec![tmp_vec, ips];
        info_vec.push(info);
    }

    let mut table = Table::new();
    table.add_row(row!["ID", "NAME", "DESC", "MAC", "IP"]);

    for (ind, info) in info_vec.into_iter().enumerate() {
        let ind = ind + 1;
        let mut cells = vec![Cell::new(&ind.to_string())];
        let tmp_vec = &info[0];
        let ips = &info[1];
        for t in tmp_vec {
            cells.push(Cell::new(&t));
        }
        let ips_str = ips.join("\n");
        cells.push(Cell::new(&ips_str));
        let row = Row::new(cells);
        table.add_row(row);
    }
    table.printstd();
}

fn quitting(mode: &str) {
    info!("quitting...");
    match mode {
        "local" | "client" => {
            let packets_captured: usize = match PACKETS_CAPTURED.lock() {
                Ok(p) => *p,
                Err(e) => panic!("try to lock the PACKETS_CAPTURED failed: {}", e),
            };
            info!("packets captured [{}]", packets_captured);
        }
        "server" => {
            let packets_server_recved: usize = match PACKETS_SERVER_RECVED.lock() {
                Ok(p) => *p,
                Err(e) => panic!("try to lock the PACKETS_SERVER_RECVED failed: {}", e),
            };
            info!("packets server recved [{}]", packets_server_recved);
        }
        _ => (),
    }

    std::process::exit(0);
}

/// Convert human-readable file_size parameter to bytes, for exampele, 1KB, 1MB, 1GB, 1PB .etc.
fn file_size_parser(file_size: &str) -> u64 {
    if file_size.len() > 0 {
        let nums_vec = vec!['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];
        let mut ind = 0;
        for ch in file_size.chars() {
            if !nums_vec.contains(&ch) {
                break;
            }
            ind += 1;
        }

        let (num, unit) = if ind > 0 && ind <= file_size.len() {
            let num_str = &file_size[..ind];
            let unit = &file_size[ind..];
            let num: u64 = match num_str.parse() {
                Ok(n) => n,
                Err(_) => panic!("wrong file size parameter [{file_size}]"),
            };
            (num, unit)
        } else {
            panic!("wrong file size parameter [{}]", file_size);
        };

        let final_file_size = if unit.len() == 0 {
            // no unit, by default, it bytes
            num
        } else {
            let unit_fix = unit.trim();
            if unit_fix.starts_with("B") || unit_fix.starts_with("b") {
                num
            } else if unit_fix.starts_with("K") || unit_fix.starts_with("k") {
                num * 1024
            } else if unit_fix.starts_with("G") || unit_fix.starts_with("g") {
                num * 1024 * 1024
            } else if unit_fix.starts_with("P") || unit_fix.starts_with("p") {
                num * 1024 * 1024 * 1024
            } else {
                panic!("wrong unit [{}]", unit);
            }
        };
        debug!("finial file size [{}] bytes", final_file_size);
        final_file_size
    } else {
        0
    }
}

const ROTATE_SEC_FORMAT: &str = "%Y_%m_%d_%H_%M_%S";
const ROTATE_MIN_FORMAT: &str = "%Y_%m_%d_%H_%M";
const ROTATE_HOUR_FORMAT: &str = "%Y_%m_%d_%H";
const ROTATE_DAY_FORMAT: &str = "%Y_%m_%d";

/// Convert human-readable rotate parameter to secs, for exampele, 1s, 1m, 1h, 1d, 1w, .etc.
fn rotate_parser(rotate: &str) -> (u64, &str) {
    if rotate.len() > 0 {
        let nums_vec = vec!['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];
        let mut ind = 0;
        for ch in rotate.chars() {
            if !nums_vec.contains(&ch) {
                break;
            }
            ind += 1;
        }

        let (num, unit) = if ind > 0 && ind <= rotate.len() {
            let num_str = &rotate[..ind];
            let unit = &rotate[ind..];
            let num: u64 = match num_str.parse() {
                Ok(n) => n,
                Err(_) => panic!("wrong file size parameter [{rotate}]"),
            };
            (num, unit)
        } else {
            panic!("wrong file size parameter [{}]", rotate);
        };

        let (final_rotate, format_str) = if unit.len() == 0 {
            // no unit, by default, it bytes
            (num, ROTATE_SEC_FORMAT)
        } else {
            let unit_fix = unit.trim();
            if unit_fix.starts_with("S") || unit_fix.starts_with("s") {
                (num, ROTATE_SEC_FORMAT)
            } else if unit_fix.starts_with("M") || unit_fix.starts_with("m") {
                (num * 60, ROTATE_MIN_FORMAT)
            } else if unit_fix.starts_with("H") || unit_fix.starts_with("h") {
                (num * 60 * 60, ROTATE_HOUR_FORMAT)
            } else if unit_fix.starts_with("D") || unit_fix.starts_with("d") {
                (num * 60 * 60 * 24, ROTATE_DAY_FORMAT)
            } else if unit_fix.starts_with("W") || unit_fix.starts_with("w") {
                (num * 60 * 60 * 24 * 7, ROTATE_DAY_FORMAT)
            } else {
                panic!("wrong unit [{}]", unit);
            }
        };
        debug!("finial rotate [{}] secs", final_rotate);
        (final_rotate, format_str)
    } else {
        (0, ROTATE_SEC_FORMAT)
    }
}

fn get_file_size(target_file: &str) -> u64 {
    match fs::metadata(target_file) {
        Ok(m) => {
            if m.is_file() {
                m.len()
            } else {
                panic!("save file path [{}] is not file", target_file);
            }
        }
        Err(_) => 0, // file not exists, ignore the error
    }
}

fn print_filter_examples() {
    let examples = vec![
        "ip=192.168.1.1 and !tcp",
        "ip!=192.168.1.1 and port!=80",
        "icmp and ip=192.168.1.1",
        "icmp and (ip=192.168.1.1 or ip=192.168.1.2)",
    ];
    let explains = vec![
        "Capture packets with IP address 192.168.1.1 and port number 80",
        "Capture packets with IP address not 192.168.1.1 and port number not 80",
        "Capture packets with ICMP and IP address 192.168.1.1",
        "Capture packets with ICMP and IP address 192.168.1.1 or IP address 192.168.1.2",
    ];
    for (exa, exp) in zip(examples, explains) {
        info!("[{}] - {}", exa, exp);
    }
    // let valid_procotol = pcapture::filter::show_valid_protocol();
    // info!("{:?}", valid_procotol);
}

fn print_valid_procotol() {
    let valid_procotol = pcapture::filter::valid_protocol();
    info!("{:?}", valid_procotol);
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mode = args.mode.clone();
    ctrlc::set_handler(move || {
        quitting(&mode);
    })
    .expect("error setting Ctrl+C handler");

    init_log_level(&args.log_level);
    debug!("init args done");

    if args.list_interface {
        list_interface();
        std::process::exit(0);
    }

    if args.filter_examples {
        print_filter_examples();
        std::process::exit(0);
    }

    if args.filter_valid_protocol {
        print_valid_procotol();
        std::process::exit(0);
    }

    info!("working...");
    match args.mode.as_str() {
        "local" => capture_local(&args),
        "client" => {
            capture_remote_client(&args)
                .await
                .expect("capture remote client error");
        }
        "server" => {
            capture_remote_server(&args)
                .await
                .expect("capture remote server error");
        }
        _ => panic!("unsupported mode"),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[tokio::test]
    async fn server_run() {
        let itr = vec!["", "--mode", "server", "--rotate", "20s"];
        let args = Args::parse_from(itr);
        println!("{}", args.mode);
        println!("{}", args.rotate);
        capture_remote_server(&args)
            .await
            .expect("capture remote server error");
    }
}
