use bincode::Decode;
use bincode::Encode;
use clap::Parser;
#[cfg(feature = "libpnet")]
use pcapture;
use pcapture::Device;
#[cfg(feature = "libpnet")]
use pnet::ipnetwork::IpNetwork;
use serde::Deserialize;
use serde::Serialize;
use std::iter::zip;
#[cfg(feature = "libpcap")]
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use tracing::Level;
use tracing::debug;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

mod client;
mod local;
mod server;
mod split;

use client::capture_remote_client;
use local::capture_local;
use server::capture_remote_server;

static PACKETS_SERVER_TOTAL_RECVED: LazyLock<Arc<Mutex<usize>>> =
    LazyLock::new(|| Arc::new(Mutex::new(0)));

static PACKETS_CAPTURED: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));

// The default is 65535. This should always be larger than the snaplen.
const DEFAULT_BUFFER_SIZE: usize = 163840; // 16MB
// The default is 65535.
const DEFAULT_SNAPLEN_SIZE: usize = 65535;

/// Next generation packet dump software.
#[derive(Parser, Debug, Clone)]
#[command(author = "RikoNaka", version, about, long_about = None)]
struct Args {
    /// The interface to capture, by default, this is 'any' which means pseudo-device that captures on all interfaces
    #[arg(short = 'i', long, default_value = "any")]
    interface: String,

    /// Exit after receiving 'count' packets
    #[arg(short = 'c', long)]
    count: Option<usize>,

    /// Before writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.
    #[arg(short = 'C', long)]
    file_size: Option<String>, // 1MB, 1KB, 1GB .etc

    /// Before writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.
    #[arg(short = 'r', long)]
    rotate: Option<String>, // 1S, 1M, 1D .etc

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
    #[arg(short = 'f', long)]
    filter: Option<String>,

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
    pub p_data: Vec<u8>,
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
    let mut p = match PACKETS_SERVER_TOTAL_RECVED.lock() {
        Ok(p) => p,
        Err(e) => panic!("update PACKETS_SERVER_TOTAL_RECVED failed: {}", e),
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
    let devices = Device::list().expect("get device from libpnet failed");
    debug!("init devices list done");

    let mut info = Vec::new();
    for device in devices {
        let mut line = Vec::new();
        line.push(device.0.name);
        line.push(device.0.description);
        let mut ips = Vec::new();
        for ip in &device.0.ips {
            match ip {
                IpNetwork::V4(ipv4) => {
                    ips.push(ipv4.to_string());
                }
                IpNetwork::V6(ipv6) => {
                    ips.push(ipv6.to_string());
                }
            }
        }
        let ips_str = if ips.len() > 0 {
            ips.join("|")
        } else {
            String::from("no_ip")
        };
        line.push(ips_str);
        match device.0.mac {
            Some(mac) => {
                line.push(mac.to_string());
            }
            None => line.push(String::from("no_mac")),
        }
        let line_str = line.join(", ");
        info.push(line_str);
    }

    let info_str = info.join("\n");
    println!("{}", info_str);
}

#[cfg(feature = "libpcap")]
fn list_interface() {
    let devices = Device::list().expect("get device from libpcap failed");
    debug!("init devices list done");

    let mut info = Vec::new();
    for device in devices {
        let mut line = Vec::new();
        line.push(device.name);

        match &device.desc {
            Some(desc) => line.push(desc.clone()),
            None => line.push(String::from("no_desc")),
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
        let ips_str = if ips.len() > 0 {
            ips.join("|")
        } else {
            String::from("no_ip")
        };
        line.push(ips_str);
        line.push(String::from("libpcap_no_mac"));

        let line_str = line.join(", ");
        info.push(line_str);
    }

    let info_str = info.join("\n");
    println!("{}", info_str);
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
            let total_recved: usize = match PACKETS_SERVER_TOTAL_RECVED.lock() {
                Ok(p) => *p,
                Err(e) => panic!("try to lock the PACKETS_SERVER_TOTAL_RECVED failed: {}", e),
            };
            info!("packets server recved [{}]", total_recved);
        }
        _ => (),
    }

    std::process::exit(0);
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
        "local" => capture_local(args),
        "client" => {
            capture_remote_client(args)
                .await
                .expect("capture remote client error");
        }
        "server" => {
            capture_remote_server(args)
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
        println!("{:?}", args.rotate);
        capture_remote_server(args)
            .await
            .expect("capture remote server error");
    }
}
