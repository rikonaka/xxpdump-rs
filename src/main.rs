use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use bitcode::Decode;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use bitcode::Encode;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use clap::ArgAction;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use clap::Parser;
#[cfg(feature = "libpnet")]
use pcapture;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::Device;
#[cfg(feature = "libpcap")]
use pcapture::libpcap::Addr;
#[cfg(feature = "libpnet")]
use pnet::ipnetwork::IpNetwork;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use serde::Deserialize;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use serde::Serialize;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::iter::zip;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::sync::atomic::AtomicBool;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::sync::atomic::Ordering;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::time::Instant;

mod client;
mod local;
mod server;
mod split;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use client::capture_remote_client;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use local::capture_local;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use server::capture_remote_server;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
// The default is 65535. This should always be larger than the snaplen.
const DEFAULT_BUFFER_SIZE: usize = 163840; // 16MB
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
// The default is 65535.
const DEFAULT_SNAPLEN_SIZE: usize = 65535;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
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
    #[arg(short = 'p', long, action, default_value_t = false)]
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
    #[arg(short = 'T', long, default_value_t = 0.1)]
    timeout: f32,

    /// Set the read timeout for the capture, by default, this is 0 so it will block indefinitely
    #[arg(short = 'N', long, action, default_value_t = false)]
    nonblock: bool,

    /// Set the filter when saving the packet, e.g. --filter ip=192.168.1.1 and port=80, please use --filter-examples to show more examples
    #[arg(short = 'f', long)]
    filter: Option<String>,

    /// Show the filter parameter more examples
    #[arg(long, alias = "fe", action, default_value_t = false)]
    filter_examples: bool,

    /// Set the program work mode, by default, this is 'local' mode and save traffic file in local storege
    #[arg(short = 'm', long, default_value = "local")]
    mode: String,

    /// Print the list of the network interfaces available on the system
    #[arg(long, alias = "ls", action, default_value_t = false)]
    list_interface: bool,

    /// Set the save file path
    #[arg(short = 'w', long)]
    write: Option<String>,

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

    /// Set the print time mode, -t: no print; -tt: epoch; -ttt: delta previous packet; -tttt: human readable; -ttttt: delta first packet.
    #[arg(short = 't', action=ArgAction::Count)]
    print_time_mode: u8,

    /// Show the raw sequence number and ack number in TCP packets
    #[arg(short = 'S', long, action, default_value_t = false)]
    show_raw_seq_ack: bool,

    /// Show ethernet layer info
    #[arg(short = 'e', long, action, default_value_t = false)]
    show_ethernet: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
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

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct PcapNgTransport {
    pub p_type: PcapNgType,
    pub p_data: Vec<u8>,
}

#[cfg(feature = "libpnet")]
fn list_interface() -> Result<()> {
    let devices = Device::list()?;

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

    Ok(())
}

#[cfg(feature = "libpcap")]
fn list_interface() -> Result<()> {
    let devices = Device::list()?;

    let mut info = Vec::new();
    for device in devices {
        let mut line = Vec::new();
        line.push(device.name);

        match &device.description {
            Some(desc) => line.push(desc.clone()),
            None => line.push(String::from("no_desc")),
        }
        let mut ips = Vec::new();
        for address in &device.addresses {
            match address.addr {
                Some(addr) => match addr {
                    Addr::IpAddr(ipaddr) => {
                        ips.push(ipaddr.to_string());
                    }
                    _ => (),
                },
                None => (),
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

    Ok(())
}

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
fn print_filter_examples() {
    let examples = vec![
        "host 192.168.1.1 and !tcp",
        "host 192.168.1.1 and port not 80",
        "icmp and host 192.168.1.1",
        "icmp and (host 192.168.1.1 or host 192.168.1.2)",
    ];
    let explains = vec![
        "Capture packets with IP address 192.168.1.1 and port number 80",
        "Capture packets with IP address not 192.168.1.1 and port number not 80",
        "Capture packets with ICMP and IP address 192.168.1.1",
        "Capture packets with ICMP and IP address 192.168.1.1 or IP address 192.168.1.2",
    ];
    for (exa, exp) in zip(examples, explains) {
        println!("[{}] - {}", exa, exp);
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut start: Option<Instant> = None;
    ctrlc::set_handler(move || {
        println!("stop capturing...");

        match start {
            Some(start) => {
                let elapsed = start.elapsed().as_secs_f32();
                if elapsed > 1.5 {
                    let mut msg = String::new();
                    msg += ">>> ";
                    msg += &format!("its takes too long to stop: {:.2} seconds\n", elapsed);
                    msg += ">>> ";
                    msg += &format!("this is normally caused by libpcap's dispatch function (it is blocking) when there no traffic\n");
                    msg += ">>> ";
                    msg += &format!("if you wish, you can manually send some traffic that can be captured by xxpdump to end the wait\n");
                    msg += ">>> ";
                    msg += &format!("note that forcibly exiting now will result in the loss of captured packets (tcpdump also has this problem)\n");
                    msg += ">>> ";
                    msg += &format!("please set -N for nonblock mode next time if you want to stop it immediately\n");
                    msg += ">>> ";
                    msg += &format!("but this may cause higher CPU usage when capture traffic is heavy\n");
                    println!("{}", msg);
                }
            }
            None => {
                // Set when first press ctrl-c,
                // this is used to calculate the elapsed time when second press ctrl-c.
                start = Some(Instant::now());
            }
        }
        SHOULD_EXIT.store(true, Ordering::SeqCst);
    })
    .expect("error setting ctrl+c handler");

    if args.list_interface {
        list_interface()?;
    } else if args.filter_examples {
        print_filter_examples();
    } else {
        println!("working...");
        match args.mode.as_str() {
            "local" => {
                #[cfg(feature = "libpnet")]
                if args.interface == "any" {
                    eprintln!(
                        "capture interface any not supported on feature 'libpnet', please use feature 'libpcap' or specify a concrete interface name"
                    );
                } else {
                    capture_local(args)?;
                }
                #[cfg(feature = "libpcap")]
                capture_local(args)?;
            }
            "client" => {
                #[cfg(feature = "libpnet")]
                if args.interface == "any" {
                    eprintln!(
                        "capture interface any not supported on feature 'libpnet', please use feature 'libpcap' or specify a concrete interface name"
                    );
                } else {
                    capture_remote_client(args).await?;
                }
                #[cfg(feature = "libpcap")]
                capture_remote_client(args).await?;
            }
            "server" => {
                capture_remote_server(args).await?;
            }
            _ => panic!("unsupported mode"),
        }
    }

    Ok(())
}

#[cfg(not(any(feature = "libpnet", feature = "libpcap")))]
#[tokio::main]
async fn main() -> Result<()> {
    panic!("please enable feature 'libpnet' or 'libpcap' to use this program");
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[cfg(test)]
mod test {
    use super::*;
    use pcapture::PcapByteOrder;
    use pcapture::PcapNg;
    #[tokio::test]
    async fn server_run() {
        let itr = vec!["", "--mode", "server", "--rotate", "20s"];
        let args = Args::parse_from(itr);
        println!("{}", args.mode);
        println!("{:?}", args.rotate);
        capture_remote_server(args).await.unwrap();
    }
    #[test]
    fn read_block() {
        let path = "1.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
        let pcapng = PcapNg::read_all(path, pbo).unwrap();
        println!("blocks num: {}", pcapng.blocks.len());
        // for b in pcapng.blocks {
        //     println!("{:?}", b.name());
        // }
    }
}
