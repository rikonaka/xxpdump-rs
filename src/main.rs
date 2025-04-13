use clap::Parser;
use pcapture::pcapng::PcapNg;
use pcapture::Capture;
use pcapture::Device;
use pcapture::PcapByteOrder;
use pnet::ipnetwork::IpNetwork;
use std::fs;
use std::sync::LazyLock;
use std::sync::Mutex;
use tracing::Level;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;
use tracing_subscriber::FmtSubscriber;

mod filter;

use filter::Filters;

static PACKETS_CAPTURED: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));
static PACKETS_FILTERED: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));

// The default is 65535. This should always be larger than the snaplen.
const DEFAULT_BUFFER_SIZE: usize = 65535;
// The default is 65535.
const DEFAULT_SNAPLEN_SIZE: usize = 65535;

/// Next generation tcpdump and udpdump.
#[derive(Parser, Debug)]
#[command(author = "RikoNaka", version, about, long_about = None)]
struct Args {
    /// The interface to capture, by default, this is 'any' which means pseudo-device that captures on all interfaces
    #[arg(short, long, default_value = "any")]
    interface: String,

    /// Exit after receiving 'count' packets
    #[arg(long, action, default_value_t = 0)]
    count: usize,

    /// Before writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.
    #[arg(long, action, default_value = "")]
    file_size: String, // 1MB, 1KB, 1GB .etc

    /// Set promiscuous mode on or off
    #[arg(long, action, default_value = "true")]
    promisc: bool,

    /// Set the buffer size for incoming packet data
    #[arg(long, default_value_t = DEFAULT_BUFFER_SIZE)]
    buffer_size: usize,

    /// Set the snaplen size (the maximum length of a packet captured into the buffer), useful if you only want certain headers, but not the entire packet
    #[arg(long, default_value_t = DEFAULT_SNAPLEN_SIZE)]
    snaplen: usize,

    /// Set immediate mode on or off, by default, this is on for fast capture
    #[arg(long, action, default_value = "true")]
    immediate: bool,

    /// Set the read timeout for the capture, by default, this is 0 so it will block indefinitely
    #[arg(short, long, default_value_t = 0)]
    timeout: u64,

    /// Set the filter when saving the packet, e.g. --filter ip=192.168.1.1 and port=80, please use --filter-examples to show more examples
    #[arg(short, long, default_value = "")]
    filter: String,

    /// Show the filter parameter more examples
    #[arg(long, action, default_value = "false")]
    filter_examples: bool,

    /// Set the program work mode, by default, this is 'local' mode and save traffic file in local storege
    #[arg(short, long, default_value = "local")]
    mode: String,

    /// Print the list of the network interfaces available on the system
    #[arg(long, action, default_value = "false")]
    list_interface: bool,

    /// Set the save file path
    #[arg(short, long, default_value = "xxpdump.pcap")]
    path: String,

    /// Log display level
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn init_log_level(log_level: &str) {
    let level = match log_level {
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        _ => panic!("unknown log level [{}]", log_level),
    };

    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");
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
                Err(_) => panic!("wrong file size parameter [{}]", file_size),
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

fn work_local(mut cap: Capture, args: &Args) {
    let path = &args.path;
    let file_size = &args.file_size;
    let count = args.count;

    let file_size_bytes = file_size_parser(file_size);

    debug!("open save file path");

    /* some closure here */
    let get_savefile_size = |target_file: &str| -> u64 {
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
    };
    /* end closure */

    let mut pcapng = PcapNg::new(iface);
    loop {
        match cap.next() {
            Ok(packet_data) => {}
            Err(e) => error!("capture error: {}", e),
        }
    }

    // infinite loop cannot reach here
    quitting();
}

// fn remote_capture_server(mut cap: Capture<Active>, path: &str) {
// }

fn list_interface() {
    let devices = Device::list();
    debug!("init devices list done");

    for (i, device) in devices.iter().enumerate() {
        let mut msg = format!("{}.{} {:?}", i + 1, device.name, device.desc);
        for ip in &device.ips {
            match ip {
                IpNetwork::V4(ipv4) => {
                    msg += &format!(" {}", ipv4);
                }
                IpNetwork::V6(ipv6) => {
                    msg += &format!(" {}", ipv6);
                }
            }
        }
        msg += &format!(" {:?}", device.mac);
        info!("{}", msg);
    }
}

fn quitting() {
    info!("quitting...");
    let packets_captured: usize = match PACKETS_CAPTURED.lock() {
        Ok(p) => *p,
        Err(e) => panic!("try to lock the PACKETS_CAPTURED failed: {}", e),
    };
    let packets_filtered: usize = match PACKETS_FILTERED.lock() {
        Ok(p) => *p,
        Err(e) => panic!("try to lock the PACKETS_FILTERED failed: {}", e),
    };
    info!(
        "packets captured [{}] | packets filtered [{}]",
        packets_captured, packets_filtered
    );
    std::process::exit(0);
}

fn main() {
    ctrlc::set_handler(move || {
        quitting();
    })
    .expect("error setting Ctrl+C handler");

    let args = Args::parse();
    init_log_level(&args.log_level);
    debug!("init args done");

    if args.list_interface {
        list_interface();
        std::process::exit(0);
    }

    if args.filter_examples {
        Filters::examples(true);
        std::process::exit(0);
    }

    let mut cap = match Capture::new_pcap(&args.interface, PcapByteOrder::WiresharkDefault) {
        Ok(c) => c,
        Err(e) => panic!("init the Capture failed: {}", e),
    };
    cap.promiscuous(args.promisc);
    cap.buffer_size(args.buffer_size);
    cap.snaplen(args.snaplen);
    cap.timeout(args.timeout);

    info!("working...");
    match cap.next() {
        Ok(packet) => match args.mode.as_str() {
            "local" => work_local(cap, &args),
            _ => panic!("unknown work mode [{}]", args.mode),
        },
        Err(e) => panic!("get capture device failed: {}", e),
    }
}
