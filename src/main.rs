use clap::Parser;
use env_logger::Builder;
use log::LevelFilter;
use log::debug;
use log::error;
use log::info;
use log::warn;
use pcap::Active;
use pcap::Capture;
use pcap::Device;
use std::sync::LazyLock;
use std::sync::Mutex;

static PACKETS_CAPTURED: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));

// The default is 1000000. This should always be larger than the snaplen.
const DEFAULT_BUFFER_SIZE: i32 = 1000000;
// The default is 65535.
const DEFAULT_SNAPLEN_SIZE: i32 = 65535;

/// Next generation tcpdump and udpdump.
#[derive(Parser, Debug)]
#[command(author = "RikoNaka", version, about, long_about = None)]
struct Args {
    /// The interface to capture
    #[arg(short, long)]
    interface: String,

    /// Set promiscuous mode on or off
    #[arg(long, action, default_value = "true")]
    promisc: bool,

    /// Set the buffer size for incoming packet data
    #[arg(long, default_value_t = DEFAULT_BUFFER_SIZE)]
    buffer_size: i32,

    /// Set the snaplen size (the maximum length of a packet captured into the buffer), useful if you only want certain headers, but not the entire packet
    #[arg(long, default_value_t = DEFAULT_SNAPLEN_SIZE)]
    snaplen_size: i32,

    /// Set immediate mode on or off, by default, this is on for fast capture
    #[arg(long, action, default_value = "true")]
    immediate: bool,

    /// Set the read timeout for the Capture, by default, this is 0 so it will block indefinitely
    #[arg(short, long, default_value_t = 0)]
    timeout: i32,

    /// Set the program work mode, by default, this is 'local' mode and save traffic file in local storege
    #[arg(short, long, default_value = "local")]
    mode: String,

    /// Set the save file path
    #[arg(short, long, default_value = "xxpdump.pcap")]
    path: String,

    /// Log display level
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn init_log_level(log_level: &str) {
    match log_level {
        "info" => Builder::new().filter(None, LevelFilter::Info).init(),
        "debug" => Builder::new().filter(None, LevelFilter::Debug).init(),
        _ => panic!("unknown log level [{}]", log_level),
    }
}

fn local_capture(mut cap: Capture<Active>, path: &str) {
    debug!("open save file path");
    let mut sf = match cap.savefile(path) {
        Ok(sf) => sf,
        Err(e) => panic!("set save file path failed: {}", e),
    };

    debug!("start loop");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                debug!("received packet, len: {}", packet.len());
                match PACKETS_CAPTURED.lock() {
                    Ok(mut p) => *p += 1,
                    Err(e) => error!("update the PACKETS_CAPTURED failed: {}", e),
                }
                sf.write(&packet);
            }
            Err(e) => warn!("capture error: {}", e),
        }
    }
}

// fn remote_capture_server(mut cap: Capture<Active>, path: &str) {
// }

fn main() {
    ctrlc::set_handler(move || {
        info!("quitting...");
        let packets_captured: usize = match PACKETS_CAPTURED.lock() {
            Ok(p) => *p,
            Err(e) => panic!("try to lock the PACKETS_CAPTURED failed: {}", e),
        };
        info!("packets captured [{}]", packets_captured);
        std::process::exit(0);
    })
    .expect("error setting Ctrl+C handler");

    let args = Args::parse();
    init_log_level(&args.log_level);
    debug!("init args done");

    info!("working...");
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => panic!("get the system device list failed: {}", e),
    };
    debug!("init devices list done");

    let mut capture_device = None;

    for device in devices {
        if device.name == args.interface {
            debug!("found device [{}]", device.name);
            capture_device = Some(device.clone());
        }
    }

    match capture_device {
        Some(device) => {
            debug!("start capture");
            match Capture::from_device(device) {
                Ok(config_capture) => {
                    let c = config_capture
                        .promisc(args.promisc)
                        .buffer_size(args.buffer_size)
                        .snaplen(args.snaplen_size)
                        .immediate_mode(args.immediate)
                        .timeout(args.timeout);
                    let cap = match c.open() {
                        Ok(cap) => cap,
                        Err(e) => panic!("can not open the capture: {}", e),
                    };

                    match args.mode.as_str() {
                        "local" => local_capture(cap, &args.path),
                        _ => panic!("unknown work mode [{}]", args.mode),
                    }
                }
                Err(e) => panic!("get capture device failed: {}", e),
            }
        }
        None => panic!("can not found interface [{}]", args.interface),
    }
}
