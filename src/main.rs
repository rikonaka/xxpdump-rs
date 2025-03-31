use clap::Parser;
use pcap::Active;
use pcap::Capture;
use pcap::Device;
use pcap::IfFlags;
use std::fs;
use std::sync::LazyLock;
use std::sync::Mutex;
use tracing::Level;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

mod filter;

static PACKETS_CAPTURED: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));

// The default is 1000000. This should always be larger than the snaplen.
const DEFAULT_BUFFER_SIZE: i32 = 1000000;
// The default is 65535.
const DEFAULT_SNAPLEN_SIZE: i32 = 65535;

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
    buffer_size: i32,

    /// Set the snaplen size (the maximum length of a packet captured into the buffer), useful if you only want certain headers, but not the entire packet
    #[arg(long, default_value_t = DEFAULT_SNAPLEN_SIZE)]
    snaplen_size: i32,

    /// Set immediate mode on or off, by default, this is on for fast capture
    #[arg(long, action, default_value = "true")]
    immediate: bool,

    /// Set the read timeout for the capture, by default, this is 0 so it will block indefinitely
    #[arg(short, long, default_value_t = 0)]
    timeout: i32,

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

fn local_capture(mut cap: Capture<Active>, args: &Args) {
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
    let combine_filename = |ind: usize| -> String {
        let filename = format!("{}.{}", ind, &path);
        filename
    };
    let check_savefile_size = |ind: usize| -> usize {
        let mut i = ind;
        loop {
            let target_file = combine_filename(i);
            let savefile_size = get_savefile_size(&target_file);
            debug!("target file [{}] size is [{}]", target_file, savefile_size);
            if savefile_size > file_size_bytes {
                i += 1;
            } else {
                return i;
            }
        }
    };
    /* end closure */

    /* count */
    let finite_loop = if count > 0 { true } else { false };
    let mut c = 0;

    if finite_loop {
        debug!("start finite loop [{}]", count);
    } else {
        debug!("start loop");
    }

    /* file_size */
    let file_size_flag = if file_size.len() > 0 { true } else { false };
    let mut file_suffix_ind = 0;
    let mut sf = if file_size_flag {
        let new_path = format!("{}.{}", file_suffix_ind, path);
        debug!("file_size enabled, new save path [{}]", &new_path);
        let sf = match cap.savefile(&new_path) {
            Ok(sf) => sf,
            Err(e) => panic!("set save file path [{}] failed: {}", new_path, e),
        };
        sf
    } else {
        // do nothing here
        let sf = match cap.savefile(&path) {
            Ok(sf) => sf,
            Err(e) => panic!("set save file path [{}] failed: {}", path, e),
        };
        sf
    };

    loop {
        // count parameter
        if finite_loop {
            if c >= count {
                break;
            }
            c += 1;
        }

        // file_size paramter
        if file_size_flag {
            let after_check_ind = check_savefile_size(file_suffix_ind);
            // debug!("after check ind [{}]", after_check_ind);
            let new_path = combine_filename(after_check_ind);
            if after_check_ind > file_suffix_ind {
                file_suffix_ind = after_check_ind;
                let new_sf = match cap.savefile(&new_path) {
                    Ok(sf) => sf,
                    Err(e) => panic!("set save file path failed: {}", e),
                };
                debug!("change save file to [{}]", new_path);
                sf = new_sf;
            }
        }

        match cap.next_packet() {
            Ok(packet) => {
                debug!("received packet len: {}", packet.len());
                match PACKETS_CAPTURED.lock() {
                    Ok(mut p) => *p += 1,
                    Err(e) => error!("update the PACKETS_CAPTURED failed: {}", e),
                }

                let packet_vec = packet.to_vec();
                sf.write(&packet);
                // write packet to file immediately
                match sf.flush() {
                    Ok(_) => (),
                    Err(e) => error!("flush error: {}", e),
                }
            }
            Err(e) => error!("capture error: {}", e),
        }
    }
    // infinite loop cannot reach here
    quitting();
}

// fn remote_capture_server(mut cap: Capture<Active>, path: &str) {
// }

fn list_interface(devices: &[Device]) {
    for (i, device) in devices.iter().enumerate() {
        let mut msg = format!("{}.{}", i + 1, device.name);
        match &device.desc {
            Some(d) => msg += &format!(" ({})", d),
            None => (),
        }
        let mut flag_msg_vec = Vec::new();
        match device.flags.if_flags {
            IfFlags::UP => flag_msg_vec.push("Up"),
            IfFlags::RUNNING => flag_msg_vec.push("Running"),
            IfFlags::LOOPBACK => flag_msg_vec.push("Loopback"),
            IfFlags::WIRELESS => flag_msg_vec.push("Wireless"),
            _ => (),
        }

        if flag_msg_vec.len() > 0 {
            let flag_msg = flag_msg_vec.join(", ");
            msg += &format!("[{}]", flag_msg);
        }
        info!("{}", msg);
        debug!("{} - {:?}", i + 1, device);
    }
}

fn quitting() {
    info!("quitting...");
    let packets_captured: usize = match PACKETS_CAPTURED.lock() {
        Ok(p) => *p,
        Err(e) => panic!("try to lock the PACKETS_CAPTURED failed: {}", e),
    };
    info!("packets captured [{}]", packets_captured);
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

    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => panic!("get the system device list failed: {}", e),
    };
    debug!("init devices list done");

    if args.list_interface {
        list_interface(&devices);
        std::process::exit(0);
    }

    if args.filter_examples {
        std::process::exit(0);
    }

    info!("working...");
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
                        "local" => local_capture(cap, &args),
                        _ => panic!("unknown work mode [{}]", args.mode),
                    }
                }
                Err(e) => panic!("get capture device failed: {}", e),
            }
        }
        None => panic!("can not found interface [{}]", args.interface),
    }
}
