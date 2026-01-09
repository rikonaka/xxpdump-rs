#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::anyhow;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::DateTime;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::Local;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::TimeZone;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::InterfaceDescriptionBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::SectionHeaderBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherType;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ethernet::EtherTypes;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ethernet::EthernetPacket;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ip::IpNextHeaderProtocols;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ipv4::Ipv4Packet;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ipv6::Ipv6Packet;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use regex::Regex;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::fs::File;
use std::net::IpAddr;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tracing::debug;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::Args;

// write after how many packets
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const WRITE_AFTER_PACKETS: usize = 100;

/// Convert human-readable file_size parameter to bytes, for exampele, 1KB, 1MB, 1GB, 1PB .etc.
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
fn parse_bytes(file_size: &str) -> Result<u64> {
    if file_size.len() == 0 {
        return Err(anyhow!("file size parameter is empty"));
    }

    let pattern = Regex::new(r"^(?P<num>[0-9]+)(?P<unit>[KkMmGgPpBb]?[Bb]?)$")?;
    if let Some(caps) = pattern.captures(file_size) {
        let num_str = &caps["num"];
        let unit_str = &caps["unit"];
        let num: u64 = match num_str.parse() {
            Ok(n) => n,
            Err(_) => return Err(anyhow!("wrong size parameter [{file_size}]")),
        };

        let final_size = if unit_str.len() == 0 {
            // no unit, by default, it bytes
            num
        } else {
            if unit_str.starts_with("B") || unit_str.starts_with("b") {
                // make 'b' as bytes here, sometimes some people write it wrongly
                num
            } else if unit_str.starts_with("K") || unit_str.starts_with("k") {
                num * 1024
            } else if unit_str.starts_with("M") || unit_str.starts_with("m") {
                num * 1024 * 1024
            } else if unit_str.starts_with("G") || unit_str.starts_with("g") {
                num * 1024 * 1024 * 1024
            } else if unit_str.starts_with("P") || unit_str.starts_with("p") {
                num * 1024 * 1024 * 1024 * 1024
            } else {
                return Err(anyhow!("wrong unit [{}]", unit_str));
            }
        };
        debug!("finial size [{}] bytes", final_size);
        return Ok(final_size);
    } else {
        return Err(anyhow!("wrong size parameter [{}]", file_size));
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_SEC_FORMAT: &str = "%Y_%m_%d_%H_%M_%S";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_MIN_FORMAT: &str = "%Y_%m_%d_%H_%M";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_HOUR_FORMAT: &str = "%Y_%m_%d_%H";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_DAY_FORMAT: &str = "%Y_%m_%d";

/// Convert human-readable rotate parameter to secs, for exampele, 1s, 1m, 1h, 1d, 1w, .etc.
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
fn parse_rotate(rotate: &str) -> Result<(u64, &str)> {
    if rotate.len() == 0 {
        return Err(anyhow!("rotate parameter is empty"));
    }

    let pattern = Regex::new(r"^(?P<num>[0-9]+)(?P<unit>[SsMmHhDdWw]?)$")?;
    if let Some(caps) = pattern.captures(rotate) {
        let num_str = &caps["num"];
        let unit_str = &caps["unit"];
        let num: u64 = match num_str.parse() {
            Ok(n) => n,
            Err(_) => return Err(anyhow!("wrong rotate parameter [{rotate}]")),
        };
        let (final_rotate, format_str) = if unit_str.len() == 0 {
            // no unit, by default, it secs
            (num, ROTATE_SEC_FORMAT)
        } else {
            if unit_str.starts_with("S") || unit_str.starts_with("s") {
                (num, ROTATE_SEC_FORMAT)
            } else if unit_str.starts_with("M") || unit_str.starts_with("m") {
                (num * 60, ROTATE_MIN_FORMAT)
            } else if unit_str.starts_with("H") || unit_str.starts_with("h") {
                (num * 60 * 60, ROTATE_HOUR_FORMAT)
            } else if unit_str.starts_with("D") || unit_str.starts_with("d") {
                (num * 60 * 60 * 24, ROTATE_DAY_FORMAT)
            } else if unit_str.starts_with("W") || unit_str.starts_with("w") {
                (num * 60 * 60 * 24 * 7, ROTATE_DAY_FORMAT)
            } else {
                return Err(anyhow!("wrong unit [{unit_str}]"));
            }
        };
        debug!("finial rotate [{final_rotate}] secs");
        Ok((final_rotate, format_str))
    } else {
        return Err(anyhow!("wrong rotate parameter [{rotate}]"));
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleNone {
    shb: Option<SectionHeaderBlock>,
    idbs: Option<Vec<InterfaceDescriptionBlock>>,
    // write it not immediately
    blocks: Vec<GeneralBlock>,
    write_fs: File,
    pbo: PcapByteOrder,
    write_header: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleNone {
    pub fn append(&mut self, block: GeneralBlock) -> Result<()> {
        self.blocks.push(block);
        // call it but not write immediately
        self.write(false)?;
        Ok(())
    }
    pub fn write(&mut self, write_immediately: bool) -> Result<()> {
        if self.blocks.len() < WRITE_AFTER_PACKETS && !write_immediately {
            return Ok(());
        }
        // only write header once
        if self.write_header {
            if let Some(shb) = &self.shb {
                shb.write(&mut self.write_fs, self.pbo)?;
            }
            if let Some(idbs) = &self.idbs {
                for idb in idbs {
                    idb.write(&mut self.write_fs, self.pbo)?;
                }
            }
            self.write_header = false;
        }
        for block in &self.blocks {
            block.write(&mut self.write_fs, self.pbo)?;
        }
        self.blocks.clear();
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleRotate {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_rotate: u64,
    last_rotate: DateTime<Local>,
    origin_path: String,
    // write it not immediately
    pub blocks: Vec<GeneralBlock>,
    pub write_fs: File,
    // {prefix}.origin_path => real write path
    prefix: String,
    prefix_format: String,
    pbo: PcapByteOrder,
    write_header: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleRotate {
    pub fn append(&mut self, block: GeneralBlock) -> Result<()> {
        self.blocks.push(block);
        // call it but not write immediately
        self.write(false)?;
        Ok(())
    }
    pub fn write(&mut self, write_immediately: bool) -> Result<()> {
        if self.blocks.len() < WRITE_AFTER_PACKETS && !write_immediately {
            return Ok(());
        }

        // check rotate time
        let now = Local::now();
        let elapsed = now.timestamp() - self.last_rotate.timestamp();
        // rotate the file
        if elapsed as u64 >= self.threshold_rotate {
            self.prefix = now.format(&self.prefix_format).to_string();
            let write_path = format!("{}.{}", self.prefix, self.origin_path);
            let write_fs = File::create(write_path)?;

            self.last_rotate = now;
            self.write_fs = write_fs;
            self.write_header = true;
        }

        // write header when new file created
        if self.write_header {
            if let Some(shb) = &self.shb {
                shb.write(&mut self.write_fs, self.pbo)?;
            }
            if let Some(idbs) = &self.idbs {
                for idb in idbs {
                    idb.write(&mut self.write_fs, self.pbo)?;
                }
            }
            self.write_header = false;
        }

        for block in &self.blocks {
            block.write(&mut self.write_fs, self.pbo)?;
        }
        self.blocks.clear();
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleFileSize {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_size: u64,
    last_size: u64,
    origin_path: String,
    // write it not immediately
    pub blocks: Vec<GeneralBlock>,
    pub write_fs: File,
    // {prefix}.write_path => real write path
    prefix: usize,
    file_count: usize,
    pbo: PcapByteOrder,
    write_header: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleFileSize {
    pub fn append(&mut self, block: GeneralBlock) -> Result<()> {
        self.blocks.push(block);
        // call it but not write immediately
        self.write(false)?;
        Ok(())
    }
    pub fn write(&mut self, write_immediately: bool) -> Result<()> {
        if self.blocks.len() < WRITE_AFTER_PACKETS && !write_immediately {
            return Ok(());
        }
        if self.last_size >= self.threshold_size {
            self.prefix += 1;
            if self.file_count > 0 && self.prefix >= self.file_count {
                self.prefix = 0;
            }
            let write_path = format!("{}.{}", self.prefix, self.origin_path);
            let fs = File::create(write_path)?;

            self.last_size = 0;
            self.write_fs = fs;
            self.write_header = true;
        }

        if self.write_header {
            if let Some(shb) = &self.shb {
                shb.write(&mut self.write_fs, self.pbo)?;
            }
            if let Some(idbs) = &self.idbs {
                for idb in idbs {
                    idb.write(&mut self.write_fs, self.pbo)?;
                }
            }
            self.write_header = false;
        }

        for block in &self.blocks {
            block.write(&mut self.write_fs, self.pbo)?;
            self.last_size += block.size() as u64;
        }
        self.blocks.clear();
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplieRuleCount {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_num: usize,
    packet_num: usize,
    origin_path: String,
    // write it not immediatelyly
    pub blocks: Vec<GeneralBlock>,
    pub write_fs: File,
    // {prefix}.write_path => real write path
    prefix: usize,
    prefix_max: usize,
    pbo: PcapByteOrder,
    write_header: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplieRuleCount {
    pub fn append(&mut self, block: GeneralBlock) -> Result<()> {
        self.blocks.push(block);
        // call it but not write immediatelyly
        self.write(false)?;
        Ok(())
    }
    pub fn write(&mut self, write_immediately: bool) -> Result<()> {
        if self.blocks.len() < WRITE_AFTER_PACKETS && !write_immediately {
            return Ok(());
        }

        if self.packet_num >= self.threshold_num {
            self.prefix += 1;
            if self.prefix >= self.prefix_max {
                self.prefix = 0;
            }
            let write_path = format!("{}.{}", self.prefix, self.origin_path);
            let fs = File::create(write_path)?;

            self.packet_num = 0;
            self.write_fs = fs;
            self.write_header = true;
        }

        if self.write_header {
            if let Some(shb) = &self.shb {
                shb.write(&mut self.write_fs, self.pbo)?;
            }
            if let Some(idbs) = &self.idbs {
                for idb in idbs {
                    idb.write(&mut self.write_fs, self.pbo)?;
                }
            }
            self.write_header = false;
        }

        for block in &self.blocks {
            block.write(&mut self.write_fs, self.pbo)?;
        }
        self.packet_num += self.blocks.len();
        self.blocks.clear();
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub enum SplitRule {
    Count(SplieRuleCount),
    FileSize(SplitRuleFileSize),
    Rotate(SplitRuleRotate),
    None(SplitRuleNone),
    Print,
}

impl Drop for SplitRule {
    fn drop(&mut self) {
        match self {
            Self::Count(c) => {
                c.write(true).expect("final write failed");
            }
            Self::FileSize(f) => {
                f.write(true).expect("final write failed");
            }
            Self::Rotate(r) => {
                r.write(true).expect("final write failed");
            }
            Self::None(n) => {
                n.write(true).expect("final write failed");
            }
            Self::Print => (),
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRule {
    pub fn init(args: &Args, pbo: PcapByteOrder) -> Result<SplitRule> {
        let path = &args.write;
        if let Some(path) = path {
            let file_count = args.file_count;

            let input_count = args.count;
            let input_size_str = &args.file_size;
            let input_rotate_str = &args.rotate;

            if let Some(count) = input_count {
                let write_path = format!("0.{}", path);
                let write_fs = File::create(&write_path)?;
                let src = SplieRuleCount {
                    shb: None,
                    idbs: None,
                    threshold_num: count,
                    packet_num: 0,
                    origin_path: path.clone(),
                    blocks: Vec::new(),
                    write_fs,
                    prefix: 0,
                    prefix_max: file_count,
                    pbo,
                    write_header: true,
                };
                Ok(SplitRule::Count(src))
            } else if let Some(input_size_str) = input_size_str {
                let write_path = format!("0.{}", path);
                let write_fs = File::create(&write_path)?;
                let file_size = parse_bytes(input_size_str)?;
                let spfs = SplitRuleFileSize {
                    shb: None,
                    idbs: None,
                    threshold_size: file_size,
                    last_size: 0,
                    origin_path: path.clone(),
                    blocks: Vec::new(),
                    write_fs,
                    prefix: 0,
                    file_count,
                    pbo,
                    write_header: true,
                };
                Ok(SplitRule::FileSize(spfs))
            } else if let Some(rotate_str) = input_rotate_str {
                let current_rotate = Local::now();
                let (rotate, rotate_format) = parse_rotate(rotate_str)?;
                let current_rotate_str = current_rotate.format(rotate_format).to_string();
                let write_path = format!("{}.{}", current_rotate_str, path);
                let write_fs = File::create(&write_path)?;
                let srr = SplitRuleRotate {
                    shb: None,
                    idbs: None,
                    threshold_rotate: rotate,
                    last_rotate: current_rotate,
                    origin_path: path.clone(),
                    blocks: Vec::new(),
                    write_fs,
                    prefix_format: rotate_format.to_string(),
                    prefix: current_rotate_str,
                    pbo,
                    write_header: true,
                };
                Ok(SplitRule::Rotate(srr))
            } else {
                let write_fs = File::create(&path)?;
                let srn = SplitRuleNone {
                    shb: None,
                    idbs: None,
                    blocks: Vec::new(),
                    write_fs,
                    pbo,
                    write_header: true,
                };
                Ok(SplitRule::None(srn))
            }
        } else {
            // show the packets on terminal
            let srp = SplitRule::Print;
            Ok(srp)
        }
    }
    pub fn append(&mut self, block: GeneralBlock) -> Result<()> {
        match self {
            Self::Count(c) => c.append(block),
            Self::FileSize(f) => f.append(block),
            Self::Rotate(r) => r.append(block),
            Self::None(n) => n.append(block),
            Self::Print => {
                print_packet(block);
                // just show the packet info on terminal
                Ok(())
            }
        }
    }
    pub fn update_shb(&mut self, shb: SectionHeaderBlock) {
        match self {
            Self::Count(c) => c.shb = Some(shb),
            Self::FileSize(f) => f.shb = Some(shb),
            Self::Rotate(r) => r.shb = Some(shb),
            Self::None(_) => (),
            Self::Print => (),
        }
    }
    pub fn update_idb(&mut self, idb: InterfaceDescriptionBlock) {
        match self {
            Self::Count(c) => {
                if let Some(idbs) = &mut c.idbs {
                    idbs.push(idb);
                } else {
                    c.idbs = Some(vec![idb]);
                }
            }
            Self::FileSize(f) => {
                if let Some(idbs) = &mut f.idbs {
                    idbs.push(idb);
                } else {
                    f.idbs = Some(vec![idb]);
                }
            }
            Self::Rotate(r) => {
                if let Some(idbs) = &mut r.idbs {
                    idbs.push(idb);
                } else {
                    r.idbs = Some(vec![idb]);
                }
            }
            Self::None(_) => (),
            Self::Print => (),
        }
    }
}

fn ts_to_sec_nsec(ts_high: u32, ts_low: u32, if_tsresol: u8) -> (i64, u32) {
    let ts64: u64 = ((ts_high as u64) << 32) | (ts_low as u64);

    let is_binary = (if_tsresol & 0x80) != 0;
    let r = (if_tsresol & 0x7f) as u32;

    // tick = numerator / denominator
    let (numerator, denominator): (u128, u128) = if is_binary {
        (1_000_000_000u128, 1u128 << r)
    } else {
        (1_000_000_000u128, 10u128.pow(r))
    };

    let total_ns: u128 = (ts64 as u128) * numerator / denominator;

    let sec: i64 = (total_ns / 1_000_000_000u128) as i64;
    let nsec: u32 = (total_ns % 1_000_000_000u128) as u32;
    (sec, nsec)
}

fn parse_tcp_flag(tcp_flags: u8) -> String {
    let mut flags = Vec::new();
    if tcp_flags & 0x01 != 0 {
        flags.push("F");
    }
    if tcp_flags & 0x02 != 0 {
        flags.push("S");
    }
    if tcp_flags & 0x04 != 0 {
        flags.push("R");
    }
    if tcp_flags & 0x08 != 0 {
        flags.push("P");
    }
    if tcp_flags & 0x10 != 0 {
        // flags.push("A");
        flags.push(".");
    }
    if tcp_flags & 0x20 != 0 {
        flags.push("U");
    }
    flags.join("")
}

fn print_tcp(msg: &str, src_addr: IpAddr, dst_addr: IpAddr, payload: &[u8]) {
    if let Some(tcp_packet) = TcpPacket::new(payload) {
        let src_port = tcp_packet.get_source();
        let dst_port = tcp_packet.get_destination();
        let tcp_flags = tcp_packet.get_flags();
        let tcp_flags_str = parse_tcp_flag(tcp_flags);
        println!(
            "{} {}.{} > {}.{}, TCP: Flags [{}], seq {}, ack {}, win {}, length {}",
            msg,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            tcp_flags_str,
            tcp_packet.get_sequence(),
            tcp_packet.get_acknowledgement(),
            tcp_packet.get_window(),
            tcp_packet.payload().len()
        );
    }
}

fn print_udp(msg: &str, src_addr: IpAddr, dst_addr: IpAddr, payload: &[u8]) {
    if let Some(udp_packet) = UdpPacket::new(payload) {
        let src_port = udp_packet.get_source();
        let dst_port = udp_packet.get_destination();
        println!(
            "{} {}.{} > {}.{}, UDP: length {}",
            msg,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            udp_packet.payload().len()
        );
    }
}

fn print_ip(msg: &str, next_level_protocol: EtherType, payload: &[u8]) {
    match next_level_protocol {
        EtherTypes::Ipv4 => {
            let msg = format!("{} IP:", msg);
            if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
                let src_ipv4 = ipv4_packet.get_source();
                let dst_ipv4 = ipv4_packet.get_destination();
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        print_tcp(
                            &msg,
                            src_ipv4.into(),
                            dst_ipv4.into(),
                            ipv4_packet.payload(),
                        );
                    }
                    IpNextHeaderProtocols::Udp => {
                        print_udp(
                            &msg,
                            src_ipv4.into(),
                            dst_ipv4.into(),
                            ipv4_packet.payload(),
                        );
                    }
                    _ => (),
                }
            }
        }
        EtherTypes::Ipv6 => {
            let msg = format!("{} IP:", msg);
            if let Some(ipv6_packet) = Ipv6Packet::new(payload) {
                let src_ip = ipv6_packet.get_source();
                let dst_ip = ipv6_packet.get_destination();
                match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => {
                        print_tcp(&msg, src_ip.into(), dst_ip.into(), ipv6_packet.payload());
                    }
                    IpNextHeaderProtocols::Udp => {
                        print_udp(&msg, src_ip.into(), dst_ip.into(), ipv6_packet.payload());
                    }
                    _ => (),
                }
            }
        }
        _ => (),
    }
}

fn print_ethernet(msg: &str, payload: &[u8]) {
    if let Some(ethernet_packet) = EthernetPacket::new(payload) {
        let next_level_protocol = ethernet_packet.get_ethertype();
        match next_level_protocol {
            EtherTypes::Ipv4 | EtherTypes::Ipv6 => {
                print_ip(msg, next_level_protocol, ethernet_packet.payload())
            }
            _ => (),
        }
    }
}

fn print_packet(block: GeneralBlock) {
    // example:
    // 12:34:56.789012 IP 192.168.1.10.54321 > 93.184.216.34.80: Flags [S], seq 123, win 64240, options [...], length 0
    // from my tcpdump output:
    // 16:04:23.412830 IP 192.168.5.136.50720 > 36.110.219.249.https: Flags [.], ack 71540, win 64240, length 0
    // 16:04:23.414623 IP 192.168.5.136.50618 > 36.110.219.249.https: Flags [.], ack 45260, win 64240, length 0
    // 16:04:23.415451 IP 36.110.219.249.https > 192.168.5.136.50722: Flags [P.], seq 48180:49640, ack 1, win 64240, length 1460
    // 16:04:23.416183 IP 120.255.43.60.https > 192.168.5.136.50845: Flags [P.], seq 74460:77380, ack 1, win 64240, length 2920
    // 16:04:23.416370 IP 192.168.5.136.50845 > 120.255.43.60.https: Flags [.], ack 77380, win 64240, length 0
    // 16:04:23.418079 IP 36.110.219.249.https > 192.168.5.136.50618: Flags [P.], seq 45260:49640, ack 1, win 64240, length 4380
    // 16:04:23.418268 IP 192.168.5.136.50618 > 36.110.219.249.https: Flags [.], ack 49640, win 64240, length 0
    // 16:04:23.419536 IP 112.46.2.127.https > 192.168.5.136.50799: Flags [P.], seq 159140:164980, ack 1, win 64240, length 5840
    // 16:04:23.419537 IP 36.110.219.249.https > 192.168.5.136.50796: Flags [P.], seq 36500:45260, ack 1, win 64240, length 8760
    // 16:04:23.419780 IP 192.168.5.136.50799 > 112.46.2.127.https: Flags [.], ack 164980, win 64240, length 0
    // 16:04:23.419780 IP 192.168.5.136.50796 > 36.110.219.249.https: Flags [.], ack 45260, win 64240, length 0
    // 16:04:23.420987 IP 36.110.219.249.https > 192.168.5.136.50796: Flags [P.], seq 45260:46720, ack 1, win 64240, length 1460
    // program output:
    // 22:34:23.838757 IP: 192.168.5.1.50966 > 192.168.5.3.22 TCP: Flags [P.], seq 2709816865, ack 1664830852, win 1018, length 188
    // 22:34:23.839431 IP: 192.168.5.3.22 > 192.168.5.1.50966 TCP: Flags [P.], seq 1664830852, ack 2709817053, win 9663, length 100
    // 22:34:23.865925 IP: 192.168.5.1.50966 > 192.168.5.3.22 TCP: Flags [P.], seq 2709817053, ack 1664830952, win 1023, length 172
    // 22:34:23.866733 IP: 192.168.5.3.22 > 192.168.5.1.50966 TCP: Flags [P.], seq 1664830952, ack 2709817225, win 9663, length 284
    match block {
        GeneralBlock::EnhancedPacketBlock(epb) => {
            let ts_high = epb.ts_high;
            let ts_low = epb.ts_low;
            let if_tsresol: u8 = 6;
            let (ts_sec, ts_nsec) = ts_to_sec_nsec(ts_high, ts_low, if_tsresol);

            let dt = Local
                .timestamp_opt(ts_sec, ts_nsec)
                .single()
                .unwrap_or_else(|| DateTime::from(Local::now()));
            let ts_usec = ts_nsec / 1_000;
            let time_str = format!("{}.{:06}", dt.format("%H:%M:%S"), ts_usec);

            let data = epb.packet_data;
            print_ethernet(&time_str, &data);
        }
        _ => (),
    }
}
