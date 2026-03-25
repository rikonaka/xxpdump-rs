#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::anyhow;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::DateTime;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::Duration;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::Local;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::TimeZone;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::EnhancedPacketBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::InterfaceDescriptionBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::SectionHeaderBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::Packet;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::arp::ArpOperations;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::arp::ArpPacket;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ethernet::EtherType;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ethernet::EtherTypes;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ethernet::EthernetPacket;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::icmp::IcmpPacket;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::icmp::IcmpTypes;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::icmpv6::Icmpv6Packet;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ip::IpNextHeaderProtocol;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ip::IpNextHeaderProtocols;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ipv4::Ipv4Packet;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::ipv6::Ipv6Packet;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::tcp::TcpPacket;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pnet::packet::udp::UdpPacket;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use regex::Regex;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::collections::HashMap;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::fmt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::fs::File;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::net::IpAddr;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::net::SocketAddr;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::CliArgs;

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
        return Ok(final_size);
    } else {
        return Err(anyhow!("wrong size parameter [{}]", file_size));
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_SEC_FORMAT: &str = "%Y%m%d%H%M%S";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_MIN_FORMAT: &str = "%Y%m%d%H%M";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_HOUR_FORMAT: &str = "%Y%m%d%H";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_DAY_FORMAT: &str = "%Y%m%d";

/// Convert human-readable rotate parameter to secs, for exampele, 1s, 1m, 1h, 1d, 1w, .etc.
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
fn parse_rotate(rotate: &str) -> Result<(f32, &str)> {
    if rotate.len() == 0 {
        return Err(anyhow!("rotate parameter is empty"));
    }

    let pattern = Regex::new(r"^(?P<num>[0-9]+)(?P<unit>[SsMmHhDdWw]?)$")?;
    if let Some(caps) = pattern.captures(rotate) {
        let num_str = &caps["num"];
        let unit_str = &caps["unit"];
        let num: u64 = match num_str.parse() {
            Ok(n) => n,
            Err(_e) => return Err(anyhow!("wrong rotate parameter [{rotate}]")),
        };
        let (threshold_rotate, format_str) = if unit_str.len() == 0 {
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
        Ok((threshold_rotate as f32, format_str))
    } else {
        return Err(anyhow!("wrong rotate parameter [{rotate}]"));
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleNone {
    shb: Option<SectionHeaderBlock>,
    idbs: Option<Vec<InterfaceDescriptionBlock>>,
    write_fs: File,
    pbo: PcapByteOrder,
    write_header: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleNone {
    pub fn append(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        self.write(epb)?;
        Ok(())
    }
    pub fn write(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
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
        epb.write(&mut self.write_fs, self.pbo)?;
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleRotate {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_rotate: f32,
    last_rotate: DateTime<Local>,
    origin_path: String,
    // write it not immediately
    pub write_fs: File,
    // {prefix}.origin_path => real write path
    prefix: String,
    prefix_format: String,
    pbo: PcapByteOrder,
    write_header: bool,
    addr: Option<SocketAddr>,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleRotate {
    pub fn append(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        self.write(epb)?;
        Ok(())
    }
    pub fn write(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        // check rotate time
        let now = Local::now();
        let elapsed = now - self.last_rotate;
        // rotate the file
        if elapsed.as_seconds_f32() >= self.threshold_rotate {
            self.prefix = now.format(&self.prefix_format).to_string();
            let write_path = match self.addr {
                Some(addr) => format!("{}.{}.{}", addr.ip(), self.prefix, self.origin_path),
                None => format!("{}.{}", self.prefix, self.origin_path),
            };

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

        epb.write(&mut self.write_fs, self.pbo)?;
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleFileSize {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_file_size: u64,
    last_size: u64,
    file_ext: String,
    // write it not immediately
    pub write_fs: File,
    // {prefix}.write_path => real write path
    prefix: usize,
    prefix_max: usize,
    pbo: PcapByteOrder,
    write_header: bool,
    addr: Option<SocketAddr>,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleFileSize {
    pub fn append(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        // call it but not write immediately
        self.write(epb)?;
        Ok(())
    }
    pub fn write(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        if self.last_size >= self.threshold_file_size {
            self.prefix += 1;
            if self.prefix_max > 0 && self.prefix >= self.prefix_max {
                self.prefix = 0;
            }
            let write_path = match self.addr {
                Some(addr) => format!("{}.{}.{}", addr.ip(), self.prefix, self.file_ext),
                None => format!("{}.{}", self.prefix, self.file_ext),
            };
            println!("new file to write: {}", &write_path);
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

        epb.write(&mut self.write_fs, self.pbo)?;
        self.last_size += epb.size() as u64;
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplieRuleCount {
    shb: Option<SectionHeaderBlock>,
    idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_packet_num: usize,
    packet_num: usize,
    file_ext: String,
    // write it not immediatelyly
    write_fs: File,
    // {prefix}.write_path => real write path
    prefix: usize,
    prefix_max: usize,
    pbo: PcapByteOrder,
    write_header: bool,
    addr: Option<SocketAddr>,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplieRuleCount {
    pub fn append(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        // call it but not write immediatelyly
        self.write(epb)?;
        Ok(())
    }
    pub fn write(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        if self.packet_num >= self.threshold_packet_num {
            self.prefix += 1;
            if self.prefix >= self.prefix_max {
                self.prefix = 0;
            }
            let write_path = match self.addr {
                Some(addr) => format!("{}.{}.{}", addr.ip(), self.prefix, self.file_ext),
                None => format!("{}.{}", self.prefix, self.file_ext),
            };
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

        epb.write(&mut self.write_fs, self.pbo)?;
        self.packet_num += 1;
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
    Print(PacketPrinter),
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl fmt::Display for SplitRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count(_) => write!(f, "write with count"),
            Self::FileSize(_) => write!(f, "write with file_size"),
            Self::Rotate(_) => write!(f, "write with rotate"),
            Self::None(_) => write!(f, "write with none"),
            Self::Print(_) => write!(f, "print not write"),
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRule {
    pub fn init(args: &CliArgs, pbo: PcapByteOrder, addr: Option<SocketAddr>) -> Result<SplitRule> {
        if let Some(file_ext) = &args.write {
            let file_ext = if file_ext.ends_with(".pcapng") || file_ext.ends_with(".pcap") {
                file_ext.clone()
            } else {
                // default to pcapng
                let new_file_ext = format!("{}.pcapng", file_ext);
                match addr {
                    Some(addr) => {
                        println!(
                            "change write file extension from [{}] to [{}] for client {}",
                            file_ext, &new_file_ext, addr
                        );
                    }
                    None => println!(
                        "change write file extension from [{}] to [{}]",
                        file_ext, &new_file_ext
                    ),
                }
                new_file_ext
            };

            let prefix_max = args.max_file_count;
            let input_count = args.count;
            let input_file_size_str = &args.file_size;
            let input_rotate_str = &args.rotate;

            if let Some(count) = input_count {
                // write with count mode
                let write_path = match addr {
                    Some(addr) => format!("{}.0.{}", addr.ip(), file_ext),
                    None => format!("0.{}", file_ext),
                };
                let write_fs = File::create(&write_path)?;
                let src = SplieRuleCount {
                    shb: None,
                    idbs: None,
                    threshold_packet_num: count,
                    packet_num: 0,
                    file_ext: file_ext.clone(),
                    write_fs,
                    prefix: 0,
                    prefix_max,
                    pbo,
                    write_header: true,
                    addr,
                };
                Ok(SplitRule::Count(src))
            } else if let Some(input_file_size_str) = input_file_size_str {
                // write with file size mode
                let write_path = match addr {
                    Some(addr) => format!("{}.0.{}", addr.ip(), file_ext),
                    None => format!("0.{}", file_ext),
                };
                let write_fs = File::create(&write_path)?;
                let file_size = parse_bytes(input_file_size_str)?;
                let spfs = SplitRuleFileSize {
                    shb: None,
                    idbs: None,
                    threshold_file_size: file_size,
                    last_size: 0,
                    file_ext: file_ext.clone(),
                    write_fs,
                    prefix: 0,
                    prefix_max,
                    pbo,
                    write_header: true,
                    addr,
                };
                Ok(SplitRule::FileSize(spfs))
            } else if let Some(input_rotate_str) = input_rotate_str {
                let current_rotate = Local::now();
                let (threshold_rotate, prefix_format) = parse_rotate(input_rotate_str)?;
                let prefix = current_rotate.format(prefix_format).to_string();
                let write_path = match addr {
                    Some(addr) => format!("{}.{}.{}", addr.ip(), prefix, file_ext),
                    None => format!("{}.{}", prefix, file_ext),
                };
                let write_fs = File::create(&write_path)?;
                let srr = SplitRuleRotate {
                    shb: None,
                    idbs: None,
                    threshold_rotate,
                    last_rotate: current_rotate,
                    origin_path: file_ext.clone(),
                    write_fs,
                    prefix_format: prefix_format.to_string(),
                    prefix,
                    pbo,
                    write_header: true,
                    addr,
                };
                Ok(SplitRule::Rotate(srr))
            } else {
                let write_path = match addr {
                    Some(addr) => format!("{}.{}", addr.ip(), file_ext),
                    None => format!("{}", file_ext),
                };
                let write_fs = File::create(&write_path)?;
                let srn = SplitRuleNone {
                    shb: None,
                    idbs: None,
                    write_fs,
                    pbo,
                    write_header: true,
                };
                Ok(SplitRule::None(srn))
            }
        } else {
            // show the packets on terminal
            let mut p = PacketPrinter::new();
            match args.print_time_mode {
                1 => p
                    .time_printer
                    .set_time_printer_mode(TimePrinterMode::NoPrint),
                2 => p.time_printer.set_time_printer_mode(TimePrinterMode::Epoch),
                3 => p
                    .time_printer
                    .set_time_printer_mode(TimePrinterMode::DeltaPrevious),
                4 => p
                    .time_printer
                    .set_time_printer_mode(TimePrinterMode::HumanReadable),
                5 => p
                    .time_printer
                    .set_time_printer_mode(TimePrinterMode::DeltaFirst),
                _ => {
                    // default mode (this value is assigned in PacketPrinter::new())
                    // p.set_time_printer_mode(TimePrinterMode::HumanReadable);
                }
            }
            match args.show_raw_seq_ack {
                true => p.tcp_udp_printer.show_raw_seq_ack = true,
                false => p.tcp_udp_printer.show_raw_seq_ack = false,
            }
            match args.show_ethernet {
                true => p.ethernet_printer.show_ethernet = true,
                false => p.ethernet_printer.show_ethernet = false,
            }

            let srp = SplitRule::Print(p);
            Ok(srp)
        }
    }
    pub fn append(&mut self, epb: EnhancedPacketBlock) -> Result<()> {
        match self {
            Self::Count(c) => c.append(epb),
            Self::FileSize(f) => f.append(epb),
            Self::Rotate(r) => r.append(epb),
            Self::None(n) => n.append(epb),
            Self::Print(p) => {
                p.print(epb);
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
            Self::None(n) => n.shb = Some(shb),
            Self::Print(_) => (),
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
            Self::None(n) => {
                if let Some(idbs) = &mut n.idbs {
                    idbs.push(idb);
                } else {
                    n.idbs = Some(vec![idb]);
                }
            }
            Self::Print(_) => (),
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug, Clone)]
pub struct TcpUdpPrinter {
    // src_addr -> src_port -> dst_addr -> dst_port -> first_seq
    first_seq: HashMap<IpAddr, HashMap<u16, HashMap<IpAddr, HashMap<u16, u32>>>>,
    // src_addr -> src_port -> dst_addr -> dst_port -> first_ack
    first_ack: HashMap<IpAddr, HashMap<u16, HashMap<IpAddr, HashMap<u16, u32>>>>,
    show_raw_seq_ack: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl Default for TcpUdpPrinter {
    fn default() -> Self {
        Self {
            first_seq: HashMap::new(),
            first_ack: HashMap::new(),
            show_raw_seq_ack: false,
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl TcpUdpPrinter {
    fn get_first_seq(
        &self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
    ) -> Option<u32> {
        if let Some(map1) = self.first_seq.get(&src_addr) {
            if let Some(map2) = map1.get(&src_port) {
                if let Some(map3) = map2.get(&dst_addr) {
                    if let Some(first_seq) = map3.get(&dst_port) {
                        return Some(*first_seq);
                    }
                }
            }
        }
        None
    }
    fn get_first_ack(
        &self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
    ) -> Option<u32> {
        if let Some(map1) = self.first_ack.get(&src_addr) {
            if let Some(map2) = map1.get(&src_port) {
                if let Some(map3) = map2.get(&dst_addr) {
                    if let Some(first_ack) = map3.get(&dst_port) {
                        return Some(*first_ack);
                    }
                }
            }
        }
        None
    }
    fn insert_first_seq(
        &mut self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        first_seq: u32,
    ) {
        self.first_seq
            .entry(src_addr)
            .or_insert_with(HashMap::new)
            .entry(src_port)
            .or_insert_with(HashMap::new)
            .entry(dst_addr)
            .or_insert_with(HashMap::new)
            .insert(dst_port, first_seq);
    }
    fn insert_first_ack(
        &mut self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        first_ack: u32,
    ) {
        self.first_ack
            .entry(src_addr)
            .or_insert_with(HashMap::new)
            .entry(src_port)
            .or_insert_with(HashMap::new)
            .entry(dst_addr)
            .or_insert_with(HashMap::new)
            .insert(dst_port, first_ack);
    }
    fn parse_tcp_flag(&self, tcp_flags: u8) -> String {
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
    fn normalize_seq(
        &mut self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        seq: u32,
    ) -> u32 {
        if self.show_raw_seq_ack {
            seq
        } else {
            let first_seq = if let Some(first_seq) =
                self.get_first_seq(src_addr, src_port, dst_addr, dst_port)
            {
                first_seq
            } else {
                let first_seq = seq;
                self.insert_first_seq(src_addr, src_port, dst_addr, dst_port, first_seq);
                first_seq
            };

            if seq > first_seq {
                seq - first_seq
            } else {
                first_seq - seq
            }
        }
    }
    fn normalize_ack(
        &mut self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        ack: u32,
    ) -> u32 {
        if self.show_raw_seq_ack {
            ack
        } else {
            let first_ack = if let Some(first_ack) =
                self.get_first_ack(src_addr, src_port, dst_addr, dst_port)
            {
                first_ack
            } else {
                let first_ack = ack;
                self.insert_first_ack(src_addr, src_port, dst_addr, dst_port, first_ack);
                first_ack
            };
            if ack > first_ack {
                ack - first_ack
            } else {
                first_ack - ack
            }
        }
    }
    fn print(
        &mut self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        next_level_protocol: IpNextHeaderProtocol,
        payload: &[u8],
    ) -> String {
        match next_level_protocol {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp_packet) = TcpPacket::new(payload) {
                    let src_port = tcp_packet.get_source();
                    let dst_port = tcp_packet.get_destination();
                    let tcp_flags = tcp_packet.get_flags();
                    let tcp_flags_str = self.parse_tcp_flag(tcp_flags);
                    let seq_raw = tcp_packet.get_sequence();
                    let ack_raw = tcp_packet.get_acknowledgement();

                    let seq = self.normalize_seq(src_addr, src_port, dst_addr, dst_port, seq_raw);
                    let seq_end = seq + tcp_packet.payload().len() as u32;
                    let ack = self.normalize_ack(src_addr, src_port, dst_addr, dst_port, ack_raw);

                    let msg = format!(
                        "TCP {} > {} flags [{}] seq {}:{} ack {} win {} len {}",
                        src_port,
                        dst_port,
                        tcp_flags_str,
                        seq,
                        seq_end,
                        ack,
                        tcp_packet.get_window(),
                        tcp_packet.payload().len()
                    );
                    return msg;
                } else {
                    let msg = format!("TCP(failed) len {}", payload.len());
                    return msg;
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp_packet) = UdpPacket::new(payload) {
                    let src_port = udp_packet.get_source();
                    let dst_port = udp_packet.get_destination();
                    let msg = format!(
                        "UDP {} > {} len {}",
                        src_port,
                        dst_port,
                        udp_packet.payload().len()
                    );
                    return msg;
                } else {
                    let msg = format!("UDP(failed) len {}", payload.len());
                    return msg;
                }
            }
            IpNextHeaderProtocols::Icmp => {
                if let Some(icmp_packet) = IcmpPacket::new(payload) {
                    let icmp_type = icmp_packet.get_icmp_type();
                    let icmp_code = icmp_packet.get_icmp_code();

                    let icmp_type_str = match icmp_type {
                        IcmpTypes::AddressMaskReply => String::from("AddressMaskReply"),
                        IcmpTypes::AddressMaskRequest => String::from("AddressMaskRequest"),
                        IcmpTypes::DestinationUnreachable => String::from("DestinationUnreachable"),
                        IcmpTypes::EchoReply => String::from("EchoReply"),
                        IcmpTypes::EchoRequest => String::from("EchoRequest"),
                        IcmpTypes::InformationReply => String::from("InformationReply"),
                        IcmpTypes::InformationRequest => String::from("InformationRequest"),
                        IcmpTypes::ParameterProblem => String::from("ParameterProblem"),
                        IcmpTypes::RedirectMessage => String::from("RedirectMessage"),
                        IcmpTypes::RouterAdvertisement => String::from("RouterAdvertisement"),
                        IcmpTypes::RouterSolicitation => String::from("RouterSolicitation"),
                        IcmpTypes::SourceQuench => String::from("SourceQuench"),
                        IcmpTypes::TimeExceeded => String::from("TimeExceeded"),
                        IcmpTypes::TimestampReply => String::from("TimestampReply"),
                        IcmpTypes::Timestamp => String::from("Timestamp"),
                        IcmpTypes::Traceroute => String::from("Traceroute"),
                        _ => format!("{}", icmp_type.0),
                    };

                    format!(
                        "ICMP type {}({}) code({}) len {}",
                        icmp_type_str,
                        icmp_type.0,
                        icmp_code.0,
                        icmp_packet.payload().len()
                    )
                } else {
                    String::from("BUILD TCP FAILED")
                }
            }
            IpNextHeaderProtocols::Icmpv6 => {
                if let Some(icmpv6_packet) = Icmpv6Packet::new(payload) {
                    use pnet::packet::icmpv6::Icmpv6Types;

                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();

                    let icmp_type_str = match icmpv6_type {
                        Icmpv6Types::DestinationUnreachable => {
                            String::from("DestinationUnreachable")
                        }
                        Icmpv6Types::EchoReply => String::from("EchoReply"),
                        Icmpv6Types::EchoRequest => String::from("EchoRequest"),
                        Icmpv6Types::NeighborAdvert => String::from("NeighborAdvert"),
                        Icmpv6Types::NeighborSolicit => String::from("NeighborSolicit"),
                        Icmpv6Types::PacketTooBig => String::from("PacketTooBig"),
                        Icmpv6Types::ParameterProblem => String::from("ParameterProblem"),
                        Icmpv6Types::Redirect => String::from("Redirect"),
                        Icmpv6Types::RouterAdvert => String::from("RouterAdvert"),
                        Icmpv6Types::RouterSolicit => String::from("RouterSolicit"),
                        Icmpv6Types::TimeExceeded => String::from("TimeExceeded"),
                        _ => format!("{}", icmpv6_type.0),
                    };

                    format!(
                        "ICMPv6 type {}({}) code({}) len {}",
                        icmp_type_str,
                        icmpv6_type.0,
                        icmpv6_code.0,
                        icmpv6_packet.payload().len()
                    )
                } else {
                    String::from("BUILD ICMPV6 ERROR")
                }
            }
            _ => {
                let msg = format!(
                    "{} len {}",
                    next_level_protocol.to_string().to_uppercase(),
                    payload.len()
                );
                return msg;
            }
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
pub struct IpPrinter {}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl Default for IpPrinter {
    fn default() -> Self {
        Self {}
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl IpPrinter {
    fn print(
        self,
        next_level_protocol: EtherType,
        payload: &[u8],
    ) -> (
        String,
        Option<(IpAddr, IpAddr, Option<IpNextHeaderProtocol>, Vec<u8>)>,
    ) {
        match next_level_protocol {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
                    let src_ip = ipv4_packet.get_source();
                    let dst_ip = ipv4_packet.get_destination();
                    let next_level_protocol = ipv4_packet.get_next_level_protocol();
                    let msg = format!("IP {} > {}", src_ip, dst_ip);
                    let payload = ipv4_packet.payload();
                    (
                        msg,
                        Some((
                            src_ip.into(),
                            dst_ip.into(),
                            Some(next_level_protocol),
                            payload.to_vec(),
                        )),
                    )
                } else {
                    (String::from("BUILD IPV4 ERROR"), None)
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6_packet) = Ipv6Packet::new(payload) {
                    let src_ip = ipv6_packet.get_source();
                    let dst_ip = ipv6_packet.get_destination();
                    let next_level_protocol = ipv6_packet.get_next_header();
                    let msg = format!("IPv6 {} > {}", src_ip, dst_ip);
                    (
                        msg,
                        Some((
                            src_ip.into(),
                            dst_ip.into(),
                            Some(next_level_protocol),
                            payload.to_vec(),
                        )),
                    )
                } else {
                    (String::from("BUILD IPV6 ERROR"), None)
                }
            }
            EtherTypes::Arp => {
                if let Some(arp_packet) = ArpPacket::new(payload) {
                    let sender = arp_packet.get_sender_proto_addr();
                    let target = arp_packet.get_target_proto_addr();
                    let operation = arp_packet.get_operation();
                    let op_str = match operation {
                        ArpOperations::Reply => String::from("Reply"),
                        ArpOperations::Request => String::from("Request"),
                        _ => format!("{}", operation.0),
                    };
                    let msg = format!("ARP {} > {} op({})", sender, target, op_str);
                    (msg, None)
                } else {
                    (String::from("BUILD ARP ERROR"), None)
                }
            }
            _ => (
                format!(
                    "{} len {}",
                    next_level_protocol.to_string().to_uppercase(),
                    payload.len()
                ),
                None,
            ),
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
struct EthernetPrinter {
    pub show_ethernet: bool,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl Default for EthernetPrinter {
    fn default() -> Self {
        Self {
            show_ethernet: false,
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl EthernetPrinter {
    fn print(&self, payload: &[u8]) -> (String, Option<EtherType>, Vec<u8>) {
        if let Some(ethernet_packet) = EthernetPacket::new(payload) {
            let next_level_protocol = ethernet_packet.get_ethertype();
            let src_mac = ethernet_packet.get_source();
            let dst_mac = ethernet_packet.get_destination();
            let payload = ethernet_packet.payload();
            let msg = if self.show_ethernet {
                format!(
                    "ETH {} > {} ethertype {} (0x{:04x})",
                    src_mac,
                    dst_mac,
                    next_level_protocol.to_string().to_lowercase(),
                    next_level_protocol.0,
                )
            } else {
                if payload.len() == 0 {
                    String::from("NO IP")
                } else {
                    String::new()
                }
            };
            (msg, Some(next_level_protocol), payload.to_vec())
        } else {
            (String::from("NO ETH"), None, Vec::new())
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
struct PacketTimePrinter {
    pub time_printer_mode: TimePrinterMode,
    pub if_tsresol: u8,
    // store previous packet time
    pub pre_packet_time: Option<Duration>, // for -ttt
    // store first packet time
    pub first_packet_time: Option<Duration>, // for -ttttt
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl Default for PacketTimePrinter {
    fn default() -> Self {
        Self {
            // default value
            time_printer_mode: TimePrinterMode::HumanReadable,
            // default value
            if_tsresol: 6,
            pre_packet_time: None,
            first_packet_time: None,
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl PacketTimePrinter {
    fn set_time_printer_mode(&mut self, mode: TimePrinterMode) {
        self.time_printer_mode = mode;
    }
    fn ts_to_sec_nsec(&self, ts_high: u32, ts_low: u32, if_tsresol: u8) -> (i64, u32) {
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
    /// Don't print timestamps.
    fn print_1(&self) -> String {
        String::new()
    }
    /// Print Unix epoch time.
    fn print_2(&self, ts_high: u32, ts_low: u32) -> String {
        let (ts_sec, ts_nsec) = self.ts_to_sec_nsec(ts_high, ts_low, self.if_tsresol);
        let time_str = format!("{}.{:06}", ts_sec, ts_nsec);
        time_str
    }
    /// Print delta time between current and previous packet.
    fn print_3(&mut self, ts_high: u32, ts_low: u32) -> String {
        let (ts_sec, ts_nsec) = self.ts_to_sec_nsec(ts_high, ts_low, self.if_tsresol);
        let current_duration = Duration::seconds(ts_sec) + Duration::nanoseconds(ts_nsec as i64);

        let pre_duration = if let Some(fpt) = self.pre_packet_time {
            fpt
        } else {
            self.pre_packet_time = Some(current_duration);
            current_duration
        };

        self.pre_packet_time = Some(current_duration);
        let delta = current_duration - pre_duration;
        let sec = delta.num_seconds();
        let nsec = if let Some(nsec) = (delta - Duration::seconds(sec)).num_nanoseconds() {
            nsec
        } else {
            0
        };
        let time_str = format!("{}.{}", sec, format!("{:09}", nsec).trim_end_matches('0'));
        time_str
    }
    /// Print human-readable date/time.
    fn print_4(&self, ts_high: u32, ts_low: u32) -> String {
        let (ts_sec, ts_nsec) = self.ts_to_sec_nsec(ts_high, ts_low, self.if_tsresol);

        let dt = if let Some(dt) = Local.timestamp_opt(ts_sec, ts_nsec).single() {
            dt
        } else {
            DateTime::from(Local::now())
        };
        let ts_usec = ts_nsec / 1_000;
        let time_str = format!("{}.{:06}", dt.format("%H:%M:%S"), ts_usec);
        time_str
    }
    /// Print delta time since the first packet.
    fn print_5(&mut self, ts_high: u32, ts_low: u32) -> String {
        let (ts_sec, ts_nsec) = self.ts_to_sec_nsec(ts_high, ts_low, self.if_tsresol);
        let current_duration = Duration::seconds(ts_sec) + Duration::nanoseconds(ts_nsec as i64);

        let first_duration = if let Some(fpt) = self.first_packet_time {
            fpt
        } else {
            self.first_packet_time = Some(current_duration);
            current_duration
        };
        let delta = current_duration - first_duration;
        let sec = delta.num_seconds();
        let nsec = if let Some(nsec) = (delta - Duration::seconds(sec)).num_nanoseconds() {
            nsec
        } else {
            0
        };
        let time_str = format!("{}.{}", sec, format!("{:09}", nsec).trim_end_matches('0'));
        time_str
    }
    fn print(&mut self, ts_high: u32, ts_low: u32) -> String {
        let msg = match self.time_printer_mode {
            TimePrinterMode::NoPrint => self.print_1(),
            TimePrinterMode::Epoch => self.print_2(ts_high, ts_low),
            TimePrinterMode::DeltaPrevious => self.print_3(ts_high, ts_low),
            TimePrinterMode::HumanReadable => self.print_4(ts_high, ts_low),
            TimePrinterMode::DeltaFirst => self.print_5(ts_high, ts_low),
        };
        msg
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
pub enum TimePrinterMode {
    NoPrint,
    Epoch,
    DeltaPrevious,
    HumanReadable,
    DeltaFirst,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug, Clone)]
pub struct PacketPrinter {
    time_printer: PacketTimePrinter,
    ethernet_printer: EthernetPrinter,
    ip_printer: IpPrinter,
    tcp_udp_printer: TcpUdpPrinter,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl PacketPrinter {
    fn new() -> Self {
        Self {
            time_printer: PacketTimePrinter::default(),
            ethernet_printer: EthernetPrinter::default(),
            ip_printer: IpPrinter::default(),
            tcp_udp_printer: TcpUdpPrinter::default(),
        }
    }

    fn print(&mut self, epb: EnhancedPacketBlock) {
        // from my tcpdump (version: 4.99.5) output:
        // program output:
        // 11:51:39.979805 IP: 192.168.5.3.22 > 192.168.5.1.55981, TCP: Flags [P.], seq 2406649272:2406649364, ack 2364440282, win 9836, len 92
        // 11:51:40.021937 IP: 192.168.5.3.22 > 192.168.5.1.55981, TCP: Flags [P.], seq 2406649364:2406649464, ack 2364440282, win 9836, len 100
        // 11:51:40.022391 IP: 192.168.5.1.55981 > 192.168.5.3.22, TCP: Flags [.], seq 2364440282:2364440282, ack 2406649464, win 1023, len 0
        let ts_high = epb.ts_high;
        let ts_low = epb.ts_low;
        let ethernet_data = epb.packet_data;

        let mut msg_vec = Vec::new();

        // 1. print time string
        let time_str = self.time_printer.print(ts_high, ts_low);
        msg_vec.push(time_str);

        // 2. print ethernet info if needed
        let (ethernet_str, next_level_protocol, eth_payload) =
            self.ethernet_printer.print(&ethernet_data);
        msg_vec.push(ethernet_str);

        if eth_payload.len() > 0 {
            // 3. print IP info
            let (ip_msg, ret) = match next_level_protocol {
                Some(nlp) => self.ip_printer.print(nlp, &eth_payload),
                None => (String::new(), None),
            };
            msg_vec.push(ip_msg);
            if let Some((src_addr, dst_addr, nlp, ip_payload)) = ret {
                if ip_payload.len() > 0 {
                    // 4. print TCP/UDP info
                    let tcp_udp_msg = match nlp {
                        Some(nlp) => {
                            self.tcp_udp_printer
                                .print(src_addr, dst_addr, nlp, &ip_payload)
                        }
                        None => String::new(),
                    };
                    msg_vec.push(tcp_udp_msg);
                }
            }
        }

        let new_msg_vec: Vec<&str> = msg_vec
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.as_str())
            .collect();
        let final_msg = new_msg_vec.join("|");
        println!("{}", final_msg);
    }
}
