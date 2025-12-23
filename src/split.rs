#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::DateTime;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use chrono::Local;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::InterfaceDescriptionBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::SectionHeaderBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::fs::File;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tracing::debug;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::Args;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
/// Convert human-readable file_size parameter to bytes, for exampele, 1KB, 1MB, 1GB, 1PB .etc.
fn filesize_parser(file_size: &str) -> u64 {
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
            } else if unit_fix.starts_with("M") || unit_fix.starts_with("m") {
                num * 1024 * 1024
            } else if unit_fix.starts_with("G") || unit_fix.starts_with("g") {
                num * 1024 * 1024 * 1024
            } else if unit_fix.starts_with("P") || unit_fix.starts_with("p") {
                num * 1024 * 1024 * 1024 * 1024
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

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_SEC_FORMAT: &str = "%Y_%m_%d_%H_%M_%S";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_MIN_FORMAT: &str = "%Y_%m_%d_%H_%M";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_HOUR_FORMAT: &str = "%Y_%m_%d_%H";
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
const ROTATE_DAY_FORMAT: &str = "%Y_%m_%d";

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
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

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleNone {
    write_fs: File,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleNone {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        block.write(&mut self.write_fs, pbo)?;
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleRotate {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_rotate: u64,
    current_rotate: DateTime<Local>,
    origin_path: String,
    pub write_fs: File,
    // {current_prefix}.write_path => next write path
    current_prefix: String,
    prefix_format: String,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleRotate {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        match block {
            GeneralBlock::EnhancedPacketBlock(_) | GeneralBlock::SimplePacketBlock(_) => {
                let now = Local::now();
                let elapsed = now.timestamp() - self.current_rotate.timestamp();
                if elapsed as u64 >= self.threshold_rotate {
                    self.current_prefix = now.format(&self.prefix_format).to_string();
                    let write_path = format!("{}.{}", self.current_prefix, self.origin_path);
                    let mut fs = File::create(write_path)?;

                    if let Some(shb) = &self.shb {
                        shb.write(&mut fs, pbo)?;
                    } else {
                        panic!("shb not found");
                    }
                    if let Some(idbs) = &self.idbs {
                        for idb in idbs {
                            idb.write(&mut fs, pbo)?;
                        }
                    } else {
                        panic!("idb not found");
                    }

                    self.write_fs = fs;
                    self.current_rotate = now
                }
            }
            _ => (),
        }

        block.write(&mut self.write_fs, pbo)?;
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplitRuleFileSize {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_file_size: u64,
    current_file_size: u64,
    origin_path: String,
    pub write_fs: File,
    // {current_prefix + 1}.write_path => next write path
    current_prefix: usize,
    file_count: usize,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRuleFileSize {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        match block {
            GeneralBlock::EnhancedPacketBlock(_) | GeneralBlock::SimplePacketBlock(_) => {
                if self.current_file_size >= self.threshold_file_size {
                    self.current_prefix += 1;
                    if self.file_count > 0 && self.current_prefix >= self.file_count {
                        self.current_prefix = 0;
                    }
                    let write_path = format!("{}.{}", self.current_prefix, self.origin_path);
                    let mut fs = File::create(write_path)?;

                    if let Some(shb) = &self.shb {
                        shb.write(&mut fs, pbo)?;
                    } else {
                        panic!("shb not found");
                    }
                    if let Some(idbs) = &self.idbs {
                        for idb in idbs {
                            idb.write(&mut fs, pbo)?;
                        }
                    } else {
                        panic!("idb not found");
                    }

                    self.current_file_size = 0;
                    self.write_fs = fs;
                }
            }
            _ => (),
        }

        block.write(&mut self.write_fs, pbo)?;
        self.current_file_size += block.size() as u64;
        Ok(())
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[derive(Debug)]
pub struct SplieRuleCount {
    pub shb: Option<SectionHeaderBlock>,
    pub idbs: Option<Vec<InterfaceDescriptionBlock>>,
    threshold_num_packet: usize,
    current_num_packet: usize,
    origin_path: String,
    pub write_fs: File,
    // {current_prefix + 1}.write_path => next write path
    current_prefix: usize,
    file_count: usize,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplieRuleCount {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        // debug use
        // match block {
        //     GeneralBlock::EnhancedPacketBlock(_) => println!("EPB"),
        //     GeneralBlock::InterfaceDescriptionBlock(_) => println!("IDB"),
        //     GeneralBlock::InterfaceStatisticsBlock(_) => println!("ISB"),
        //     GeneralBlock::NameResolutionBlock(_) => println!("NRB"),
        //     GeneralBlock::SectionHeaderBlock(_) => println!("SHB"),
        //     GeneralBlock::SimplePacketBlock(_) => println!("SPB"),
        // }
        match block {
            GeneralBlock::EnhancedPacketBlock(_) | GeneralBlock::SimplePacketBlock(_) => {
                if self.current_num_packet >= self.threshold_num_packet {
                    // panic!("stop");
                    self.current_prefix += 1;
                    if self.file_count > 0 && self.current_prefix >= self.file_count {
                        self.current_prefix = 0;
                    }
                    let write_path = format!("{}.{}", self.current_prefix, self.origin_path);
                    println!("write_path: {}", write_path);
                    let mut fs = File::create(write_path)?;

                    if let Some(shb) = &self.shb {
                        shb.write(&mut fs, pbo)?;
                    } else {
                        panic!("shb not found");
                    }
                    if let Some(idbs) = &self.idbs {
                        for idb in idbs {
                            idb.write(&mut fs, pbo)?;
                        }
                    } else {
                        panic!("idb not found");
                    }

                    self.current_num_packet = 0;
                    self.write_fs = fs;
                }
                self.current_num_packet += 1;
            }
            _ => (), // ignore other blocks
        }

        block.write(&mut self.write_fs, pbo)?;
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
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl SplitRule {
    pub fn init(args: &Args) -> Result<SplitRule> {
        let path = &args.write;
        let file_count = args.file_count;

        let count = args.count;
        let file_size_str = &args.file_size;
        let rotate_str = &args.rotate;

        if let Some(count) = count {
            let write_path = format!("0.{}", path);
            let write_fs = File::create(&write_path)?;
            let src = SplieRuleCount {
                shb: None,
                idbs: None,
                threshold_num_packet: count,
                current_num_packet: 0,
                origin_path: path.clone(),
                write_fs,
                current_prefix: 0,
                file_count,
            };
            Ok(SplitRule::Count(src))
        } else if let Some(file_size_str) = file_size_str {
            let write_path = format!("0.{}", path);
            let write_fs = File::create(&write_path)?;
            let file_size = filesize_parser(file_size_str);
            let spfs = SplitRuleFileSize {
                shb: None,
                idbs: None,
                threshold_file_size: file_size,
                current_file_size: 0,
                origin_path: path.clone(),
                write_fs,
                current_prefix: 0,
                file_count,
            };
            Ok(SplitRule::FileSize(spfs))
        } else if let Some(rotate_str) = rotate_str {
            let current_rotate = Local::now();
            let (rotate, rotate_format) = rotate_parser(rotate_str);
            let current_rotate_str = current_rotate.format(rotate_format).to_string();
            let write_path = format!("{}.{}", current_rotate_str, path);
            let write_fs = File::create(&write_path)?;
            let srr = SplitRuleRotate {
                shb: None,
                idbs: None,
                threshold_rotate: rotate,
                current_rotate,
                origin_path: path.clone(),
                write_fs,
                prefix_format: rotate_format.to_string(),
                current_prefix: current_rotate_str,
            };
            Ok(SplitRule::Rotate(srr))
        } else {
            let write_fs = File::create(&path)?;
            let srn = SplitRuleNone { write_fs };
            Ok(SplitRule::None(srn))
        }
    }
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        match self {
            Self::Count(c) => c.write(block, pbo),
            Self::FileSize(f) => f.write(block, pbo),
            Self::Rotate(r) => r.write(block, pbo),
            Self::None(n) => n.write(block, pbo),
        }
    }
    pub fn update_shb(&mut self, shb: SectionHeaderBlock) {
        match self {
            Self::Count(c) => c.shb = Some(shb),
            Self::FileSize(f) => f.shb = Some(shb),
            Self::Rotate(r) => r.shb = Some(shb),
            Self::None(_) => (),
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
        }
    }
}
