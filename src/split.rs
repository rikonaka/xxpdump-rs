use anyhow::Result;
use chrono::DateTime;
use chrono::Local;
use pcapture::PcapByteOrder;
use pcapture::pcapng::GeneralBlock;
use pcapture::pcapng::InterfaceDescriptionBlock;
use pcapture::pcapng::SectionHeaderBlock;
use std::fs::File;

use crate::Args;
use crate::file_size_parser;
use crate::rotate_parser;

#[derive(Debug)]
pub struct SplitRuleNone {
    write_fs: File,
}

impl SplitRuleNone {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        block.write(&mut self.write_fs, pbo)?;
        Ok(())
    }
}

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

impl SplitRuleRotate {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        let now = Local::now();

        if now.timestamp() as u64 >= self.current_rotate.timestamp() as u64 + self.threshold_rotate
        {
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
        }

        block.write(&mut self.write_fs, pbo)?;
        Ok(())
    }
}

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

impl SplitRuleFileSize {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        self.current_file_size += block.size() as u64;

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

            self.current_file_size = block.size() as u64;
            self.write_fs = fs;
        }

        block.write(&mut self.write_fs, pbo)?;
        Ok(())
    }
}

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

impl SplieRuleCount {
    pub fn write(&mut self, block: GeneralBlock, pbo: PcapByteOrder) -> Result<()> {
        self.current_num_packet += 1;
        println!(
            "current: {}, prefix: {}, file_count: {}",
            self.current_num_packet, self.current_prefix, self.file_count
        );

        if self.current_num_packet > self.threshold_num_packet {
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

            self.current_num_packet = 1;
            self.write_fs = fs;
        }

        block.write(&mut self.write_fs, pbo)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum SplitRule {
    Count(SplieRuleCount),
    FileSize(SplitRuleFileSize),
    Rotate(SplitRuleRotate),
    None(SplitRuleNone),
}

impl SplitRule {
    pub fn init(args: &Args) -> Result<SplitRule> {
        let path = &args.write;
        let file_count = args.file_count;

        let count = args.count;
        let file_size_str = &args.file_size;
        let rotate_str = &args.rotate;

        if count > 0 {
            let write_path = format!("0.{}", path);
            let write_fs = File::create(&write_path)?;
            let src = SplieRuleCount {
                shb: None,
                idbs: None,
                threshold_num_packet: count,
                current_num_packet: 0,
                origin_path: path.clone(),
                write_fs,
                current_prefix: 1,
                file_count,
            };
            Ok(SplitRule::Count(src))
        } else if file_size_str.len() > 0 {
            let write_path = format!("0.{}", path);
            let write_fs = File::create(&write_path)?;
            let file_size = file_size_parser(file_size_str);
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
        } else if rotate_str.len() > 0 {
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
                origin_path: write_path,
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
