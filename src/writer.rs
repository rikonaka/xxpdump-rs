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
pub struct SplitRuleRotate {
    shb: Option<SectionHeaderBlock>,
    idb: Option<InterfaceDescriptionBlock>,
    threshold_rotate: usize,
    current_rotate: DateTime<Local>,
    write_path: String,
    write_fs: File,
    // {current_prefix}.write_path => next write path
    current_prefix: String,
    prefix_format: String,
}

impl SplitRuleRotate {
    pub fn write(&mut self, block: GeneralBlock) -> Result<()> {
        let now = Local::now();
        let pbo = PcapByteOrder::WiresharkDefault;

        if now.timestamp() as usize
            >= self.current_rotate.timestamp() as usize + self.threshold_rotate
        {
            self.current_prefix = now.format(&self.prefix_format).to_string();
            let write_path = format!("{}.{}", self.current_prefix, self.write_path);
            let mut fs = File::create(write_path)?;

            if let Some(shb) = &self.shb {
                shb.write(&mut fs, pbo)?;
            } else {
                panic!("shb not found");
            }
            if let Some(idb) = &self.idb {
                idb.write(&mut fs, pbo)?;
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
    shb: Option<SectionHeaderBlock>,
    idb: Option<InterfaceDescriptionBlock>,
    threshold_file_size: usize,
    current_file_size: usize,
    write_path: String,
    write_fs: File,
    // {current_prefix + 1}.write_path => next write path
    current_prefix: usize,
    file_count: usize,
}

impl SplitRuleFileSize {
    pub fn write(&mut self, block: GeneralBlock) -> Result<()> {
        self.current_file_size += block.size();
        let pbo = PcapByteOrder::WiresharkDefault;

        if self.current_file_size >= self.threshold_file_size {
            if self.file_count > 0 {
                self.current_prefix += 1;
                if self.current_prefix >= self.file_count {
                    self.current_prefix = 0;
                }
            }
            let write_path = format!("{}.{}", self.current_prefix, self.write_path);
            let mut fs = File::create(write_path)?;

            if let Some(shb) = &self.shb {
                shb.write(&mut fs, pbo)?;
            } else {
                panic!("shb not found");
            }
            if let Some(idb) = &self.idb {
                idb.write(&mut fs, pbo)?;
            } else {
                panic!("idb not found");
            }

            self.current_file_size = block.size();
            self.write_fs = fs;
        }

        block.write(&mut self.write_fs, pbo)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SplieRuleCount {
    shb: Option<SectionHeaderBlock>,
    idb: Option<InterfaceDescriptionBlock>,
    threshold_num_packet: usize,
    current_num_packet: usize,
    write_path: String,
    write_fs: File,
    // {current_prefix + 1}.write_path => next write path
    current_prefix: usize,
    file_count: usize,
}

impl SplieRuleCount {
    pub fn write(&mut self, block: GeneralBlock) -> Result<()> {
        self.current_num_packet += 1;
        let pbo = PcapByteOrder::WiresharkDefault;

        if self.current_num_packet >= self.threshold_num_packet {
            if self.file_count > 0 {
                self.current_prefix += 1;
                if self.current_prefix >= self.file_count {
                    self.current_prefix = 0;
                }
            }
            let write_path = format!("{}.{}", self.current_prefix, self.write_path);
            let mut fs = File::create(write_path)?;

            if let Some(shb) = &self.shb {
                shb.write(&mut fs, pbo)?;
            } else {
                panic!("shb not found");
            }
            if let Some(idb) = &self.idb {
                idb.write(&mut fs, pbo)?;
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
    None,
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
                idb: None,
                threshold_num_packet: count,
                current_num_packet: 0,
                write_path,
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
                idb: None,
                threshold_file_size: file_size,
                current_file_size: 0,
                write_path,
                write_fs,
                current_prefix: 1,
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
                idb: None,
                threshold_rotate: rotate,
                current_rotate,
                write_path,
                write_fs,
                prefix_format: rotate_format.to_string(),
                current_prefix: current_rotate_str,
            };
            Ok(SplitRule::Rotate(srr))
        } else {
            Ok(SplitRule::None)
        }
    }
}

pub struct Writer {}

impl Writer {
    pub fn new() {}
}
