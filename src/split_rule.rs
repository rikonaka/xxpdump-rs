use anyhow::Result;
use bincode::config::Configuration;
use chrono::Local;
use pcapture::PcapByteOrder;
use pcapture::pcapng::EnhancedPacketBlock;
use pcapture::pcapng::InterfaceDescriptionBlock;
use pcapture::pcapng::InterfaceStatisticsBlock;
use pcapture::pcapng::NameResolutionBlock;
use pcapture::pcapng::SectionHeaderBlock;
use pcapture::pcapng::SimplePacketBlock;
use std::collections::HashMap;
use std::fs::File;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;
use tracing::error;

use crate::Args;
use crate::PcapNgTransport;
use crate::PcapNgType;
use crate::ROTATE_SEC_FORMAT;
use crate::file_size_parser;
use crate::get_file_size;
use crate::rotate_parser;

static HEADERS_SHB: LazyLock<Mutex<HashMap<String, SectionHeaderBlock>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static HEADERS_IDB: LazyLock<Mutex<HashMap<String, InterfaceDescriptionBlock>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct HEADERS;

impl HEADERS {
    pub fn update_headers_shb(uuid: &str, shb: SectionHeaderBlock) {
        let mut p = match HEADERS_SHB.lock() {
            Ok(p) => p,
            Err(e) => panic!("try update and lock HEADERS_SHB failed: {}", e),
        };
        (*p).insert(uuid.to_string(), shb);
    }
    pub fn get_header_shb(uuid: &str) -> Option<SectionHeaderBlock> {
        let p = match HEADERS_SHB.lock() {
            Ok(p) => p,
            Err(e) => panic!("lock HEADERS_SHB failed: {}", e),
        };
        debug!("HEADERS_SHB: {:?}", p);
        match p.get(uuid) {
            Some(shb) => Some(shb.clone()),
            None => None,
        }
    }
    pub fn update_headers_idb(uuid: &str, idb: InterfaceDescriptionBlock) {
        let mut p = match HEADERS_IDB.lock() {
            Ok(p) => p,
            Err(e) => panic!("try update and lock HEADERS_IDB failed: {}", e),
        };
        (*p).insert(uuid.to_string(), idb);
    }
    pub fn get_header_idb(uuid: &str) -> Option<InterfaceDescriptionBlock> {
        let p = match HEADERS_IDB.lock() {
            Ok(p) => p,
            Err(e) => panic!("lock HEADERS_IDB failed: {}", e),
        };
        debug!("HEADERS_IDB: {:?}", p);
        match p.get(uuid) {
            Some(idb) => Some(idb.clone()),
            None => None,
        }
    }
}

fn gen_file_name_simple(path: &str, uuid: &str) -> String {
    let now = Local::now();
    let now_str = now.format(ROTATE_SEC_FORMAT);
    let uuid_split: Vec<&str> = uuid.split("-").collect();
    let filename = format!("{}.{}.{}", now_str, uuid_split[0], path);
    filename
}

fn write_packet(
    fs: &mut File,
    client_uuid: &str,
    pcapng_t: PcapNgTransport,
    pbo: PcapByteOrder,
    config: Configuration,
) -> Result<()> {
    match pcapng_t.p_type {
        PcapNgType::SectionHeaderBlock => {
            let decode: (SectionHeaderBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (shb, _) = decode;
            shb.write(fs, pbo)?;
            HEADERS::update_headers_shb(client_uuid, shb);
        }
        PcapNgType::InterfaceDescriptionBlock => {
            let decode: (InterfaceDescriptionBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (idb, _) = decode;
            idb.write(fs, pbo)?;
            HEADERS::update_headers_idb(client_uuid, idb);
        }
        PcapNgType::EnhancedPacketBlock => {
            let decode: (EnhancedPacketBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (epb, _) = decode;
            epb.write(fs, pbo)?;
        }
        PcapNgType::SimplePacketBlock => {
            let decode: (SimplePacketBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (spb, _) = decode;
            spb.write(fs, pbo)?;
        }
        PcapNgType::InterfaceStatisticsBlock => {
            let decode: (InterfaceStatisticsBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (isb, _) = decode;
            isb.write(fs, pbo)?;
        }
        PcapNgType::NameResolutionBlock => {
            let decode: (NameResolutionBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (nrb, _) = decode;
            nrb.write(fs, pbo)?;
        }
    }
    Ok(())
}

fn shb_not_found(client_uuid: &str) -> String {
    let r = format!(
        "shb can not be found, you will not be able to open the client [{}] traffic correctly, it is recommended to restart the client",
        client_uuid
    );
    r
}

fn idb_not_found(client_uuid: &str) -> String {
    let r = format!(
        "idb can not be found, you will not be able to open the client [{}] traffic correctly, it is recommended to restart the client",
        client_uuid
    );
    r
}

#[derive(Debug, Clone)]
pub struct SplitCount {
    // When the number of received data packets is greater than this, the file will be cut.
    count_threshold: usize,
    // The number of packets currently received.
    // When the threshold is reached, this value will be reset to zero.
    count_current: usize,
    // The file path entered by the user.
    path: String,
}

impl SplitCount {
    pub fn init(count: usize, path: &str) -> SplitCount {
        SplitCount {
            count_threshold: count,
            count_current: 0,
            path: path.to_string(),
        }
    }
    fn next_write_file(&mut self, uuid: &str) -> String {
        let next_write_file = gen_file_name_simple(&self.path, uuid);
        next_write_file
    }
    pub fn write(&mut self, client_uuid: &str, pcapng_t: PcapNgTransport) -> Result<()> {
        self.count_current += 1;
        if self.count_current >= self.count_threshold {
            // update the target file
            self.count_current = 0;
            let next_write_file = self.next_write_file(client_uuid);
            let mut fs = File::create(&next_write_file)?;

            let shb = match HEADERS::get_header_shb(client_uuid) {
                Some(shb) => shb,
                None => {
                    error!("{}", shb_not_found(client_uuid));
                    return Ok(());
                }
            };
            let idb = match HEADERS::get_header_idb(client_uuid) {
                Some(idb) => idb,
                None => {
                    error!("{}", idb_not_found(client_uuid));
                    return Ok(());
                }
            };
            shb.write(&mut fs, self.pbo)?;
            idb.write(&mut fs, self.pbo)?;
        }
        match &mut self.fs {
            Some(fs) => write_packet(fs, client_uuid, pcapng_t, self.pbo, self.config),
            None => panic!("target fs is none"),
        }
    }
}

pub struct SplitFileSize {
    filesize_threshold: u64,
    path: String,
    current_file: String,
    fs: Option<File>,
    pbo: PcapByteOrder,
    config: Configuration,
}

impl SplitFileSize {
    pub fn init(
        file_size: u64,
        path: &str,
        pbo: PcapByteOrder,
        config: Configuration,
    ) -> SplitFileSize {
        SplitFileSize {
            filesize_threshold: file_size,
            path: path.to_string(),
            current_file: String::new(),
            fs: None,
            pbo,
            config,
        }
    }
    fn next_write_file(&mut self, uuid: &str) -> String {
        let next_write_file = gen_file_name_simple(&self.path, uuid);
        next_write_file
    }
    pub fn write(&mut self, client_uuid: &str, pcapng_t: PcapNgTransport) -> Result<()> {
        let filesize = get_file_size(&self.current_file);
        if filesize >= self.filesize_threshold {
            let new_path = self.next_write_file(client_uuid);
            let mut fs = File::create(&new_path)?;

            let shb = match HEADERS::get_header_shb(client_uuid) {
                Some(shb) => shb,
                None => {
                    error!("{}", shb_not_found(client_uuid));
                    return Ok(());
                }
            };
            let idb = match HEADERS::get_header_idb(client_uuid) {
                Some(idb) => idb,
                None => {
                    error!("{}", idb_not_found(client_uuid));
                    return Ok(());
                }
            };
            shb.write(&mut fs, self.pbo)?;
            idb.write(&mut fs, self.pbo)?;

            self.fs = Some(fs);
        }
        match &mut self.fs {
            Some(fs) => write_packet(fs, client_uuid, pcapng_t, self.pbo, self.config),
            None => panic!("target fs is none"),
        }
    }
}

pub struct SplitRotate {
    start_time: Instant,
    rotate_threshold: u64,
    path: String,
    current_file: String,
    fs: Option<File>,
    pbo: PcapByteOrder,
    config: Configuration,
}

impl SplitRotate {
    fn init(rotate_sec: u64, path: &str, pbo: PcapByteOrder, config: Configuration) -> SplitRotate {
        SplitRotate {
            start_time: Instant::now(),
            rotate_threshold: rotate_sec,
            path: path.to_string(),
            current_file: String::new(),
            fs: None,
            pbo,
            config,
        }
    }
    fn next_write_file(&self, client_uuid: &str) -> String {
        let next_write_file = gen_file_name_simple(&self.path, client_uuid);
        next_write_file
    }
    pub fn write(&mut self, client_uuid: &str, pcapng_t: PcapNgTransport) -> Result<()> {
        let ep_secs = self.start_time.elapsed().as_secs();
        if ep_secs > self.rotate_threshold {
            let new_path = self.next_write_file(client_uuid);
            let mut fs = File::create(&new_path)?;

            let shb = match HEADERS::get_header_shb(client_uuid) {
                Some(shb) => shb,
                None => {
                    error!("{}", shb_not_found(client_uuid));
                    return Ok(());
                }
            };
            let idb = match HEADERS::get_header_idb(client_uuid) {
                Some(idb) => idb,
                None => {
                    error!("{}", idb_not_found(client_uuid));
                    return Ok(());
                }
            };
            shb.write(&mut fs, self.pbo)?;
            idb.write(&mut fs, self.pbo)?;

            self.fs = Some(fs);
            self.start_time += Duration::from_secs(self.rotate_threshold);
        }
        match &mut self.fs {
            Some(fs) => write_packet(fs, client_uuid, pcapng_t, self.pbo, self.config),
            None => panic!("target fs is none"),
        }
    }
}

pub struct SplitNone {
    path: String,
    fs: Option<File>,
    pbo: PcapByteOrder,
    config: Configuration,
}

impl SplitNone {
    fn init(path: &str, pbo: PcapByteOrder, config: Configuration) -> SplitNone {
        SplitNone {
            path: path.to_string(),
            fs: None,
            pbo,
            config,
        }
    }
    pub fn write(&mut self, client_uuid: &str, pcapng_t: PcapNgTransport) -> Result<()> {
        match self.fs {
            Some(_) => (),
            None => {
                let mut fs = File::create(&self.path)?;
                let shb = match HEADERS::get_header_shb(client_uuid) {
                    Some(shb) => shb,
                    None => {
                        error!("{}", shb_not_found(client_uuid));
                        return Ok(());
                    }
                };
                let idb = match HEADERS::get_header_idb(client_uuid) {
                    Some(idb) => idb,
                    None => {
                        error!("{}", idb_not_found(client_uuid));
                        return Ok(());
                    }
                };
                shb.write(&mut fs, self.pbo)?;
                idb.write(&mut fs, self.pbo)?;

                self.fs = Some(fs);
            }
        }

        match &mut self.fs {
            Some(fs) => write_packet(fs, client_uuid, pcapng_t, self.pbo, self.config),
            None => panic!("target fs is none"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SplitRule {
    Count(SplitCount),
    FileSize(SplitFileSize),
    Rotate(SplitRotate),
    None(SplitNone),
}

impl SplitRule {
    pub fn init(args: &Args, pbo: PcapByteOrder, config: Configuration) -> SplitRule {
        let path = &args.write;
        let split = if args.count > 0 {
            debug!("split count");
            let sc = SplitCount::init(args.count, path, pbo, config);
            SplitRule::Count(sc)
        } else if args.file_size.len() != 0 {
            debug!("split file size");
            let file_size = file_size_parser(&args.file_size);
            let sfs = SplitFileSize::init(file_size, path, pbo, config);
            SplitRule::FileSize(sfs)
        } else if args.rotate.len() != 0 {
            debug!("split rotate");
            let (rotate_sec, _) = rotate_parser(&args.rotate);
            let sr = SplitRotate::init(rotate_sec, path, pbo, config);
            SplitRule::Rotate(sr)
        } else {
            debug!("split none");
            let sn = SplitNone::init(path, pbo, config);
            SplitRule::None(sn)
        };
        split
    }
    fn update_current_file(&mut self, current_file: &str) {
        match self {
            SplitRule::FileSize(sfs) => sfs.current_file = current_file.to_string(),
            SplitRule::Rotate(sr) => sr.current_file = current_file.to_string(),
            _ => (),
        }
    }
    pub fn write(&mut self, client_uuid: &str, pcapng_t: &PcapNgTransport) -> Result<()> {
        // lazy, init once and use it below
        match self {
            SplitRule::Count(sc) => sc.write(client_uuid, pcapng_t.clone())?,
            SplitRule::FileSize(sfs) => sfs.write(client_uuid, pcapng_t.clone())?,
            SplitRule::Rotate(sr) => sr.write(client_uuid, pcapng_t.clone())?,
            SplitRule::None(sn) => sn.write(client_uuid, pcapng_t.clone())?,
        }
        Ok(())
    }
}
