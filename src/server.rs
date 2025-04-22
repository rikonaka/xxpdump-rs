use anyhow::Result;
use bincode;
use bincode::config::Configuration;
use pcapture::EnhancedPacketBlock;
use pcapture::PcapByteOrder;
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
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Args;
use crate::PcapNgTransport;
use crate::PcapNgType;
use crate::file_size_parser;
use crate::gen_file_name_simple;
use crate::get_file_size;
use crate::rotate_parser;
use crate::update_server_recved_stat;

static HEADERS_SHB: LazyLock<Mutex<HashMap<String, SectionHeaderBlock>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static HEADERS_IDB: LazyLock<Mutex<HashMap<String, InterfaceDescriptionBlock>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn update_headers_shb(uuid: &str, shb: SectionHeaderBlock) {
    let mut p = match HEADERS_SHB.lock() {
        Ok(p) => p,
        Err(e) => panic!("try update and lock HEADERS_SHB failed: {}", e),
    };
    (*p).insert(uuid.to_string(), shb);
}

fn get_header_shb(uuid: &str) -> Option<SectionHeaderBlock> {
    let p = match HEADERS_SHB.lock() {
        Ok(p) => p,
        Err(e) => panic!("lock HEADERS_SHB failed: {}", e),
    };
    match p.get(uuid) {
        Some(shb) => Some(shb.clone()),
        None => None,
    }
}

fn update_headers_idb(uuid: &str, idb: InterfaceDescriptionBlock) {
    let mut p = match HEADERS_IDB.lock() {
        Ok(p) => p,
        Err(e) => panic!("try update and lock HEADERS_IDB failed: {}", e),
    };
    (*p).insert(uuid.to_string(), idb);
}

fn get_header_idb(uuid: &str) -> Option<InterfaceDescriptionBlock> {
    let p = match HEADERS_IDB.lock() {
        Ok(p) => p,
        Err(e) => panic!("lock HEADERS_IDB failed: {}", e),
    };
    match p.get(uuid) {
        Some(idb) => Some(idb.clone()),
        None => None,
    }
}

#[derive(Debug, Clone)]
struct SplitCount {
    total_packet_num: usize,   // total value
    current_packet_num: usize, // current value
    user_input_path: String,
    current_file_name: String,
}

impl SplitCount {
    fn init(count: usize, path: &str) -> SplitCount {
        let sc = SplitCount {
            total_packet_num: count,
            current_packet_num: 0,
            user_input_path: path.to_string(),
            current_file_name: String::new(),
        };
        sc
    }
    fn next_file_name(&mut self, uuid: &str) -> String {
        let filename = gen_file_name_simple(&self.user_input_path, uuid);
        self.current_file_name = filename.clone();
        filename
    }
}

#[derive(Debug, Clone)]
struct SplitFileSize {
    file_size: u64,
    user_input_path: String,
    current_file_name: String,
}

impl SplitFileSize {
    fn init(file_size: u64, path: &str) -> SplitFileSize {
        let sfs = SplitFileSize {
            file_size,
            user_input_path: path.to_string(),
            current_file_name: String::new(),
        };
        sfs
    }
    fn next_file_name(&mut self, uuid: &str) -> String {
        let filename = gen_file_name_simple(&self.user_input_path, uuid);
        self.current_file_name = filename.clone();
        filename
    }
}

#[derive(Debug, Clone)]
struct SplitRotate {
    start: Instant,
    rotate_sec: u64,
    user_input_path: String,
    current_file_name: String,
}

impl SplitRotate {
    fn init(rotate_sec: u64, path: &str) -> SplitRotate {
        let sr = SplitRotate {
            start: Instant::now(),
            rotate_sec,
            user_input_path: path.to_string(),
            current_file_name: String::new(),
        };
        sr
    }
    fn next_file_name(&mut self, client_uuid: &str) -> String {
        let filename = gen_file_name_simple(&self.user_input_path, client_uuid);
        self.current_file_name = filename.clone();
        filename
    }
}

#[derive(Debug, Clone)]
enum SplitRule {
    Count(SplitCount),
    FileSize(SplitFileSize),
    Rotate(SplitRotate),
    None,
}

impl SplitRule {
    fn init(args: &Args) -> SplitRule {
        let path = &args.path;
        let split = if args.count > 0 {
            debug!("split count");
            let sc = SplitCount::init(args.count, path);
            SplitRule::Count(sc)
        } else if args.file_size.len() != 0 {
            debug!("split file size");
            let file_size = file_size_parser(&args.file_size);
            let sfs = SplitFileSize::init(file_size, path);
            SplitRule::FileSize(sfs)
        } else if args.rotate.len() != 0 {
            debug!("split rotate");
            let (rotate_sec, _) = rotate_parser(&args.rotate);
            let sr = SplitRotate::init(rotate_sec, path);
            SplitRule::Rotate(sr)
        } else {
            debug!("split none");
            SplitRule::None
        };
        split
    }
    fn update_current_file_name(&mut self, path: &str) {
        match self {
            SplitRule::Count(sc) => sc.current_file_name = path.to_string(),
            SplitRule::FileSize(sfs) => sfs.current_file_name = path.to_string(),
            SplitRule::Rotate(sr) => sr.current_file_name = path.to_string(),
            SplitRule::None => (),
        }
    }
}

#[derive(Debug)]
struct SplitWriter {
    split_rule: SplitRule,
    user_input_path: String,
    client_uuid: String,
    fs: Option<File>,
}

impl SplitWriter {
    fn new(split: SplitRule, path: &str) -> Result<SplitWriter> {
        let split = split.clone();
        Ok(SplitWriter {
            split_rule: split,
            user_input_path: path.to_string(),
            client_uuid: String::new(),
            fs: None,
        })
    }
    fn update_uuid(&mut self, uuid: &str) -> Result<()> {
        self.client_uuid = uuid.to_string();
        let target_path = gen_file_name_simple(&self.user_input_path, &self.client_uuid);
        self.split_rule.update_current_file_name(&target_path);
        let fs = File::create(target_path)?;
        self.fs = Some(fs);
        Ok(())
    }
    fn pcapng_write(
        &mut self,
        pcapng_t: &PcapNgTransport,
        pbo: PcapByteOrder,
        config: Configuration,
    ) -> Result<()> {
        let write_func = |fs: &mut File| -> Result<()> {
            match pcapng_t.p_type {
                PcapNgType::SectionHeaderBlock => {
                    let decode: (SectionHeaderBlock, usize) =
                        bincode::decode_from_slice(&pcapng_t.p_data, config)?;
                    let (shb, _) = decode;
                    shb.write(fs, pbo)?;
                    update_headers_shb(&self.client_uuid, shb);
                }
                PcapNgType::InterfaceDescriptionBlock => {
                    let decode: (InterfaceDescriptionBlock, usize) =
                        bincode::decode_from_slice(&pcapng_t.p_data, config)?;
                    let (idb, _) = decode;
                    idb.write(fs, pbo)?;
                    update_headers_idb(&self.client_uuid, idb);
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
        };

        match &mut self.split_rule {
            SplitRule::Count(sc) => {
                sc.current_packet_num += 1;
                if sc.current_packet_num >= sc.total_packet_num {
                    sc.current_packet_num = 0;
                    let new_path = sc.next_file_name(&self.client_uuid);
                    let mut fs = File::create(&new_path)?;

                    let shb = match get_header_shb(&self.client_uuid) {
                        Some(shb) => shb,
                        None => panic!("shb can not be found"),
                    };
                    let idb = match get_header_idb(&self.client_uuid) {
                        Some(idb) => idb,
                        None => panic!("idb can not be found"),
                    };
                    shb.write(&mut fs, pbo)?;
                    idb.write(&mut fs, pbo)?;

                    self.fs = Some(fs);
                }
                match &mut self.fs {
                    Some(fs) => write_func(fs)?,
                    None => panic!("target fs is none"),
                }
            }
            SplitRule::FileSize(sfs) => {
                let file_size = get_file_size(&sfs.current_file_name);
                if file_size >= sfs.file_size {
                    let new_path = sfs.next_file_name(&self.client_uuid);
                    let mut fs = File::create(&new_path)?;

                    let shb = match get_header_shb(&self.client_uuid) {
                        Some(shb) => shb,
                        None => panic!("shb can not be found"),
                    };
                    let idb = match get_header_idb(&self.client_uuid) {
                        Some(idb) => idb,
                        None => panic!("idb can not be found"),
                    };
                    shb.write(&mut fs, pbo)?;
                    idb.write(&mut fs, pbo)?;

                    self.fs = Some(fs);
                }
                match &mut self.fs {
                    Some(fs) => write_func(fs)?,
                    None => panic!("target fs is none"),
                }
            }
            SplitRule::Rotate(sr) => {
                let ep_secs = sr.start.elapsed().as_secs();
                if ep_secs > sr.rotate_sec {
                    let new_path = sr.next_file_name(&self.client_uuid);
                    let mut fs = File::create(&new_path)?;

                    let shb = match get_header_shb(&self.client_uuid) {
                        Some(shb) => shb,
                        None => panic!("shb can not be found"),
                    };
                    let idb = match get_header_idb(&self.client_uuid) {
                        Some(idb) => idb,
                        None => panic!("idb can not be found"),
                    };
                    shb.write(&mut fs, pbo)?;
                    idb.write(&mut fs, pbo)?;

                    self.fs = Some(fs);
                    sr.start += Duration::from_secs(sr.rotate_sec);
                }
                match &mut self.fs {
                    Some(fs) => write_func(fs)?,
                    None => panic!("target fs is none"),
                }
            }
            SplitRule::None => match &mut self.fs {
                Some(fs) => write_func(fs)?,
                None => panic!("target fs is none"),
            },
        }

        Ok(())
    }
}

struct Server {
    listener: TcpListener,
    pbo: PcapByteOrder,
    user_input_path: String,
    split_rule: SplitRule,
}

impl Server {
    async fn init(
        addr: &str,
        pbo: PcapByteOrder,
        user_input_path: &str,
        split_rule: SplitRule,
    ) -> Result<Server> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Server {
            listener,
            pbo,
            user_input_path: user_input_path.to_string(),
            split_rule,
        })
    }
    async fn recv_pcapng(
        socket: &mut TcpStream,
        path: &str,
        pbo: PcapByteOrder,
        split: SplitRule,
    ) -> Result<()> {
        let config = bincode::config::standard();
        let mut writer = SplitWriter::new(split, path)?;
        let mut uuid = String::new();
        loop {
            let mut len_buf = [0u8; 4];
            match socket.read_exact(&mut len_buf).await {
                Ok(_) => (),
                Err(e) => {
                    error!("read len failed [{}]: {}", &uuid, e);
                    return Ok(());
                }
            };
            let recv_len = u32::from_be_bytes(len_buf) as usize;

            let mut buf = vec![0u8; recv_len];
            match socket.read_exact(&mut buf).await {
                Ok(_) => (),
                Err(e) => {
                    error!("read data failed [{}]: {}", &uuid, e);
                    return Ok(());
                }
            };

            let decode: (PcapNgTransport, usize) = bincode::decode_from_slice(&buf, config)?;
            let (pcapng_t, decode_len) = decode;
            if decode_len == recv_len {
                // it should equal
                writer.update_uuid(&pcapng_t.p_uuid)?;
                writer.pcapng_write(&pcapng_t, pbo, config)?;
                update_server_recved_stat();
                uuid = pcapng_t.p_uuid;
            } else {
                warn!("decode_len[{}] != recv_len[{}]", decode_len, recv_len);
            }
        }
    }
    async fn recv_block_loop(&mut self) -> Result<()> {
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let path = self.user_input_path.to_string();
            let pbo = self.pbo.clone();
            let split = self.split_rule.clone();

            // the default format is pcapng
            tokio::spawn(async move {
                match Self::recv_pcapng(&mut socket, &path, pbo, split).await {
                    Ok(_) => (),
                    Err(e) => error!("recv pcapng from failed: {}", e), // ignore the error and keep running
                }
            });
        }
    }
}

pub async fn capture_remote_server(args: &Args) -> Result<()> {
    info!("listening at {}", args.server_addr);
    let pbo = PcapByteOrder::WiresharkDefault; // default
    let split_rule = SplitRule::init(args);

    let mut server = Server::init(&args.server_addr, pbo, &args.path, split_rule).await?;
    server.recv_block_loop().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use uuid::Uuid;
    #[test]
    fn uuid_gen() {
        let uuid = Uuid::new_v4();
        // aa3293ec-5cec-4984-aa19-56d462bdc0eb
        println!("{}", uuid);
    }
}
