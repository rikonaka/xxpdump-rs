use anyhow::Result;
use bincode;
use bincode::Decode;
use bincode::Encode;
use bincode::config::Configuration;
use chrono::Local;
use pcapture::Capture;
use pcapture::EnhancedPacketBlock;
use pcapture::GeneralBlock;
use pcapture::PcapByteOrder;
use pcapture::pcap::FileHeader;
use pcapture::pcap::PacketRecord;
use pcapture::pcapng::InterfaceDescriptionBlock;
use pcapture::pcapng::InterfaceStatisticsBlock;
use pcapture::pcapng::NameResolutionBlock;
use pcapture::pcapng::SectionHeaderBlock;
use pcapture::pcapng::SimplePacketBlock;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use strum_macros::EnumString;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::error;
use tracing::warn;

use crate::Args;
use crate::ROTATE_SEC_FORMAT;
use crate::file_size_parser;
use crate::get_file_size;
use crate::rotate_parser;
use crate::upadte_global_stat;

struct ConInfo {
    client_id: usize,
    client_addr: IpAddr,
    client_current_path: String,
}

static CONNECTIONS: LazyLock<Mutex<HashMap<usize, ConInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
enum PcapType {
    Header,
    Record,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct PcapTransport {
    pub p_type: PcapType,
    pub p_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
enum PcapNgType {
    InterfaceDescriptionBlock,
    // PacketBlock,
    SimplePacketBlock,
    NameResolutionBlock,
    InterfaceStatisticsBlock,
    EnhancedPacketBlock,
    SectionHeaderBlock,
    // CustomBlock,
    // CustomBlock2,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct PcapNgTransport {
    pub p_type: PcapNgType,
    pub p_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, EnumString, EnumIter, Serialize, Deserialize, Encode, Decode)]
enum WorkStyle {
    Pcap,
    PcapNg,
}

impl WorkStyle {
    fn to_u8(self) -> u8 {
        self as u8
    }
    fn from_u8(value: u8) -> Option<Self> {
        WorkStyle::iter().find(|&e| e as u8 == value)
    }
}

struct Client {
    stream: TcpStream,
    client_style: WorkStyle,
}

impl Client {
    /// Connecting to a remote backup server.
    async fn connect(addr: &str, client_style: WorkStyle) -> Result<Client> {
        let stream = TcpStream::connect(&addr).await?;
        Ok(Client {
            stream,
            client_style,
        })
    }
    /// Client only send data not recv.
    async fn send_pcap(&mut self, pcap_t: PcapTransport, config: Configuration) -> Result<()> {
        let encode_1 = bincode::encode_to_vec(pcap_t, config)?;
        let encode_len = encode_1.len() as u32;
        let encode_2 = encode_len.to_be_bytes(); // BigEndian on internet

        // first send 4 bytes length
        self.stream.write_all(&encode_2).await?;
        // second send the data
        self.stream.write_all(&encode_1).await?;
        Ok(())
    }
    async fn send_pcapng(
        &mut self,
        pcapng_t: PcapNgTransport,
        config: Configuration,
    ) -> Result<()> {
        let encode_1 = bincode::encode_to_vec(pcapng_t, config)?;
        let encode_len = encode_1.len() as u32;
        let encode_2 = encode_len.to_be_bytes(); // BigEndian on internet

        // first send 4 bytes length
        self.stream.write_all(&encode_2).await?;
        // second send the data
        self.stream.write_all(&encode_1).await?;
        Ok(())
    }
}

fn gen_file_name_by_time(path: &str) -> String {
    let now = Local::now();
    let now_str = now.format(ROTATE_SEC_FORMAT);
    let filename = format!("{}.{}", now_str, path);
    filename
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
            current_file_name: gen_file_name_by_time(path),
        };
        sc
    }
    fn next_file_name(&mut self) -> String {
        let filename = gen_file_name_by_time(&self.user_input_path);
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
            current_file_name: gen_file_name_by_time(path),
        };
        sfs
    }
    fn next_file_name(&mut self) -> String {
        let filename = gen_file_name_by_time(&self.user_input_path);
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
            current_file_name: gen_file_name_by_time(path),
        };
        sr
    }
    fn next_file_name(&mut self) -> String {
        let filename = gen_file_name_by_time(&self.user_input_path);
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
            let sc = SplitCount::init(args.count, path);
            SplitRule::Count(sc)
        } else if args.file_size.len() != 0 {
            let file_size = file_size_parser(&args.file_size);
            let sfs = SplitFileSize::init(file_size, path);
            SplitRule::FileSize(sfs)
        } else if args.rotate.len() != 0 {
            let (rotate_sec, _) = rotate_parser(&args.rotate);
            let sr = SplitRotate::init(rotate_sec, path);
            SplitRule::Rotate(sr)
        } else {
            SplitRule::None
        };
        split
    }
    fn current_file_name(&self, path: &str) -> String {
        match self {
            SplitRule::Count(sc) => sc.current_file_name.clone(),
            SplitRule::FileSize(sfs) => sfs.current_file_name.clone(),
            SplitRule::Rotate(sr) => sr.current_file_name.clone(),
            SplitRule::None => path.to_string(),
        }
    }
    fn next_file_name(&mut self, path: &str) -> String {
        match self {
            SplitRule::Count(sc) => sc.next_file_name(),
            SplitRule::FileSize(sfs) => sfs.next_file_name(),
            SplitRule::Rotate(sr) => sr.next_file_name(),
            SplitRule::None => path.to_string(),
        }
    }
}

#[derive(Debug)]
struct SplitWriter {
    split_rule: SplitRule,
    user_input_path: String, // original user input path, we will construct the new path base on user input path
    fs: File,
}

impl SplitWriter {
    fn new(split: SplitRule, path: &str) -> Result<SplitWriter> {
        let mut split = split.clone();
        let new_path = split.next_file_name(path);
        let fs = File::create(&new_path)?;
        Ok(SplitWriter {
            split_rule: split,
            user_input_path: path.to_string(),
            fs,
        })
    }
    fn pcap_write(
        &mut self,
        pcap_t: &PcapTransport,
        pbo: PcapByteOrder,
        config: Configuration,
    ) -> Result<()> {
        let write_func = |fs: &mut File| -> Result<()> {
            match pcap_t.p_type {
                PcapType::Header => {
                    let decode: (FileHeader, usize) =
                        bincode::decode_from_slice(&pcap_t.p_data, config)?;
                    let (header, _) = decode;
                    header.write(fs, pbo)?;
                }
                PcapType::Record => {
                    let decode: (PacketRecord, usize) =
                        bincode::decode_from_slice(&pcap_t.p_data, config)?;
                    let (record, _) = decode;
                    record.write(fs, pbo)?;
                }
            }
            Ok(())
        };

        match &mut self.split_rule {
            SplitRule::Count(sc) => {
                sc.current_packet_num += 1;
                if sc.current_packet_num >= sc.total_packet_num {
                    sc.current_packet_num = 0;
                    let new_path = sc.next_file_name();
                    let fs = File::create(&new_path)?;
                    self.fs = fs;
                }
                write_func(&mut self.fs)?;
            }
            SplitRule::FileSize(sfs) => {
                let file_size = get_file_size(&sfs.current_file_name);
                if file_size >= sfs.file_size {
                    let new_path = sfs.next_file_name();
                    let fs = File::create(&new_path)?;
                    self.fs = fs;
                }
                write_func(&mut self.fs)?;
            }
            SplitRule::Rotate(sr) => {
                let ep_secs = sr.start.elapsed().as_secs();
                if ep_secs >= sr.rotate_sec {
                    let new_path = sr.next_file_name();
                    let fs = File::create(&new_path)?;
                    self.fs = fs;
                    sr.start += Duration::from_secs(sr.rotate_sec);
                }
                write_func(&mut self.fs)?;
            }
            SplitRule::None => write_func(&mut self.fs)?,
        }

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
                }
                PcapNgType::InterfaceDescriptionBlock => {
                    let decode: (InterfaceDescriptionBlock, usize) =
                        bincode::decode_from_slice(&pcapng_t.p_data, config)?;
                    let (idb, _) = decode;
                    idb.write(fs, pbo)?;
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
                    let new_path = sc.next_file_name();
                    let fs = File::create(&new_path)?;
                    self.fs = fs;
                }
                write_func(&mut self.fs)?;
            }
            SplitRule::FileSize(sfs) => {
                let file_size = get_file_size(&sfs.current_file_name);
                if file_size >= sfs.file_size {
                    let new_path = sfs.next_file_name();
                    let fs = File::create(&new_path)?;
                    self.fs = fs;
                }
                write_func(&mut self.fs)?;
            }
            SplitRule::Rotate(sr) => {
                let ep_secs = sr.start.elapsed().as_secs();
                if ep_secs > sr.rotate_sec {
                    let new_path = sr.next_file_name();
                    let fs = File::create(&new_path)?;
                    self.fs = fs;
                    sr.start += Duration::from_secs(sr.rotate_sec);
                }
                write_func(&mut self.fs)?;
            }
            SplitRule::None => write_func(&mut self.fs)?,
        }

        Ok(())
    }
}

struct Server {
    listener: TcpListener,
    pbo: PcapByteOrder,
    server_style: WorkStyle,
    user_input_path: String,
    split_rule: SplitRule,
}

impl Server {
    async fn init(
        addr: &str,
        pbo: PcapByteOrder,
        server_style: WorkStyle,
        user_input_path: &str,
        split_rule: SplitRule,
    ) -> Result<Server> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Server {
            listener,
            pbo,
            server_style,
            user_input_path: user_input_path.to_string(),
            split_rule,
        })
    }
    async fn recv_pcap(
        socket: &mut TcpStream,
        path: &str,
        pbo: PcapByteOrder,
        split: SplitRule,
    ) -> Result<()> {
        let config = bincode::config::standard();
        let mut writer = SplitWriter::new(split, path)?;
        loop {
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await?;
            let recv_len = u32::from_be_bytes(len_buf) as usize;

            let mut buf = vec![0u8; recv_len];
            socket.read_exact(&mut buf).await?;

            let decode: (PcapTransport, usize) = bincode::decode_from_slice(&buf, config)?;
            let (pcap_t, decode_len) = decode;
            if decode_len == recv_len {
                // it should equal
                writer.pcap_write(&pcap_t, pbo, config)?;
            } else {
                warn!("decode_len[{}] != recv_len[{}]", decode_len, recv_len);
            }
        }
    }
    async fn recv_pcapng(
        socket: &mut TcpStream,
        path: &str,
        pbo: PcapByteOrder,
        split: SplitRule,
    ) -> Result<()> {
        let config = bincode::config::standard();
        let mut writer = SplitWriter::new(split, path)?;
        loop {
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await?;
            let recv_len = u32::from_be_bytes(len_buf) as usize;

            let mut buf = vec![0u8; recv_len];
            socket.read_exact(&mut buf).await?;

            let decode: (PcapNgTransport, usize) = bincode::decode_from_slice(&buf, config)?;
            let (pcapng_t, decode_len) = decode;
            if decode_len == recv_len {
                // it should equal
                writer.pcapng_write(&pcapng_t, pbo, config)?;
            } else {
                warn!("decode_len[{}] != recv_len[{}]", decode_len, recv_len);
            }
        }
    }
    async fn recv(&mut self) -> Result<()> {
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let path = self.user_input_path.to_string();
            let pbo = self.pbo.clone();
            let split = self.split_rule.clone();
            match self.server_style {
                WorkStyle::Pcap => {
                    tokio::spawn(async move {
                        match Self::recv_pcap(&mut socket, &path, pbo, split).await {
                            Ok(_) => (),
                            Err(e) => error!("recv pcap failed: {}", e), // ignore the error and keep running
                        }
                    });
                }
                WorkStyle::PcapNg => {
                    tokio::spawn(async move {
                        match Self::recv_pcapng(&mut socket, &path, pbo, split).await {
                            Ok(_) => (),
                            Err(e) => error!("recv pcapng failed: {}", e), // ignore the error and keep running
                        }
                    });
                }
            }
        }
    }
}

pub async fn capture_remote_server(args: &Args) -> Result<()> {
    let pbo = PcapByteOrder::WiresharkDefault; // default
    let server_style = WorkStyle::PcapNg; // default
    let split_rule = SplitRule::init(args);

    let mut server =
        Server::init(&args.server_addr, pbo, server_style, &args.path, split_rule).await?;
    server.recv().await?;
    Ok(())
}

pub async fn capture_remote_client(cap: &Capture, args: &Args) -> Result<()> {
    let pbo = PcapByteOrder::WiresharkDefault; // default
    let client_style = WorkStyle::PcapNg; // default
    let config = bincode::config::standard();

    let mut client = Client::connect(&args.server_addr, client_style).await?;
    let pcapng = cap.gen_pcapng(pbo);

    for p in pcapng.blocks {
        let (p_type, p_data) = match p {
            GeneralBlock::SectionHeaderBlock(shb) => {
                (PcapNgType::SectionHeaderBlock, shb.to_vec(pbo)?)
            }
            GeneralBlock::InterfaceDescriptionBlock(idb) => {
                (PcapNgType::InterfaceDescriptionBlock, idb.to_vec(pbo)?)
            }
            GeneralBlock::EnhancedPacketBlock(epb) => {
                (PcapNgType::EnhancedPacketBlock, epb.to_vec(pbo)?)
            }
            GeneralBlock::SimplePacketBlock(spb) => {
                (PcapNgType::SimplePacketBlock, spb.to_vec(pbo)?)
            }
            GeneralBlock::InterfaceStatisticsBlock(isb) => {
                (PcapNgType::InterfaceStatisticsBlock, isb.to_vec(pbo)?)
            }
            GeneralBlock::NameResolutionBlock(nrb) => {
                (PcapNgType::NameResolutionBlock, nrb.to_vec(pbo)?)
            }
        };
        let pcapng_t = PcapNgTransport { p_type, p_data };
        client.send_pcapng(pcapng_t, config);
    }

    loop {
        let block = cap.next_with_pcapng().expect("capture packet failed");
        upadte_global_stat();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn server_presudo_code() {
        let addr = "127.0.0.1:8888";
        let path = "xxpdump_net.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
    }
}
