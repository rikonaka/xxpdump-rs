use anyhow::Result;
use bincode;
use bincode::Decode;
use bincode::Encode;
use bincode::config::Configuration;
use pcapture::EnhancedPacketBlock;
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
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use strum_macros::EnumString;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use crate::file_size_parser;
use crate::rotate_parser;

struct ConInfo {
    client_id: usize,
    client_addr: IpAddr,
    client_current_path: String,
}

static CONNECTIONS: LazyLock<Mutex<HashMap<usize, ConInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum PcapType {
    Header,
    Record,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PcapTransport {
    pub p_type: PcapType,
    pub p_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum PcapNgType {
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
pub struct PcapNgTransport {
    pub p_type: PcapNgType,
    pub p_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, EnumString, EnumIter, Serialize, Deserialize, Encode, Decode)]
pub enum WorkStyle {
    Pcap,
    PcapNg,
}

impl WorkStyle {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        WorkStyle::iter().find(|&e| e as u8 == value)
    }
}

pub struct Client {
    stream: TcpStream,
    client_style: WorkStyle,
}

impl Client {
    /// Connecting to a remote backup server.
    pub async fn connect(url: &str, port: u16, client_type: WorkStyle) -> Result<Client> {
        let addr = format!("{}:{}", url, port);
        let stream = TcpStream::connect(&addr).await?;
        Ok(Client {
            stream,
            client_style: client_type,
        })
    }
    /// Client only send data not recv.
    pub async fn send_pcap(&mut self, pcap_t: PcapTransport) -> Result<()> {
        let config = bincode::config::standard();
        let encode_1 = bincode::encode_to_vec(pcap_t, config)?;
        let encode_len = encode_1.len() as u32;
        let encode_2 = encode_len.to_be_bytes(); // BigEndian on internet

        // first send 4 bytes length
        self.stream.write_all(&encode_2).await?;
        // second send the data
        self.stream.write_all(&encode_1).await?;
        Ok(())
    }
}

pub struct SplitCount {
    current: usize,
}

pub enum Split {
    Count(usize),
    None,
}

pub struct Server {
    listener: TcpListener,
    pbo: PcapByteOrder,
    server_style: WorkStyle,
    path: String,
    split: Split,
    fs: Option<File>,
}

impl Server {
    fn check_and_change_target_path(&mut self) -> Result<()> {
        match self.split {
            Split::Count(count) => {
                let fs = File::create(&self.path)?;
                self.fs = Some(fs);
            }
            Split::None => (),
        }
        Ok(())
    }

    pub async fn init(
        addr: &str,
        pbo: PcapByteOrder,
        server_type: WorkStyle,
        path: &str,
        split: Split,
    ) -> Result<Server> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Server {
            listener,
            pbo,
            server_style: server_type,
            path: path.to_string(),
            split,
            fs: None,
        })
    }
    async fn recv_pcap(socket: &mut TcpStream) -> Result<()> {
        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await?;
        let recv_len = u32::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; recv_len];
        socket.read_exact(&mut buf).await?;

        let config = bincode::config::standard();
        let decode: (PcapTransport, usize) = bincode::decode_from_slice(&buf, config)?;
        let (pcap_t, decode_len) = decode;
        if decode_len == recv_len {
            // it should equal
            match &mut self.fs {
                Some(fs) => {
                    let pbo = match self.pbo {
                        Some(pbo) => pbo,
                        None => PcapByteOrder::WiresharkDefault,
                    };
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
                }
                None => todo!(),
            }
        } else {
            todo!()
        }
        Ok(())
    }
    async fn recv_pcapng(socket: &mut TcpStream) -> Result<()> {
        Ok(())
    }
    async fn recv(&mut self) -> Result<()> {
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            tokio::spawn(async move {
                match self.server_style {
                    WorkStyle::Pcap => Self::recv_pcap(&mut socket).await,
                    WorkStyle::PcapNg => Self::recv_pcapng(&mut socket).await,
                }
            });
        }

        Ok(())
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
