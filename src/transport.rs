use anyhow::Result;
use bincode;
use bincode::Decode;
use bincode::Encode;
use pcapture::PcapByteOrder;
use pcapture::pcap::FileHeader;
use pcapture::pcap::PacketRecord;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum PcapType {
    Header,
    Record,
    // recv this message means the server need split the file
    Split,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PcapTransport {
    pub p_type: PcapType,
    pub p_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum PcapNgType {
    InterfaceDescriptionBlock,
    PacketBlock,
    SimplePacketBlock,
    NameResolutionBlock,
    InterfaceStatisticsBlock,
    EnhancedPacketBlock,
    SectionHeaderBlock,
    // CustomBlock,
    // CustomBlock2,
    // recv this message means the server need split the file
    Split,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PcapNgTransport {
    pub p_type: PcapNgType,
    pub p_data: Vec<u8>,
}

pub struct Client {
    stream: TcpStream,
    is_pcapng: bool,
}

impl Client {
    /// Connecting to a remote backup server.
    pub fn connect(url: &str, port: u16) -> Result<Client> {
        let addr = format!("{}:{}", url, port);
        let stream = TcpStream::connect(&addr)?;
        Ok(Client {
            stream,
            is_pcapng: true,
        })
    }
    /// Client only send data not recv.
    pub fn send_pcap(&mut self, pcap_t: PcapTransport) -> Result<()> {
        let config = bincode::config::standard();
        let encode_1 = bincode::encode_to_vec(pcap_t, config)?;
        let encode_len = encode_1.len() as u32;
        let encode_2 = encode_len.to_be_bytes(); // BigEndian on internet

        // first send 4 bytes length
        self.stream.write_all(&encode_2)?;
        // second send the data
        self.stream.write_all(&encode_1)?;
        Ok(())
    }
    /// Using pcap format.
    pub fn use_pcap(&mut self) {
        self.is_pcapng = false;
    }
    /// Using pcapng format (default).
    pub fn use_pcapng(&mut self) {
        self.is_pcapng = true;
    }
}

pub struct Server {
    listener: TcpListener,
    fs: Option<File>,
    pbo: Option<PcapByteOrder>,
}

impl Server {
    pub fn listen() -> Result<Server> {
        let listener = TcpListener::bind("127.0.0.1:4000")?;
        Ok(Server {
            listener,
            fs: None,
            pbo: None,
        })
    }
    pub fn set_output_path(&mut self, path: &str) {
        let fs = File::create(path).expect(&format!("create save file [{}] failed", path));
        self.fs = Some(fs);
    }
    pub fn set_pbo(&mut self, pbo: PcapByteOrder) {
        self.pbo = Some(pbo);
    }
    pub fn recv_pcap(&mut self) -> Result<()> {
        for stream in self.listener.incoming() {
            let mut stream = stream?;
            let mut reader = BufReader::new(&mut stream);

            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let recv_len = u32::from_be_bytes(len_buf) as usize;

            let mut buf = vec![0u8; recv_len];
            reader.read_exact(&mut buf)?;

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
                            PcapType::Split => todo!(),
                        }
                    }
                    None => todo!(),
                }
            } else {
                todo!()
            }
        }
        Ok(())
    }
}
