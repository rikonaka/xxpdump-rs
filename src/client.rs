use anyhow::Result;
use bincode;
use bincode::config::Configuration;
use pcapture::Capture;
use pcapture::GeneralBlock;
use pcapture::PcapByteOrder;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::Args;
use crate::PcapNgTransport;
use crate::PcapNgType;
use crate::update_captured_stat;

struct Client {
    stream: TcpStream,
}

impl Client {
    /// Connecting to a remote backup server.
    async fn connect(addr: &str) -> Result<Client> {
        let stream = TcpStream::connect(&addr).await?;
        Ok(Client { stream })
    }
    /// Client only send data not recv.
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
    async fn send_block(
        &mut self,
        block: GeneralBlock,
        p_uuid: &str,
        config: Configuration,
    ) -> Result<()> {
        let (p_type, p_data) = match block {
            GeneralBlock::SectionHeaderBlock(shb) => (
                PcapNgType::SectionHeaderBlock,
                bincode::encode_to_vec(shb, config)?,
            ),
            GeneralBlock::InterfaceDescriptionBlock(idb) => (
                PcapNgType::InterfaceDescriptionBlock,
                bincode::encode_to_vec(idb, config)?,
            ),
            GeneralBlock::EnhancedPacketBlock(epb) => (
                PcapNgType::EnhancedPacketBlock,
                bincode::encode_to_vec(epb, config)?,
            ),
            GeneralBlock::SimplePacketBlock(spb) => (
                PcapNgType::SimplePacketBlock,
                bincode::encode_to_vec(spb, config)?,
            ),
            GeneralBlock::InterfaceStatisticsBlock(isb) => (
                PcapNgType::InterfaceStatisticsBlock,
                bincode::encode_to_vec(isb, config)?,
            ),
            GeneralBlock::NameResolutionBlock(nrb) => (
                PcapNgType::NameResolutionBlock,
                bincode::encode_to_vec(nrb, config)?,
            ),
        };
        let pcapng_t = PcapNgTransport {
            p_type,
            p_uuid: p_uuid.to_string(),
            p_data,
        };
        self.send_pcapng(pcapng_t, config).await?;
        Ok(())
    }
}

const CLIENT_UUID_PATH: &str = ".client_uuid";

fn find_uuid() -> Result<String> {
    let client_uuid_path = Path::new(CLIENT_UUID_PATH);
    let uuid = if client_uuid_path.exists() {
        let mut client_uuid_fs = File::open(client_uuid_path)?;
        let mut uuid_str = String::new();
        let _ = client_uuid_fs.read_to_string(&mut uuid_str)?;
        uuid_str
    } else {
        // create a new uuid for client
        let uuid = Uuid::new_v4();
        let uuid_str = uuid.to_string();
        let mut fs = File::create(client_uuid_path)?;
        fs.write_all(uuid_str.as_bytes())?;
        uuid_str
    };
    Ok(uuid)
}

pub async fn capture_remote_client(cap: &mut Capture, args: &Args) -> Result<()> {
    let pbo = PcapByteOrder::WiresharkDefault; // default
    let config = bincode::config::standard();
    let p_uuid = find_uuid()?;
    let mut client = Client::connect(&args.server_addr).await?;

    let pcapng = cap.gen_pcapng(pbo);
    for block in pcapng.blocks {
        // shb and idb
        client.send_block(block, &p_uuid, config).await?;
        update_captured_stat();
    }

    loop {
        let block = cap.next_with_pcapng().expect("client capture packet failed");
        client.send_block(block, &p_uuid, config).await?;
        update_captured_stat();
    }
}
