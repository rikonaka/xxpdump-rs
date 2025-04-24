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
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::error;
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
    /// Very simple auth function.
    async fn auth(&mut self, password: &str) -> Result<bool> {
        let password_vec = password.as_bytes();
        let password_vec_len = password_vec.len() as u32;
        let password_vec_len_encode = password_vec_len.to_be_bytes(); // BigEndian on internet

        // first send 4 bytes length
        self.stream.write_all(&password_vec_len_encode).await?;
        // second send the data
        self.stream.write_all(&password_vec).await?;

        // wait server send auth result
        let server_resp_len = self.stream.read_u32().await?;
        let mut buf = vec![0u8; server_resp_len as usize];
        let _ = self.stream.read_exact(&mut buf).await?;

        let server_resp_str = String::from_utf8_lossy(&buf).to_string();
        if server_resp_str == "ok" {
            Ok(true)
        } else {
            Ok(false)
        }
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

    if client.auth(&args.server_passwd).await? {
        let pcapng = cap.gen_pcapng(pbo);
        for block in pcapng.blocks {
            // shb and idb
            client.send_block(block, &p_uuid, config).await?;
            update_captured_stat();
        }

        loop {
            let block = cap
                .next_with_pcapng()
                .expect("client capture packet failed");
            client.send_block(block, &p_uuid, config).await?;
            update_captured_stat();
        }
    } else {
        error!("password is wrong");
        Ok(())
    }
}
