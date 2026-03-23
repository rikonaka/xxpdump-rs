#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::anyhow;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use bitcode;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::EnhancedPacketBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::InterfaceDescriptionBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::InterfaceStatisticsBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::NameResolutionBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::SectionHeaderBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::SimplePacketBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::sync::atomic::AtomicUsize;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::sync::atomic::Ordering::SeqCst;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::io::AsyncReadExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::io::AsyncWriteExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::net::TcpListener;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::net::TcpStream;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::Args;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::PcapNgTransport;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::PcapNgType;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::split::SplitRule;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
fn packet_process(split_rule: &mut SplitRule, pcapng_t: PcapNgTransport) -> Result<()> {
    match pcapng_t.p_type {
        PcapNgType::SectionHeaderBlock => {
            let shb: SectionHeaderBlock = bitcode::decode(&pcapng_t.p_data)?;
            split_rule.update_shb(shb.clone());

            let block = GeneralBlock::SectionHeaderBlock(shb);
            split_rule.append(block)?;
        }
        PcapNgType::InterfaceDescriptionBlock => {
            let idb: InterfaceDescriptionBlock = bitcode::decode(&pcapng_t.p_data)?;
            split_rule.update_idb(idb.clone());

            let block = GeneralBlock::InterfaceDescriptionBlock(idb);
            split_rule.append(block)?;
        }
        PcapNgType::EnhancedPacketBlock => {
            let epb: EnhancedPacketBlock = bitcode::decode(&pcapng_t.p_data)?;
            let block = GeneralBlock::EnhancedPacketBlock(epb);
            split_rule.append(block)?;
        }
        PcapNgType::SimplePacketBlock => {
            let spb: SimplePacketBlock = bitcode::decode(&pcapng_t.p_data)?;
            let block = GeneralBlock::SimplePacketBlock(spb);
            split_rule.append(block)?;
        }
        PcapNgType::InterfaceStatisticsBlock => {
            let isb: InterfaceStatisticsBlock = bitcode::decode(&pcapng_t.p_data)?;
            let block = GeneralBlock::InterfaceStatisticsBlock(isb);
            split_rule.append(block)?;
        }
        PcapNgType::NameResolutionBlock => {
            let nrb: NameResolutionBlock = bitcode::decode(&pcapng_t.p_data)?;
            let block = GeneralBlock::NameResolutionBlock(nrb);
            split_rule.append(block)?;
        }
    }
    Ok(())
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
pub static SERVRE_TOTAL_RECVED: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
async fn recv_packets(socket: &mut TcpStream, args: &Args, pbo: PcapByteOrder) -> Result<()> {
    let mut split_rule = SplitRule::init(args, pbo)?;

    loop {
        let pcapng_t_len = socket.read_u32().await?;
        println!("recv a block from client, length: {}", pcapng_t_len);
        let mut buff = vec![0u8; pcapng_t_len as usize];
        socket.read_exact(&mut buff).await?;
        println!(
            "data: {}",
            buff.iter()
                .map(|x| format!("{:02x}", x))
                .collect::<Vec<String>>()
                .join("")
        );
        println!("recv block data from client, start to decode...");
        let pcapng_t: PcapNgTransport = bitcode::decode(&buff)?;
        println!("decode block data from client, start to process...");

        packet_process(&mut split_rule, pcapng_t)?;
        SERVRE_TOTAL_RECVED.fetch_add(1, SeqCst);

        println!("recv and process a block from client successfully");
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
struct Server {
    listener: TcpListener,
    server_passwd: String,
    args: Args,
    pbo: PcapByteOrder,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl Server {
    async fn init(args: &Args, pbo: PcapByteOrder) -> Result<Server> {
        let addr = &args.server_addr;
        let listener = TcpListener::bind(addr).await?;
        let server_passwd = args.server_passwd.to_string();
        Ok(Server {
            listener,
            server_passwd: server_passwd.to_string(),
            args: args.clone(),
            pbo,
        })
    }

    /// very simple server auth
    async fn auth(&self, socket: &mut TcpStream) -> Result<bool> {
        let recv_len = socket.read_u32().await?;

        let mut buff = vec![0u8; recv_len as usize];
        let _passwd_len = socket.read_exact(&mut buff).await?;

        let cliend_send_passwd = String::from_utf8_lossy(&buff).to_string();
        if cliend_send_passwd == self.server_passwd {
            let auth_success_ret = "ok";
            let auth_success_ret_vec = auth_success_ret.as_bytes();
            socket.write_u32(auth_success_ret_vec.len() as u32).await?;
            socket.write_all(auth_success_ret_vec).await?;
            Ok(true)
        } else {
            let auth_failed_ret = "failed";
            let auth_failed_ret_vec = auth_failed_ret.as_bytes();
            socket.write_u32(auth_failed_ret_vec.len() as u32).await?;
            socket.write_all(auth_failed_ret_vec).await?;
            Ok(false)
        }
    }
    async fn run(&mut self) -> Result<()> {
        loop {
            let (mut stream, _addr) = self.listener.accept().await?;
            if self.auth(&mut stream).await? {
                // the default format is pcapng
                let args = self.args.clone();
                let pbo = self.pbo;
                tokio::spawn(async move {
                    match recv_packets(&mut stream, &args, pbo).await {
                        Ok(_) => (),
                        Err(e) => {
                            // ignore the error and keep running
                            eprintln!("recv pcapng from failed: {}", e)
                        }
                    }
                });
            }
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
pub async fn capture_remote_server(args: Args) -> Result<()> {
    println!("listening at {}", &args.server_addr);
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut server = Server::init(&args, pbo).await?;

    match server.run().await {
        Ok(_) => (),
        Err(e) => return Err(anyhow!("server run failed: {}", e)),
    }

    Ok(())
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[cfg(test)]
mod test {
    use std::fs::File;
    #[test]
    fn empty_file() {
        let _ = File::create("test.bin").unwrap();
    }
}
