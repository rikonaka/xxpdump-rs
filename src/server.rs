#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::anyhow;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use bincode::config;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use bincode::config::Configuration;
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
use tokio::io::AsyncReadExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::io::AsyncWriteExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::net::TcpListener;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::net::TcpStream;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tracing::error;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tracing::info;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::Args;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::PACKETS_SERVER_TOTAL_RECVED;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::PcapNgTransport;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::PcapNgType;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::split::SplitRule;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::update_captured_packets_num;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::update_server_recved_stat;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
fn get_server_total_recved() -> usize {
    let packets_server_recved = match PACKETS_SERVER_TOTAL_RECVED.lock() {
        Ok(p) => *p,
        Err(e) => panic!("try to lock the PACKETS_SERVER_TOTAL_RECVED failed: {}", e),
    };
    packets_server_recved
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
fn packet_process(
    split_rule: &mut SplitRule,
    config: Configuration,
    pcapng_t: PcapNgTransport,
) -> Result<()> {
    update_captured_packets_num(1);
    match pcapng_t.p_type {
        PcapNgType::SectionHeaderBlock => {
            let decode: (SectionHeaderBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (shb, _) = decode;
            split_rule.update_shb(shb.clone());

            let block = GeneralBlock::SectionHeaderBlock(shb);
            split_rule.append(block)?;
        }
        PcapNgType::InterfaceDescriptionBlock => {
            let decode: (InterfaceDescriptionBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (idb, _) = decode;
            split_rule.update_idb(idb.clone());

            let block = GeneralBlock::InterfaceDescriptionBlock(idb);
            split_rule.append(block)?;
        }
        PcapNgType::EnhancedPacketBlock => {
            let decode: (EnhancedPacketBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (epb, _) = decode;
            let block = GeneralBlock::EnhancedPacketBlock(epb);
            split_rule.append(block)?;
        }
        PcapNgType::SimplePacketBlock => {
            let decode: (SimplePacketBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (spb, _) = decode;
            let block = GeneralBlock::SimplePacketBlock(spb);
            split_rule.append(block)?;
        }
        PcapNgType::InterfaceStatisticsBlock => {
            let decode: (InterfaceStatisticsBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (isb, _) = decode;
            let block = GeneralBlock::InterfaceStatisticsBlock(isb);
            split_rule.append(block)?;
        }
        PcapNgType::NameResolutionBlock => {
            let decode: (NameResolutionBlock, usize) =
                bincode::decode_from_slice(&pcapng_t.p_data, config)?;
            let (nrb, _) = decode;
            let block = GeneralBlock::NameResolutionBlock(nrb);
            split_rule.append(block)?;
        }
    }
    Ok(())
}

async fn recv_packets(socket: &mut TcpStream, args: &Args, pbo: PcapByteOrder) -> Result<()> {
    let config = config::standard();
    let mut split_rule = SplitRule::init(args, pbo)?;

    loop {
        let pcapng_t_len = socket.read_u32().await?;
        let mut buf = vec![0u8; pcapng_t_len as usize];
        socket.read_exact(&mut buf).await?;
        let decode: (PcapNgTransport, usize) = bincode::decode_from_slice(&buf, config)?;

        let (pcapng_t, decode_len) = decode;
        if decode_len == pcapng_t_len as usize {
            // it should equal
            packet_process(&mut split_rule, config, pcapng_t)?;
            update_server_recved_stat();
        } else {
            error!(
                "decode_len[{}] != recv_len[{}], ignore this data",
                decode_len, pcapng_t_len
            );
        }
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

        let mut buf = vec![0u8; recv_len as usize];
        let _ = socket.read_exact(&mut buf).await?;

        let cliend_send_passwd = String::from_utf8_lossy(&buf).to_string();
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
                            let server_total_recved = get_server_total_recved();
                            // ignore the error and keep running
                            error!(
                                "recv pcapng from failed: {}, total recv packet size: {}",
                                e, server_total_recved
                            )
                        }
                    }
                });
            }
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
pub async fn capture_remote_server(args: Args) -> Result<()> {
    info!("listening at {}", &args.server_addr);
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
