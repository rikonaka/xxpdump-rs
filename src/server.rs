use anyhow::Result;
use bincode::config;
use bincode::config::Configuration;
use pcapture::PcapByteOrder;
use pcapture::pcapng::EnhancedPacketBlock;
use pcapture::pcapng::GeneralBlock;
use pcapture::pcapng::InterfaceDescriptionBlock;
use pcapture::pcapng::InterfaceStatisticsBlock;
use pcapture::pcapng::NameResolutionBlock;
use pcapture::pcapng::SectionHeaderBlock;
use pcapture::pcapng::SimplePacketBlock;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::error;
use tracing::info;

use crate::Args;
use crate::PACKETS_SERVER_TOTAL_RECVED;
use crate::PcapNgTransport;
use crate::PcapNgType;
use crate::split::SplitRule;
use crate::update_captured_stat;
use crate::update_server_recved_stat;

fn get_server_total_recved() -> usize {
    let packets_server_recved = match PACKETS_SERVER_TOTAL_RECVED.lock() {
        Ok(p) => *p,
        Err(e) => panic!("try to lock the PACKETS_SERVER_TOTAL_RECVED failed: {}", e),
    };
    packets_server_recved
}

static SERVER_PIPE: LazyLock<Arc<Mutex<VecDeque<PcapNgTransport>>>> = LazyLock::new(|| {
    let v = VecDeque::new();
    Arc::new(Mutex::new(v))
});

struct ServerPipe;

impl ServerPipe {
    fn push(pcapng_t: PcapNgTransport) {
        match SERVER_PIPE.lock() {
            Ok(mut pipe) => pipe.push_back(pcapng_t),
            Err(e) => panic!("try to lock the SERVER_PIPE failed: {}", e),
        }
    }
    fn pop() -> Option<PcapNgTransport> {
        match SERVER_PIPE.lock() {
            Ok(mut pipe) => pipe.pop_front(),
            Err(e) => panic!("try to lock the SERVER_PIPE failed: {}", e),
        }
    }
    fn start(&self, args: &Args, config: Configuration, pbo: PcapByteOrder) {
        let mut split_rule = SplitRule::init(args).expect("init SplitRule failed");

        loop {
            match Self::pop() {
                Some(pcapng_t) => {
                    update_captured_stat();
                    match pcapng_t.p_type {
                        PcapNgType::SectionHeaderBlock => {
                            let decode: (SectionHeaderBlock, usize) =
                                bincode::decode_from_slice(&pcapng_t.p_data, config)
                                    .expect("decode shb failed");
                            let (shb, _) = decode;
                            split_rule.update_shb(shb.clone());

                            let block = GeneralBlock::SectionHeaderBlock(shb);
                            split_rule.write(block, pbo).expect("write shb failed");
                        }
                        PcapNgType::InterfaceDescriptionBlock => {
                            let decode: (InterfaceDescriptionBlock, usize) =
                                bincode::decode_from_slice(&pcapng_t.p_data, config)
                                    .expect("decode idb failed");
                            let (idb, _) = decode;
                            split_rule.update_idb(idb.clone());

                            let block = GeneralBlock::InterfaceDescriptionBlock(idb);
                            split_rule.write(block, pbo).expect("write idb failed");
                        }
                        PcapNgType::EnhancedPacketBlock => {
                            let decode: (EnhancedPacketBlock, usize) =
                                bincode::decode_from_slice(&pcapng_t.p_data, config)
                                    .expect("decode epb failed");
                            let (epb, _) = decode;
                            let block = GeneralBlock::EnhancedPacketBlock(epb);
                            split_rule.write(block, pbo).expect("write epb failed");
                        }
                        PcapNgType::SimplePacketBlock => {
                            let decode: (SimplePacketBlock, usize) =
                                bincode::decode_from_slice(&pcapng_t.p_data, config)
                                    .expect("decode spb failed");
                            let (spb, _) = decode;
                            let block = GeneralBlock::SimplePacketBlock(spb);
                            split_rule.write(block, pbo).expect("write spb failed");
                        }
                        PcapNgType::InterfaceStatisticsBlock => {
                            let decode: (InterfaceStatisticsBlock, usize) =
                                bincode::decode_from_slice(&pcapng_t.p_data, config)
                                    .expect("decode isb failed");
                            let (isb, _) = decode;
                            let block = GeneralBlock::InterfaceStatisticsBlock(isb);
                            split_rule.write(block, pbo).expect("write isb failed");
                        }
                        PcapNgType::NameResolutionBlock => {
                            let decode: (NameResolutionBlock, usize) =
                                bincode::decode_from_slice(&pcapng_t.p_data, config)
                                    .expect("decode nrb failed");
                            let (nrb, _) = decode;
                            let block = GeneralBlock::NameResolutionBlock(nrb);
                            split_rule.write(block, pbo).expect("write irb failed");
                        }
                    }
                }
                None => (),
            }
        }
    }
}

struct Server {
    listener: TcpListener,
    server_passwd: String,
}

impl Server {
    async fn init(addr: &str, server_passwd: &str) -> Result<Server> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Server {
            listener,
            server_passwd: server_passwd.to_string(),
        })
    }
    async fn recv(socket: &mut TcpStream) -> Result<()> {
        let config = config::standard();
        loop {
            let pcapng_t_len = socket.read_u32().await?;
            let mut buf = vec![0u8; pcapng_t_len as usize];
            socket.read_exact(&mut buf).await?;
            let decode: (PcapNgTransport, usize) = bincode::decode_from_slice(&buf, config)?;

            let (pcapng_t, decode_len) = decode;
            if decode_len == pcapng_t_len as usize {
                // it should equal
                ServerPipe::push(pcapng_t);
                update_server_recved_stat();
            } else {
                error!(
                    "decode_len[{}] != recv_len[{}], ignore this data",
                    decode_len, pcapng_t_len
                );
            }
        }
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
                tokio::spawn(async move {
                    match Server::recv(&mut stream).await {
                        Ok(_) => (),
                        Err(e) => {
                            let server_total_recved = get_server_total_recved();
                            // ignore the error and keep running
                            error!(
                                "recv pcapng from failed: {}, total recv packet size: {}",
                                e, server_total_recved
                            );
                        }
                    }
                });
            }
        }
    }
}

pub async fn capture_remote_server(args: Args) -> Result<()> {
    info!("listening at {}", args.server_addr);
    let server_pip = ServerPipe;
    let mut server = Server::init(&args.server_addr, &args.server_passwd).await?;

    let config = config::standard();
    let pbo = PcapByteOrder::WiresharkDefault;
    tokio::spawn(async move { server_pip.start(&args, config, pbo) });

    match server.run().await {
        Ok(_) => (),
        Err(e) => error!("server run failed: {}", e),
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use std::fs::File;
    #[test]
    fn empty_file() {
        let _ = File::create("test.bin").unwrap();
    }
}
