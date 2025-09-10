use anyhow::Result;
use bincode::config;
use pcapture::PcapByteOrder;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Args;
use crate::PACKETS_SERVER_RECVED;
use crate::PcapNgTransport;
use crate::split_rule::SplitRule;
use crate::update_server_recved_stat;

struct Server {
    listener: TcpListener,
    split_rule: SplitRule,
    server_passwd: String,
}

impl Server {
    async fn init(addr: &str, split_rule: SplitRule, server_passwd: &str) -> Result<Server> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Server {
            listener,
            split_rule,
            server_passwd: server_passwd.to_string(),
        })
    }
    async fn recv_pcapng(socket: &mut TcpStream, split_rule: SplitRule) -> Result<()> {
        let mut uuid = String::new();

        let get_server_recved = || -> usize {
            let packets_server_recved: usize = match PACKETS_SERVER_RECVED.lock() {
                Ok(p) => *p,
                Err(e) => panic!("try to lock the PACKETS_SERVER_RECVED failed: {}", e),
            };
            packets_server_recved
        };

        loop {
            let recv_len = match socket.read_u32().await {
                Ok(l) => l,
                Err(e) => {
                    let recved = get_server_recved();
                    error!(
                        " total recved [{}], read step1 data len failed [{}]: {}",
                        recved, &uuid, e
                    );
                    return Ok(());
                }
            };

            let mut buf = vec![0u8; recv_len as usize];
            match socket.read_exact(&mut buf).await {
                Ok(_) => (),
                Err(e) => {
                    let recved = get_server_recved();
                    error!(
                        " total recved [{}], read step2 data failed [{}]: {}",
                        recved, &uuid, e
                    );
                    return Ok(());
                }
            };

            let split_rule = self.split_rule;
            let decode: (PcapNgTransport, usize) = bincode::decode_from_slice(&buf, config)?;
            let (pcapng_t, decode_len) = decode;
            if decode_len == recv_len as usize {
                // it should equal
                if writer.client_uuid.len() == 0 {
                    writer.update_client_uuid(&pcapng_t.p_uuid)?;
                }
                writer.write(&pcapng_t, pbo, config)?;
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

            if self.auth(&mut socket).await? {
                // the default format is pcapng
                tokio::spawn(async move {
                    match Self::recv_pcapng(&mut socket).await {
                        Ok(_) => (),
                        Err(e) => error!("recv pcapng from failed: {}", e), // ignore the error and keep running
                    }
                });
            }
        }
    }
    /// very simple server auth.
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
}

pub async fn capture_remote_server(args: &Args) -> Result<()> {
    info!("listening at {}", args.server_addr);
    let pbo = PcapByteOrder::WiresharkDefault; // default
    let config = config::standard();
    let split_rule = SplitRule::init(args, pbo, config);
    let mut server = Server::init(&args.server_addr, split_rule, &args.server_passwd).await?;
    server.recv_block_loop().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use uuid::Uuid;
    #[test]
    fn uuid_gen() {
        let uuid = Uuid::new_v4();
        // aa3293ec-5cec-4984-aa19-56d462bdc0eb
        // dc5b475b-5e68-4401-b824-d27d90f45755
        println!("{}", uuid);
    }
    #[test]
    fn empty_file() {
        let _ = File::create("test.bin").unwrap();
    }
}
