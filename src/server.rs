use anyhow::Result;
use bincode::config;
use pcapture::PcapByteOrder;
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
use crate::PcapNgTransport;
use crate::split_rule::SplitRule;
use crate::update_server_recved_stat;

static PACKETS_SERVER_TOTAL_RECVED: LazyLock<Arc<Mutex<usize>>> =
    LazyLock::new(|| Arc::new(Mutex::new(0)));

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

struct ServerPipe {
    split_rule: SplitRule,
}

impl ServerPipe {
    fn server_pipe_push(pcapng_t: PcapNgTransport) {
        match SERVER_PIPE.lock() {
            Ok(mut pipe) => pipe.push_back(pcapng_t),
            Err(e) => panic!("try to lock the SERVER_PIPE failed: {}", e),
        }
    }
    fn server_pipe_pop() -> Option<PcapNgTransport> {
        match SERVER_PIPE.lock() {
            Ok(mut pipe) => pipe.pop_front(),
            Err(e) => panic!("try to lock the SERVER_PIPE failed: {}", e),
        }
    }
    fn server_writer_thread(&self) {
        let split_rule = self.split_rule;
        loop {
            match Self::server_pipe_pop() {
                Some(t) => (),
                None => (),
            }
        }
    }
}

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
    async fn recv_pcapng_t(&mut self, socket: &mut TcpStream, split_rule: SplitRule) -> Result<()> {
        let mut uuid = String::new();
        let config = config::standard();

        loop {
            let pcapng_t_len = socket.read_u32().await?;
            let mut buf = vec![0u8; pcapng_t_len as usize];
            socket.read_exact(&mut buf).await?;
            let decode: (PcapNgTransport, usize) = bincode::decode_from_slice(&buf, config)?;

            let (pcapng_t, decode_len) = decode;
            if decode_len == pcapng_t_len as usize {
                // it should equal
                if writer.client_uuid.len() == 0 {
                    writer.update_client_uuid(&pcapng_t.p_uuid)?;
                }
                writer.write(&pcapng_t, pbo, config)?;
                update_server_recved_stat();
                uuid = pcapng_t.p_uuid;
            } else {
                error!(
                    "decode_len[{}] != recv_len[{}], ignore this data",
                    decode_len, pcapng_t_len
                );
            }
        }
    }
    async fn run(&mut self) -> Result<()> {
        loop {
            let (mut stream, _addr) = self.listener.accept().await?;
            if self.auth(&mut stream).await? {
                // the default format is pcapng
                tokio::spawn(async move {
                    match self.recv_pcapng_t(&mut stream).await {
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

pub async fn capture_remote_server(args: &Args) -> Result<()> {
    info!("listening at {}", args.server_addr);
    let pbo = PcapByteOrder::WiresharkDefault; // default
    let config = config::standard();
    let split_rule = SplitRule::init(args, pbo, config);
    let mut server = Server::init(&args.server_addr, split_rule, &args.server_passwd).await?;
    match server.run().await {
        Ok(_) => (),
        Err(e) => error!("server run failed: {}", e),
    }
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
