#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::anyhow;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use bitcode;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::net::SocketAddr;
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
use crate::CliArgs;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::split::SplitRule;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
pub static SERVRE_TOTAL_RECVED: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
async fn recv_packets(
    socket: &mut TcpStream,
    args: &CliArgs,
    pbo: PcapByteOrder,
    addr: SocketAddr,
) -> Result<usize> {
    let mut split_rule = SplitRule::init(args, pbo, Some(addr))?;
    let mut thread_total_recved = 0;

    loop {
        let pcapng_t_len = match socket.read_u32().await {
            Ok(t) => t,
            Err(_e) => {
                // client disconnected
                return Ok(thread_total_recved);
            }
        };
        let mut buff = vec![0u8; pcapng_t_len as usize];
        match socket.read_exact(&mut buff).await {
            Ok(_) => (),
            Err(_e) => {
                // client disconnected
                return Ok(thread_total_recved);
            }
        }
        let block: GeneralBlock = bitcode::decode(&buff)?;
        match block {
            GeneralBlock::SectionHeaderBlock(shb) => split_rule.update_shb(shb),
            GeneralBlock::InterfaceDescriptionBlock(idb) => split_rule.update_idb(idb),
            GeneralBlock::EnhancedPacketBlock(epb) => split_rule.append(epb)?,
            _ => (),
        }

        SERVRE_TOTAL_RECVED.fetch_add(1, SeqCst);
        thread_total_recved += 1;
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
struct Server {
    listener: TcpListener,
    server_passwd: String,
    args: CliArgs,
    pbo: PcapByteOrder,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl Server {
    async fn init(args: &CliArgs, pbo: PcapByteOrder) -> Result<Server> {
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
            let (mut stream, addr) = self.listener.accept().await?;
            if self.auth(&mut stream).await? {
                // the default format is pcapng
                let args = self.args.clone();
                let pbo = self.pbo;
                tokio::spawn(async move {
                    match recv_packets(&mut stream, &args, pbo, addr).await {
                        Ok(total_recved) => println!(
                            "client {} disconnected, total recved: {}",
                            addr, total_recved
                        ),
                        Err(e) => {
                            // client process packet error
                            eprintln!("recv pcapng from {} failed: {}", addr, e)
                        }
                    }
                });
            }
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
pub async fn capture_remote_server(args: CliArgs) -> Result<()> {
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
