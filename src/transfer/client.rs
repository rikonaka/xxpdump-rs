#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use bitcode;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::Capture;
#[cfg(feature = "libpcap")]
use pcapture::Device;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::sync::atomic::AtomicUsize;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::sync::atomic::Ordering::SeqCst;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::io::AsyncReadExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::io::AsyncWriteExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::net::TcpStream;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::CliArgs;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
pub static CLIENT_TOTAL_SEND: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
struct Client {
    stream: TcpStream,
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
impl Client {
    /// Connecting to a remote backup server.
    async fn connect(addr: &str) -> Result<Client> {
        let stream = TcpStream::connect(&addr).await?;
        Ok(Client { stream })
    }

    /// Client only send data not recv.
    pub async fn send_block(&mut self, block: GeneralBlock) -> Result<()> {
        let send_data = bitcode::encode(&block);
        let send_data_len = send_data.len() as u32;
        // big endian length on internet
        let send_data_len = send_data_len.to_be_bytes();

        // first send 4 bytes length
        match self.stream.write_all(&send_data_len).await {
            Ok(_) => (),
            Err(e) => {
                // server shutdown or network error
                eprintln!("failed to send data length to server: {}", e);
                return Ok(());
            }
        };
        // second send the data
        match self.stream.write_all(&send_data).await {
            Ok(_) => (),
            Err(e) => {
                // server shutdown or network error
                eprintln!("failed to send data to server: {}", e);
                return Ok(());
            }
        }

        CLIENT_TOTAL_SEND.fetch_add(1, SeqCst);
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
        let mut buff = vec![0u8; server_resp_len as usize];
        let _server_auth_response_len = self.stream.read_exact(&mut buff).await?;

        let server_resp_str = String::from_utf8_lossy(&buff).to_string();
        if server_resp_str == "ok" {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(feature = "libpnet")]
pub async fn capture_remote_client(args: CliArgs) -> Result<()> {
    let mut cap = match Capture::new(&args.interface) {
        Ok(c) => c,
        Err(e) => panic!("init the Capture failed: {}", e),
    };

    cap.set_promiscuous(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen);
    cap.set_timeout(args.timeout);

    let ignore_self_traffc_filter = if args.ignore_self_traffic {
        let server_addr_split: Vec<&str> = args.server_addr.split(":").collect();
        if server_addr_split.len() >= 2 {
            let server_addr = server_addr_split[0];
            let server_port = server_addr_split[1];
            let filter = format!("not (host {} and port {})", server_addr, server_port);
            Some(filter)
        } else {
            eprintln!(
                "invalid server address: {} (example: 192.168.5.78:12345)",
                args.server_addr
            );
            return Ok(());
        }
    } else {
        None
    };

    match args.filter {
        Some(fu) => {
            let filter = match ignore_self_traffc_filter {
                Some(istf) => {
                    let new_filter = format!("{} and ({})", istf, fu);
                    new_filter
                }
                None => fu,
            };
            cap.set_filter(&filter)?;
        }
        None => {}
    }

    let pbo = PcapByteOrder::WiresharkDefault; // default
    let mut client = Client::connect(&args.server_addr).await?;
    if client.auth(&args.server_passwd).await? {
        let pcapng = cap.gen_pcapng_header(pbo)?;
        for block in pcapng.blocks {
            // shb and idb
            client.send_block(block).await?;
        }

        loop {
            match cap.next_as_pcapng() {
                Ok(block) => {
                    client.send_block(block).await?;
                }
                Err(e) => eprintln!("{}", e),
            }
        }
    } else {
        eprintln!("password is wrong");
        Ok(())
    }
}

#[cfg(feature = "libpcap")]
pub async fn capture_remote_client(args: CliArgs) -> Result<()> {
    let devices = Device::list()?;
    let device = devices.iter().find(|&d| d.name == args.interface);
    let device = match device {
        Some(d) => d,
        None => {
            eprintln!("cannot find the interface: {}", args.interface);
            return Ok(());
        }
    };

    let mut cap = Capture::new(&device.name)?;

    cap.set_promiscuous_mode(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen);
    cap.set_immediate_mode(args.immediate);
    cap.set_timeout((args.timeout * 1000.0) as i32);

    let ignore_self_traffc_filter = if args.ignore_self_traffic {
        let server_addr_split: Vec<&str> = args.server_addr.split(":").collect();
        if server_addr_split.len() >= 2 {
            let server_addr = server_addr_split[0];
            let server_port = server_addr_split[1];
            let filter = format!("not (host {} and port {})", server_addr, server_port);
            Some(filter)
        } else {
            eprintln!(
                "invalid server address: {} (example: 192.168.5.78:12345)",
                args.server_addr
            );
            return Ok(());
        }
    } else {
        None
    };

    match args.filter {
        Some(fu) => {
            let filter = match ignore_self_traffc_filter {
                Some(istf) => {
                    let new_filter = format!("{} and ({})", istf, fu);
                    new_filter
                }
                None => fu,
            };
            cap.set_filter(&filter);
        }
        None => {}
    }

    let mut client = Client::connect(&args.server_addr).await?;

    if client.auth(&args.server_passwd).await? {
        let pbo = PcapByteOrder::WiresharkDefault;
        let pcapng = cap.gen_pcapng_header(pbo)?;
        for block in pcapng.blocks {
            // shb and idb
            client.send_block(block).await?;
        }

        loop {
            match cap.fetch_as_pcapng() {
                Ok(blocks) => {
                    for block in blocks {
                        client.send_block(block).await?;
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }
    } else {
        eprintln!("password is wrong");
        Ok(())
    }
}
