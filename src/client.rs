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
use std::sync::atomic::Ordering;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::io::AsyncReadExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::io::AsyncWriteExt;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tokio::net::TcpStream;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::Args;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::PcapNgTransport;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::PcapNgType;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::SHOULD_EXIT;

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
        async fn send_with_pcapng_transport(
            stream: &mut TcpStream,
            pcapng_t: PcapNgTransport,
        ) -> Result<()> {
            let encode_1 = bitcode::encode(&pcapng_t);
            let encode_len = encode_1.len() as u32;
            let encode_2 = encode_len.to_be_bytes(); // BigEndian on internet

            // first send 4 bytes length
            stream.write_all(&encode_2).await?;
            // second send the data
            stream.write_all(&encode_1).await?;
            Ok(())
        }

        let (p_type, p_data) = match block {
            GeneralBlock::SectionHeaderBlock(shb) => {
                (PcapNgType::SectionHeaderBlock, bitcode::encode(&shb))
            }
            GeneralBlock::InterfaceDescriptionBlock(idb) => {
                (PcapNgType::InterfaceDescriptionBlock, bitcode::encode(&idb))
            }
            GeneralBlock::EnhancedPacketBlock(epb) => {
                (PcapNgType::EnhancedPacketBlock, bitcode::encode(&epb))
            }
            GeneralBlock::SimplePacketBlock(spb) => {
                (PcapNgType::SimplePacketBlock, bitcode::encode(&spb))
            }
            GeneralBlock::InterfaceStatisticsBlock(isb) => {
                (PcapNgType::InterfaceStatisticsBlock, bitcode::encode(&isb))
            }
            GeneralBlock::NameResolutionBlock(nrb) => {
                (PcapNgType::NameResolutionBlock, bitcode::encode(&nrb))
            }
        };
        let pcapng_t = PcapNgTransport { p_type, p_data };
        send_with_pcapng_transport(&mut self.stream, pcapng_t).await?;
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

#[cfg(feature = "libpnet")]
pub async fn capture_remote_client(args: Args) -> Result<()> {
    let filter = if args.ignore_self_traffic {
        let server_addr_split: Vec<&str> = args.server_addr.split(":").collect();
        let server_addr = server_addr_split[0];
        let server_port = server_addr_split[1];
        // ignore communication with the server
        let filter = format!("not host {} and not port {}", server_addr, server_port);
        filter
    } else {
        String::new()
    };

    let filter = if let Some(fu) = args.filter {
        format!("{} and ({})", filter, fu)
    } else {
        filter
    };

    let mut cap = match Capture::new(&args.interface) {
        Ok(c) => c,
        Err(e) => panic!("init the Capture failed: {}", e),
    };
    cap.set_promiscuous(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen);
    cap.set_timeout(args.timeout);
    cap.set_filter(&filter)?;

    let pbo = PcapByteOrder::WiresharkDefault; // default
    let mut client = Client::connect(&args.server_addr).await?;
    if client.auth(&args.server_passwd).await? {
        let pcapng = cap.gen_pcapng_header(pbo)?;
        for block in pcapng.blocks {
            // shb and idb
            client.send_block(block).await?;
        }

        let mut total_recved = 0;
        while !SHOULD_EXIT.load(Ordering::SeqCst) {
            match cap.next_as_pcapng() {
                Ok(block) => {
                    total_recved += 1;
                    client.send_block(block).await?;
                }
                Err(e) => eprintln!("{}", e),
            }
        }

        println!("total captured packet: {}", total_recved);
        Ok(())
    } else {
        eprintln!("password is wrong");
        Ok(())
    }
}

#[cfg(feature = "libpcap")]
pub async fn capture_remote_client(args: Args) -> Result<()> {
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

    let filter = if args.ignore_self_traffic {
        let server_addr_split: Vec<&str> = args.server_addr.split(":").collect();
        let server_addr = server_addr_split[0];
        let server_port = server_addr_split[1];
        // ignore communication with the server
        let filter = format!("not host {} and not port {}", server_addr, server_port);
        filter
    } else {
        String::new()
    };

    cap.set_promiscuous_mode(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen);
    cap.set_immediate_mode(args.immediate);
    cap.set_timeout((args.timeout * 1000.0) as i32);
    cap.set_filter(&filter);

    let mut client = Client::connect(&args.server_addr).await?;

    if client.auth(&args.server_passwd).await? {
        let pbo = PcapByteOrder::WiresharkDefault;
        let pcapng = cap.gen_pcapng_header(pbo)?;
        for block in pcapng.blocks {
            // shb and idb
            client.send_block(block).await?;
        }

        let mut total_recved = 0;
        while !SHOULD_EXIT.load(Ordering::SeqCst) {
            match cap.fetch_as_pcapng() {
                Ok(blocks) => {
                    total_recved += blocks.len();
                    for block in blocks {
                        client.send_block(block).await?;
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }

        println!("total captured packet: {}", total_recved);
        Ok(())
    } else {
        eprintln!("password is wrong");
        Ok(())
    }
}
