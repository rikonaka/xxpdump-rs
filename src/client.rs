use anyhow::Result;
use bincode;
use bincode::config::Configuration;
#[cfg(feature = "libpcap")]
use pcap::Capture;
#[cfg(feature = "libpcap")]
use pcap::Device;
#[cfg(feature = "libpnet")]
use pcapture::Capture;
#[cfg(feature = "libpnet")]
use pcapture::PcapByteOrder;
#[cfg(feature = "libpcap")]
use pcapture::filter::Filters;
#[cfg(feature = "libpcap")]
use pcapture::pcapng::EnhancedPacketBlock;
use pcapture::pcapng::GeneralBlock;
#[cfg(feature = "libpcap")]
use pcapture::pcapng::PcapNg;
#[cfg(feature = "libpcap")]
use pnet::ipnetwork::IpNetwork;
#[cfg(feature = "libpcap")]
use subnetwork::NetmaskExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::error;
use tracing::warn;

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
    pub async fn send_block(&mut self, block: GeneralBlock, config: Configuration) -> Result<()> {
        async fn send_with_pcapng_transport(
            stream: &mut TcpStream,
            pcapng_t: PcapNgTransport,
            config: Configuration,
        ) -> Result<()> {
            let encode_1 = bincode::encode_to_vec(pcapng_t, config)?;
            let encode_len = encode_1.len() as u32;
            let encode_2 = encode_len.to_be_bytes(); // BigEndian on internet

            // first send 4 bytes length
            stream.write_all(&encode_2).await?;
            // second send the data
            stream.write_all(&encode_1).await?;
            Ok(())
        }

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
        let pcapng_t = PcapNgTransport { p_type, p_data };
        send_with_pcapng_transport(&mut self.stream, pcapng_t, config).await?;
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
        let filter = format!("ip!={} and port!={}", server_addr, server_port);
        filter
    } else {
        String::new()
    };

    let mut cap = match Capture::new(&args.interface, Some(filter)) {
        Ok(c) => c,
        Err(e) => panic!("init the Capture failed: {}", e),
    };
    cap.promiscuous(args.promisc);
    cap.buffer_size(args.buffer_size);
    cap.snaplen(args.snaplen);
    cap.timeout(args.timeout);

    let pbo = PcapByteOrder::WiresharkDefault; // default
    let config = bincode::config::standard();
    let mut client = Client::connect(&args.server_addr).await?;

    if client.auth(&args.server_passwd).await? {
        let pcapng = cap.gen_pcapng(pbo)?;
        for block in pcapng.blocks {
            // shb and idb
            client.send_block(block, config).await?;
            update_captured_stat();
        }

        loop {
            match cap.next_as_pcapng() {
                Ok(block) => {
                    client.send_block(block, config).await?;
                    update_captured_stat();
                }
                Err(e) => warn!("{}", e),
            }
        }
    } else {
        error!("password is wrong");
        Ok(())
    }
}

#[cfg(feature = "libpcap")]
pub async fn capture_remote_client(args: Args) -> Result<()> {
    let devices = Device::list().expect("can not get device from libpcap");
    let device = devices
        .iter()
        .find(|&d| d.name == args.interface)
        .expect("can not found interface");

    let cap = Capture::from_device(device.clone()).expect("init the Capture failed");
    let mut cap = cap
        .promisc(args.promisc)
        .buffer_size(args.buffer_size as i32)
        .snaplen(args.snaplen as i32)
        .timeout((args.timeout * 1000) as i32)
        .open()
        .expect("can not open libpcap capture");

    let config = bincode::config::standard();
    let mut client = Client::connect(&args.server_addr).await?;

    let filters = match &args.filter {
        Some(filter) => Filters::parser(filter).expect("parser filter failed"),
        None => None,
    };

    if client.auth(&args.server_passwd).await? {
        let if_name = &device.name;
        let if_description = match &device.desc {
            Some(d) => d.clone(),
            None => String::new(),
        };

        let mut ips = Vec::new();
        for address in &device.addresses {
            let addr = address.addr;
            let netmask = address.netmask;
            let prefix = match netmask {
                Some(addr) => {
                    let netmask_ext = NetmaskExt::from_addr(addr);
                    netmask_ext.get_prefix()
                }
                None => 0,
            };
            let ipn = IpNetwork::new(addr, prefix).expect("create IpNetwork failed");
            ips.push(ipn);
        }
        let mac = None;
        let pcapng = PcapNg::new_raw(if_name, &if_description, &ips, mac);

        for block in pcapng.blocks {
            // shb and idb
            client.send_block(block, config).await?;
            update_captured_stat();
        }

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let packet_data = packet.data;
                    match filters.as_ref() {
                        Some(fls) => {
                            if fls.check(packet_data).expect("filter check failed") {
                                let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                                    .expect("create enhanced packet block failed");
                                let block = GeneralBlock::EnhancedPacketBlock(eb);
                                client.send_block(block, config).await?;
                                update_captured_stat();
                            }
                        }
                        None => {
                            let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                                .expect("create enhanced packet block failed");
                            let block = GeneralBlock::EnhancedPacketBlock(eb);
                            client.send_block(block, config).await?;
                            update_captured_stat();
                        }
                    }
                }
                Err(e) => warn!("{}", e),
            }
        }
    } else {
        error!("password is wrong");
        Ok(())
    }
}
