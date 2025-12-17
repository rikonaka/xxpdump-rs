use pcapture::Capture;
#[cfg(feature = "libpcap")]
use pcapture::Device;
use pcapture::PcapByteOrder;
#[cfg(feature = "libpnet")]
use pcapture::filter::Filters;
#[cfg(feature = "libpcap")]
use pcapture::fs::pcapng::EnhancedPacketBlock;
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(feature = "libpcap")]
use pcapture::fs::pcapng::PcapNg;
#[cfg(feature = "libpcap")]
use pnet::ipnetwork::IpNetwork;
#[cfg(feature = "libpcap")]
use subnetwork::NetmaskExt;
use tracing::debug;
use tracing::warn;

use crate::Args;
use crate::split::SplitRule;
use crate::update_captured_stat;

#[cfg(feature = "libpnet")]
pub fn capture_local(args: Args) {
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut cap = Capture::new(&args.interface).expect(&format!("init the capture failed: {}", e));
    cap.set_promiscuous(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen);
    cap.set_timeout(args.timeout);
    cap.set_filter(args.filter)?;

    debug!("open save file path");

    let mut split_rule = SplitRule::init(&args).expect("init SplitRule failed");
    let pcapng = cap
        .gen_pcapng_header(pbo)
        .expect("generate pcapng header failed");

    for block in pcapng.blocks {
        // write all blocks
        split_rule
            .write(block.clone(), pbo)
            .expect("write pcapng header failed");
        match block {
            GeneralBlock::SectionHeaderBlock(shb) => split_rule.update_shb(shb.clone()),
            GeneralBlock::InterfaceDescriptionBlock(idb) => split_rule.update_idb(idb.clone()),
            _ => (),
        }
    }

    loop {
        match cap.next_as_pcapng() {
            Ok(block) => {
                split_rule.write(block, pbo).expect("write block failed");
                update_captured_stat();
            }
            Err(e) => warn!("{}", e),
        }
    }
}

#[cfg(feature = "libpcap")]
pub fn capture_local(args: Args) {
    let pbo = PcapByteOrder::WiresharkDefault;

    let mut cap = Capture::new(&args.interface).expect("init capture failed: {}");
    cap.set_promiscuous(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen as i32);
    cap.set_timeout((args.timeout * 1000.0) as i32);
    if let Some(filter) = args.filter {
        cap.set_filter(&filter);
    }

    debug!("open save file path");

    let devices = Device::list().expect("get devices failed");
    let mut ips = Vec::new();
    for address in &devices {
        let addr = address.addresses;
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
    let mut split_rule = SplitRule::init(&args).expect("init SplitRule failed");

    for block in pcapng.blocks {
        // write all blocks
        split_rule
            .write(block.clone(), pbo)
            .expect("write pcapng header failed");
        match block {
            GeneralBlock::SectionHeaderBlock(shb) => split_rule.update_shb(shb.clone()),
            GeneralBlock::InterfaceDescriptionBlock(idb) => split_rule.update_idb(idb.clone()),
            _ => (),
        }
    }

    loop {
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(e) => match e {
                pcap::Error::TimeoutExpired => continue,
                _ => panic!("get next packet failed: {}", e),
            },
        };

        let packet_data = packet.data;
        match &filters {
            Some(fls) => {
                if fls.check(packet_data).expect("filter check failed") {
                    let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                        .expect("create enhanced packet block failed");
                    let block = GeneralBlock::EnhancedPacketBlock(eb);
                    split_rule.write(block, pbo).expect("write block failed");
                    update_captured_stat();
                } else {
                    warn!("fls check failed")
                }
            }
            None => {
                let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                    .expect("create enhanced packet block failed");
                let block = GeneralBlock::EnhancedPacketBlock(eb);
                split_rule.write(block, pbo).expect("write block failed");
                update_captured_stat();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;
    #[test]
    fn server_run() {
        let itr = vec!["", "--count", "10"];
        let args = Args::parse_from(itr);
        println!("{:?}", args.count);
        capture_local(args);
    }
}
