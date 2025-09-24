#[cfg(feature = "libpcap")]
use pcap::Capture;
#[cfg(feature = "libpcap")]
use pcap::Device;
#[cfg(feature = "libpnet")]
use pcapture;
#[cfg(feature = "libpnet")]
use pcapture::Capture;
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
use tracing::debug;
use tracing::warn;

use crate::Args;
use crate::split::SplitRule;
use crate::update_captured_stat;

#[cfg(feature = "libpnet")]
pub fn capture_local(args: Args) {
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut cap = match Capture::new(&args.interface, args.filter.clone()) {
        Ok(c) => c,
        Err(e) => panic!("init the Capture failed: {}", e),
    };
    cap.promiscuous(args.promisc);
    cap.buffer_size(args.buffer_size);
    cap.snaplen(args.snaplen);
    cap.timeout(args.timeout);

    debug!("open save file path");

    let mut split_rule = SplitRule::init(&args).expect("init SplitRule failed");
    let pcapng = cap.gen_pcapng(pbo).expect("generate pcapng header failed");

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
    let filters = match &args.filter {
        Some(filter) => Filters::parser(filter).expect("parser filter failed"),
        None => None,
    };

    let pbo = PcapByteOrder::WiresharkDefault;
    let devices = Device::list().expect("can not get device from libpcap");
    let device = devices
        .iter()
        .find(|&d| d.name == args.interface)
        .expect("can not found interface");

    let cap = Capture::from_device(device.clone()).expect("init the Capture failed");
    let mut cap = if args.interface != "any" {
        let cap = cap
            .promisc(args.promisc)
            .buffer_size(args.buffer_size as i32)
            .snaplen(args.snaplen as i32)
            .timeout(args.timeout as i32)
            .open()
            .expect("can not open libpcap capture");
        cap
    } else {
        let cap = cap
            .buffer_size(args.buffer_size as i32)
            .snaplen(args.snaplen as i32)
            .timeout(args.timeout as i32)
            .open()
            .expect("can not open libpcap capture");
        cap
    };

    debug!("open save file path");

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
