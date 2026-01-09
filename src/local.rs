#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::Capture;
#[cfg(feature = "libpcap")]
use pcapture::Device;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(feature = "libpcap")]
use pcapture::fs::pcapng::PcapNg;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use tracing::debug;
#[cfg(feature = "libpnet")]
use tracing::warn;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::Args;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::split::SplitRule;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::update_captured_packets_num;

#[cfg(feature = "libpnet")]
pub fn capture_local(args: Args) -> Result<()> {
    let filter = if let Some(fl) = &args.filter {
        fl.clone()
    } else {
        String::new()
    };

    let pbo = PcapByteOrder::WiresharkDefault;
    let mut cap = Capture::new(&args.interface)?;
    cap.set_promiscuous(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen);
    cap.set_timeout(args.timeout);
    cap.set_filter(&filter)?;

    debug!("open save file path");

    let mut split_rule = SplitRule::init(&args, pbo)?;
    let pcapng = cap.gen_pcapng_header(pbo)?;

    // there only SHB and IDB in the generated pcapng header now
    for block in pcapng.blocks {
        match block {
            GeneralBlock::SectionHeaderBlock(shb) => split_rule.update_shb(shb.clone()),
            GeneralBlock::InterfaceDescriptionBlock(idb) => split_rule.update_idb(idb.clone()),
            _ => (),
        }
    }

    loop {
        match cap.next_as_pcapng() {
            Ok(block) => {
                split_rule.append(block)?;
                update_captured_packets_num(1);
            }
            Err(e) => warn!("{}", e),
        }
    }
}

#[cfg(feature = "libpcap")]
pub fn capture_local(args: Args) -> Result<()> {
    let mut cap = Capture::new(&args.interface)?;
    cap.set_promiscuous(args.promisc);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen as i32);
    cap.set_timeout((args.timeout * 1000.0) as i32);
    if let Some(filter) = &args.filter {
        cap.set_filter(filter);
    }

    debug!("open save file path");

    let devices = Device::list()?;
    let mut ips = Vec::new();
    let mut if_description = String::new();
    for device in devices {
        if device.name == args.interface {
            ips = device.addresses.clone();
            if let Some(d) = device.description {
                if_description = d.clone();
            }
            break;
        }
    }
    let if_name = &args.interface;

    let pbo = PcapByteOrder::WiresharkDefault;
    let pcapng = PcapNg::new_raw(if_name, &if_description, &ips);
    let mut split_rule = SplitRule::init(&args, pbo)?;

    for block in pcapng.blocks {
        match block {
            GeneralBlock::SectionHeaderBlock(shb) => split_rule.update_shb(shb.clone()),
            GeneralBlock::InterfaceDescriptionBlock(idb) => split_rule.update_idb(idb.clone()),
            _ => (),
        }
    }

    loop {
        let blocks = cap.fetch_as_pcapng()?;
        update_captured_packets_num(blocks.len());
        for block in blocks {
            split_rule.append(block)?;
        }
    }
}

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;
    #[test]
    fn server_run() {
        let itr = vec!["", "--count", "10"];
        let args = Args::parse_from(itr);
        println!("{:?}", args.count);
        capture_local(args).unwrap();
    }
}
