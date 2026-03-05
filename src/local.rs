#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use anyhow::Result;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::Capture;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::PcapByteOrder;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use pcapture::fs::pcapng::GeneralBlock;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use std::sync::atomic::Ordering;

#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::Args;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::SHOULD_EXIT;
#[cfg(any(feature = "libpnet", feature = "libpcap"))]
use crate::split::SplitRule;

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

    let mut total_recved = 0;
    while !SHOULD_EXIT.load(Ordering::SeqCst) {
        match cap.next_as_pcapng() {
            Ok(block) => {
                total_recved += 1;
                split_rule.append(block)?;
            }
            Err(_e) => (), // ignore the error, just try to capture the next packet
        }
    }

    println!("total captured packet: {}", total_recved);
    Ok(())
}

#[cfg(feature = "libpcap")]
pub fn capture_local(args: Args) -> Result<()> {
    let mut cap = Capture::new(&args.interface)?;
    cap.set_promiscuous_mode(args.promisc);
    cap.set_immediate_mode(args.immediate);
    cap.set_buffer_size(args.buffer_size);
    cap.set_snaplen(args.snaplen);
    cap.set_timeout((args.timeout * 1000.0) as i32);
    if let Some(filter) = &args.filter {
        cap.set_filter(filter);
    }

    let pbo = PcapByteOrder::WiresharkDefault;
    let pcapng = cap.gen_pcapng_header(pbo)?;
    let mut split_rule = SplitRule::init(&args, pbo)?;

    for block in pcapng.blocks {
        match block {
            GeneralBlock::SectionHeaderBlock(shb) => split_rule.update_shb(shb.clone()),
            GeneralBlock::InterfaceDescriptionBlock(idb) => split_rule.update_idb(idb.clone()),
            _ => (),
        }
    }

    let mut total_recved = 0;
    while !SHOULD_EXIT.load(Ordering::SeqCst) {
        let blocks = cap.fetch_as_pcapng()?;
        total_recved += blocks.len();
        for block in blocks {
            split_rule.append(block)?;
        }
    }

    println!("total captured packet: {}", total_recved);
    Ok(())
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
