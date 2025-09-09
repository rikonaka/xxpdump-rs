use chrono::Local;
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
#[cfg(feature = "libpcap")]
use pcapture::pcapng::GeneralBlock;
#[cfg(feature = "libpcap")]
use pcapture::pcapng::PcapNg;
use std::fs::File;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;
use tracing::warn;

use crate::Args;
use crate::file_size_parser;
use crate::get_file_size;
use crate::quitting;
use crate::rotate_parser;
use crate::update_captured_stat;

#[cfg(feature = "libpnet")]
fn capture_local_by_count(cap: &mut Capture, path: &str, count: usize) {
    let mut pcapng = cap
        .gen_pcapng(PcapByteOrder::WiresharkDefault)
        .expect("gen pcapng failed");
    for _ in 0..count {
        let block = cap
            .next_as_pcapng()
            .expect(&format!("capture local packet failed"));
        pcapng.append(block);
        update_captured_stat();
    }
    pcapng
        .write_all(path)
        .expect(&format!("write pcapng to file [{}] failed", path));
}

#[cfg(feature = "libpnet")]
fn capture_local_by_filesize(cap: &mut Capture, path: &str, file_size: u64, file_count: usize) {
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut i = 0;

    fn get_next_i(i: usize, file_count: usize) -> usize {
        if i < file_count - 1 { i + 1 } else { 0 }
    }

    // write the first header to file
    let mut new_path = format!("{}.{}", i, path);
    let mut fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));
    let pcapng = cap.gen_pcapng(pbo).expect("gen pcapng failed");
    pcapng
        .write(&mut fs)
        .expect(&format!("write pcapng to {} failed", new_path));

    loop {
        let local_file_size = get_file_size(&new_path);
        if local_file_size > file_size {
            // change write to new file
            i = if file_count > 0 {
                get_next_i(i, file_count)
            } else {
                i + 1
            };
            new_path = format!("{}.{}", i, path);
            fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));

            pcapng
                .write(&mut fs)
                .expect(&format!("write pcapng to {} failed", new_path));
        }

        match cap.next_as_pcapng() {
            Ok(block) => {
                block
                    .write(&mut fs, pbo)
                    .expect(&format!("write block to file [{}] failed", new_path));
                update_captured_stat();
            }
            Err(e) => warn!("{}", e),
        }
    }
}

#[cfg(feature = "libpnet")]
fn capture_local_by_rotate(
    cap: &mut Capture,
    path: &str,
    rotate: u64,
    file_count: usize,
    rotate_format: &str,
) {
    let mut start_time = Instant::now();
    let mut write_files = 0;

    let pbo = PcapByteOrder::WiresharkDefault;
    let now = Local::now();
    let now_str = now.format(rotate_format);

    // write the first header to file
    let mut new_path = format!("{}.{}", now_str, path);
    let mut fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));
    let pcapng = cap.gen_pcapng(pbo).expect("gen pcapng data failed");
    pcapng
        .write(&mut fs)
        .expect(&format!("write pcapng to {} failed", new_path));

    // work progress
    let mut capture = |write_files: &mut usize| {
        let duration = start_time.elapsed();
        if duration.as_secs() >= rotate {
            start_time += Duration::from_secs(rotate);
            let now = Local::now();
            let now_str = now.format(rotate_format);
            new_path = format!("{}.{}", now_str, path);
            fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));
            pcapng
                .write(&mut fs)
                .expect(&format!("write pcapng to {} failed", new_path));
            *write_files += 1;
        }

        match cap.next_as_pcapng() {
            Ok(block) => {
                block
                    .write(&mut fs, pbo)
                    .expect(&format!("write block to file [{}] failed", new_path));
                update_captured_stat();
            }
            Err(e) => warn!("{}", e),
        }
    };

    if file_count > 0 {
        // Used  in conjunction with the -G option,
        // this will limit the number of rotated dump files that get created,
        // exiting with status 0 when reaching the limit.
        loop {
            capture(&mut write_files);
            if write_files > file_count {
                break;
            }
        }
    } else {
        loop {
            capture(&mut write_files);
        }
    }
}

#[cfg(feature = "libpnet")]
fn capture_local_by_none(cap: &mut Capture, path: &str) {
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut fs = File::create(&path).expect(&format!("can not create file [{}]", path));
    let pcapng = cap.gen_pcapng(pbo).expect("gen pcapng failed");
    pcapng
        .write(&mut fs)
        .expect(&format!("write pcapng to {} failed", path));

    loop {
        match cap.next_as_pcapng() {
            Ok(block) => {
                block
                    .write(&mut fs, pbo)
                    .expect(&format!("write block to file [{}] failed", path));
                update_captured_stat();
            }
            Err(e) => warn!("{}", e),
        }
    }
}

#[cfg(feature = "libpnet")]
pub fn capture_local(args: &Args) {
    let filter = &args.filter;
    let iface = &args.interface;
    let mut cap = match Capture::new(&iface, Some(&filter)) {
        Ok(c) => c,
        Err(e) => panic!("init the Capture failed: {}", e),
    };
    cap.promiscuous(args.promisc);
    cap.buffer_size(args.buffer_size);
    cap.snaplen(args.snaplen);
    cap.timeout(args.timeout);

    debug!("open save file path");

    let path = &args.write;
    let count = args.count;
    let file_size_str = &args.file_size;
    let file_count = args.file_count;
    let rotate_str = &args.rotate;

    if count > 0 {
        capture_local_by_count(&mut cap, path, count);
    } else if file_size_str.len() > 0 {
        let file_size = file_size_parser(file_size_str);
        capture_local_by_filesize(&mut cap, path, file_size, file_count);
    } else if rotate_str.len() > 0 {
        let (rotate, rotate_format) = rotate_parser(rotate_str);
        capture_local_by_rotate(&mut cap, path, rotate, file_count, rotate_format);
    } else {
        capture_local_by_none(&mut cap, path);
    }

    quitting("local");
}

#[cfg(feature = "libpcap")]
pub fn capture_local(args: &Args) {
    let pbo = PcapByteOrder::WiresharkDefault;
    let filters = Filters::parser(&args.filter).expect("parser filter failed");

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
            .immediate_mode(true)
            .open()
            .expect("can not open libpcap capture");
        cap
    } else {
        let cap = cap
            .buffer_size(args.buffer_size as i32)
            .snaplen(args.snaplen as i32)
            .timeout(args.timeout as i32)
            .immediate_mode(true)
            .open()
            .expect("can not open libpcap capture");
        cap
    };

    debug!("open save file path");

    let path = &args.write;
    let count = args.count;
    let file_size_str = &args.file_size;
    let file_count = args.file_count;
    let rotate_str = &args.rotate;

    let mut pcapng = PcapNg::new_fake();

    if count > 0 {
        let mut num_packet = 0;
        loop {
            if num_packet >= count {
                break;
            }
            let packet = cap
                .next_packet()
                .expect("can not get next packet from libpcap");
            let packet_data = packet.data;
            match filters.as_ref() {
                Some(fls) => {
                    if fls.check(packet_data).expect("filter check failed") {
                        let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                            .expect("create enhanced packet block failed");
                        let block = GeneralBlock::EnhancedPacketBlock(eb);
                        pcapng.append(block);
                        update_captured_stat();
                        num_packet += 1;
                    }
                }
                None => {
                    let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                        .expect("create enhanced packet block failed");
                    let block = GeneralBlock::EnhancedPacketBlock(eb);
                    pcapng.append(block);
                    update_captured_stat();
                    num_packet += 1;
                }
            }
        }
        pcapng
            .write_all(path)
            .expect(&format!("write pcapng to file [{}] failed", path));
    } else if file_size_str.len() > 0 {
        let file_size = file_size_parser(file_size_str);
        let mut i = 0;

        fn get_next_i(i: usize, file_count: usize) -> usize {
            if i < file_count - 1 { i + 1 } else { 0 }
        }

        // write the first header to file
        let mut new_path = format!("{}.{}", i, path);
        let mut fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));
        pcapng
            .write(&mut fs)
            .expect(&format!("write pcapng to {} failed", new_path));

        loop {
            let local_file_size = get_file_size(&new_path);
            if local_file_size > file_size {
                // change write to new file
                i = if file_count > 0 {
                    get_next_i(i, file_count)
                } else {
                    i + 1
                };
                new_path = format!("{}.{}", i, path);
                fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));

                pcapng
                    .write(&mut fs)
                    .expect(&format!("write pcapng to {} failed", new_path));
            }

            match cap.next_packet() {
                Ok(packet) => {
                    let packet_data = packet.data;
                    match filters.as_ref() {
                        Some(fls) => {
                            if fls.check(packet_data).expect("filter check failed") {
                                let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                                    .expect("create enhanced packet block failed");
                                let block = GeneralBlock::EnhancedPacketBlock(eb);
                                block
                                    .write(&mut fs, pbo)
                                    .expect(&format!("write block to file [{}] failed", new_path));
                                update_captured_stat();
                            }
                        }
                        None => {
                            let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                                .expect("create enhanced packet block failed");
                            let block = GeneralBlock::EnhancedPacketBlock(eb);
                            block
                                .write(&mut fs, pbo)
                                .expect(&format!("write block to file [{}] failed", new_path));
                            update_captured_stat();
                        }
                    }
                }
                Err(e) => warn!("{}", e),
            }
        }
    } else if rotate_str.len() > 0 {
        let (rotate, rotate_format) = rotate_parser(rotate_str);

        let mut start_time = Instant::now();
        let mut write_files = 0;

        let pbo = PcapByteOrder::WiresharkDefault;
        let now = Local::now();
        let now_str = now.format(rotate_format);

        // write the first header to file
        let mut new_path = format!("{}.{}", now_str, path);
        let mut fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));
        pcapng
            .write(&mut fs)
            .expect(&format!("write pcapng to {} failed", new_path));

        // work progress
        let mut capture = |write_files: &mut usize| {
            let duration = start_time.elapsed();
            if duration.as_secs() >= rotate {
                start_time += Duration::from_secs(rotate);
                let now = Local::now();
                let now_str = now.format(rotate_format);
                new_path = format!("{}.{}", now_str, path);
                fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));
                pcapng
                    .write(&mut fs)
                    .expect(&format!("write pcapng to {} failed", new_path));
                *write_files += 1;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    let packet_data = packet.data;
                    match filters.as_ref() {
                        Some(fls) => {
                            if fls.check(packet_data).expect("filter check failed") {
                                let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                                    .expect("create enhanced packet block failed");
                                let block = GeneralBlock::EnhancedPacketBlock(eb);
                                block
                                    .write(&mut fs, pbo)
                                    .expect(&format!("write block to file [{}] failed", new_path));
                                update_captured_stat();
                            }
                        }
                        None => {
                            let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                                .expect("create enhanced packet block failed");
                            let block = GeneralBlock::EnhancedPacketBlock(eb);
                            block
                                .write(&mut fs, pbo)
                                .expect(&format!("write block to file [{}] failed", new_path));
                            update_captured_stat();
                        }
                    }
                }
                Err(e) => warn!("{}", e),
            }
        };

        if file_count > 0 {
            // Used  in conjunction with the -G option,
            // this will limit the number of rotated dump files that get created,
            // exiting with status 0 when reaching the limit.
            loop {
                capture(&mut write_files);
                if write_files > file_count {
                    break;
                }
            }
        } else {
            loop {
                capture(&mut write_files);
            }
        }
    } else {
        let mut fs = File::create(&path).expect(&format!("can not create file [{}]", path));
        pcapng
            .write(&mut fs)
            .expect(&format!("write pcapng to {} failed", path));

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
                                block
                                    .write(&mut fs, pbo)
                                    .expect(&format!("write block to file [{}] failed", path));
                                update_captured_stat();
                            }
                        }
                        None => {
                            let eb = EnhancedPacketBlock::new(0, packet_data, args.snaplen)
                                .expect("create enhanced packet block failed");
                            let block = GeneralBlock::EnhancedPacketBlock(eb);
                            block
                                .write(&mut fs, pbo)
                                .expect(&format!("write block to file [{}] failed", path));
                            update_captured_stat();
                        }
                    }
                }
                Err(e) => warn!("{}", e),
            }
        }
    }

    quitting("local");
}
