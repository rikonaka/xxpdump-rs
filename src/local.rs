use chrono::Local;
use pcapture;
use pcapture::Capture;
use pcapture::PcapByteOrder;
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

fn capture_local_by_count(cap: &mut Capture, path: &str, count: usize) {
    let mut pcapng = cap.gen_pcapng(PcapByteOrder::WiresharkDefault);
    for _ in 0..count {
        let block = cap
            .next_with_pcapng()
            .expect(&format!("capture local packet failed"));
        pcapng.append(block);
        update_captured_stat();
    }
    pcapng
        .write_all(path)
        .expect(&format!("write pcapng to file [{}] failed", path));
}

fn capture_local_by_filesize(cap: &mut Capture, path: &str, file_size: u64, file_count: usize) {
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut i = 0;

    fn get_next_i(i: usize, file_count: usize) -> usize {
        if i < file_count - 1 { i + 1 } else { 0 }
    }

    // write the first header to file
    let mut new_path = format!("{}.{}", i, path);
    let mut fs = File::create(&new_path).expect(&format!("can not create file [{}]", new_path));
    let pcapng = cap.gen_pcapng(pbo);
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

        match cap.next_with_pcapng() {
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
    let pcapng = cap.gen_pcapng(pbo);
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

        match cap.next_with_pcapng() {
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

fn capture_local_by_none(cap: &mut Capture, path: &str) {
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut fs = File::create(&path).expect(&format!("can not create file [{}]", path));
    let pcapng = cap.gen_pcapng(pbo);
    pcapng
        .write(&mut fs)
        .expect(&format!("write pcapng to {} failed", path));

    loop {
        match cap.next_with_pcapng() {
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

pub fn capture_local(cap: &mut Capture, args: &Args) {
    debug!("open save file path");

    let path = &args.path;
    let count = args.count;
    let file_size_str = &args.file_size;
    let file_count = args.file_count;
    let rotate_str = &args.rotate;

    if count > 0 {
        capture_local_by_count(cap, path, count);
    } else if file_size_str.len() > 0 {
        let file_size = file_size_parser(file_size_str);
        capture_local_by_filesize(cap, path, file_size, file_count);
    } else if rotate_str.len() > 0 {
        let (rotate, rotate_format) = rotate_parser(rotate_str);
        capture_local_by_rotate(cap, path, rotate, file_count, rotate_format);
    } else {
        capture_local_by_none(cap, path);
    }

    quitting("local");
}
