# xxpdump-rs

The next generation of traffic capture software.

## Installation

### Precompiled version

You can download it directly from the release page. Please note that you need to have installed the `npcap` driver on Windows (it will be automatically installed when you install Wireshark, or you can download and install it separately, and select `winpcap compatibility mode` when installing).

Because `musl` cannot compile `libpcap`, and the results compiled with `gnu` cannot be migrated to different Linux distributions, the download interface only provides downloads of musl based on `libpnet` by default. If you want to use `xxpdump` based on `libpcap`, please use the following method to install it.

### Compile and install it yourself (Linux)

#### Libpcap

You need to install the `libpcap` library on your machine in advance.

```bash
cargo install xxpdump --features "libpcap"
```

#### Libpnet

```bash
cargo install xxpdump --features "libpnet"
```

### Compile and install it yourself (Windows)

On Windows, there is only `npcap` as the underlying library option (regardless of whether the underlying library is `libpcap` or `libpnet`).

Download the `npcap-sdk` file from the [npcap](https://npcap.com/) official website and compile it yourself.

Change the path below to the path where your `Packet.lib` is located.

```bash
$env:LIB="D:\test"
```

Then install it through command.

```bash
cargo install xxpdump --features "libpnet"
```

## Platform

| Platform           | Note                         |
| :----------------- | :--------------------------- |
| Linux              | supported                    |
| Unix (*BSD, MacOS) | supported                    |
| Windows            | supported (winpcap or npcap) |

## Why not tcpdump?

The classic packet capture software `tcpdump` is outdated.

My reasons are as follows:

* The filter implementation of tcpdump is not very powerful.
* The tcpdump does not support remote backup traffic.

The opportunity for the birth of this software is that I have a server with a small memory and a small hard disk (which means I can't directly back up the traffic on this server and store it locally). I want to try to back up the traffic of this server to a backup server with a large hard disk, but the current tcpdump and other series of software cannot natively support remote transmission backup.

### Discussion about `pcap` has been moved to the `pcapture` [readme page](https://github.com/rikonaka/pcapture-rs) (2025-4-28)

## Usage

### Local Capture

Very simple to start using, capture all traffics on all interfaces.

```bash
xxpdump -w xxpdump.pcapng
```

Or specify interface.

```bash
xxpdump -i ens33 -w xxpdump.pcapng
```

Capture the traffic and apply filter.

```bash
xxpdump -i ens33 -w xxpdump.pcapng -f 'tcp and (ip=192.168.1.1 or ip=192.168.1.2) and dstport=80'
```

Capture the traffic and split according to time.

```bash
xxpdump -i ens33 -w xxpdump.pcapng --rotate 60s
```

Capture the traffic and split according to file size.

```bash
xxpdump -i ens33 -w xxpdump.pcapng --file-size 10M
```

Capture the traffic and split according to packet count.

```bash
xxpdump -i ens33 -w xxpdump.pcapng --count 1024
```

### Remote Capture

**Client**

```bash
xxpdump --mode client -i ens33 --server-addr '127.0.0.1:12345'
```

**Server**

This software does not guarantee the security of transmission, so the user needs to build a secure tunnel for this transmission (such as ssh tunnel, etc.).

```bash
xxpdump --mode server --server-addr '127.0.0.1:12345' --rotate 1h
```

Or

```bash
xxpdump --mode server --server-addr '127.0.0.1:12345' --file-size 100M
```

Or

```bash
xxpdump --mode server --server-addr '127.0.0.1:12345' --count 1024
```