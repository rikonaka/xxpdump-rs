# xxpdump-rs

The next generation of traffic capture software.

## Installation

```bash
cargo install xxpdump
```

## Why tcpdump?

The classic packet capture software `tcpdump` is outdated.

My reasons are as follows:

* The filter implementation of tcpdump is not very powerful.
* The tcpdump does not support remote backup traffic.

The opportunity for the birth of this software is that I have a server with a small memory and a small hard disk (which means I can't directly back up the traffic on this server and store it locally). I want to try to back up the traffic of this server to a backup server with a large hard disk, but the current tcpdump and other series of software cannot natively support remote transmission backup.

## Discussion about `pcap` has been moved to the `pcapture` [readme page](https://github.com/rikonaka/pcapture-rs) (2025-4-28)

## Usage

### Local Capture

Very simple to start using.

```bash
xxpdump -i ens33 -p xxpdump.pcapng
```

Capture the traffic and apply filter.

```bash
xxpdump -i ens33 -p xxpdump.pcapng -f 'tcp and (ip=192.168.1.1 or ip=192.168.1.2) and dstport=80'
```

Capture the traffic and split according to time.

```bash
xxpdump -i ens33 -p xxpdump.pcapng --rotate 60s
```

Capture the traffic and split according to file size.

```bash
xxpdump -i ens33 -p xxpdump.pcapng --file-size 10M
```

Capture the traffic and split according to packet count.

```bash
xxpdump -i ens33 -p xxpdump.pcapng --count 1024
```

### Remote Capture

**Client**

Running this command will generate a `.client_uuid` file locally to distinguish other clients.

Yes, this software supports different clients backing up to the same server.

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