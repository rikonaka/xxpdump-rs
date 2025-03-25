# xxpdump-rs

The classic packet capture software `tcpdump` is outdated.

My reasons are as follows:

* it does not support remote capture
* it does not support the management of local historical files
* it does not support automatic file upload to the server
* and more...

## Dependencies

Debian

```bash
sudo apt install libpcap-dev
```

Fedora

```bash
sudo dnf install libpcap-devel
```

If not running as root, you need to set capabilities like so:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin
```