use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use tracing::error;

pub enum FilterType {
    SrcMac(MacAddr),
    DstMac(MacAddr),
    SrcAddr(IpAddr),
    DstAddr(IpAddr),
    Addr(IpAddr),
    SrcPort(u16),
    DstPort(u16),
    Port(u16),
    Protocol(String),
}

pub struct Filter {
    pub name: String,
    pub filter_type: FilterType,
}

struct PacketMac {
    src_mac: MacAddr,
    dst_mac: MacAddr,
}

struct PacketIpv4Addr {
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
}

struct PacketIpv6Addr {
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
}

impl Filter {
    pub fn init(name: &str, filter_type: FilterType) -> Filter {
        Filter {
            name: name.to_string(),
            filter_type,
        }
    }
    fn get_mac(&self, packet: &[u8]) -> Option<PacketMac> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return None;
            }
        };
        Some(PacketMac {
            src_mac: ethernet_packet.get_source(),
            dst_mac: ethernet_packet.get_destination(),
        })
    }
    fn get_ipv4_addr(&self, packet: &[u8]) -> Option<PacketIpv4Addr> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => Some(PacketIpv4Addr {
                    src_ipv4: ipv4_packet.get_source(),
                    dst_ipv4: ipv4_packet.get_destination(),
                }),
                None => None,
            },
            _ => None,
        }
    }
    fn get_ipv6_addr(&self, packet: &[u8]) -> Option<PacketIpv6Addr> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(ipv6_packet) => Some(PacketIpv6Addr {
                    src_ipv6: ipv6_packet.get_source(),
                    dst_ipv6: ipv6_packet.get_destination(),
                }),
                None => None,
            },
            _ => None,
        }
    }
    fn get_ipv4_tcp_udp_port(&self, packet: &[u8]) -> Option<PacketIpv4Addr> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(t)
                            }
                        }
                    }
                },
                None => None,
            },
            _ => None,
        }
    }
    pub fn work(&self, packet: &[u8]) -> bool {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return false;
            }
        };

        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                let src_addr = ipv4_packet.get_source();
                let dst_addr = ipv4_packet.get_destination();
                match self.filter_type {
                    FilterType::SrcAddr(addr) => match addr {
                        IpAddr::V4(a) => {
                            if a == src_addr {
                                true
                            } else {
                                false
                            }
                        }
                        _ => false,
                    },
                    FilterType::DstAddr(addr) => match addr {
                        IpAddr::V4(a) => {
                            if a == dst_addr {
                                true
                            } else {
                                false
                            }
                        }
                        _ => false,
                    },
                    FilterType::SrcPort(port) => {}
                    FilterType::DstPort(port) => {}
                }
            }
            EtherTypes::Ipv6 => {
                let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                let src_addr = ipv6_packet.get_source();
                let dst_addr = ipv6_packet.get_destination();
                true
            }
        }
    }
}
