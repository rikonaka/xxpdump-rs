use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use tracing::error;

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Layer3(EtherType),
    Layer4(IpNextHeaderProtocol),
}

#[derive(Debug, Clone, Copy)]
pub enum FilterType {
    SrcMac(MacAddr),
    DstMac(MacAddr),
    Mac(MacAddr),
    SrcAddr(IpAddr),
    DstAddr(IpAddr),
    Addr(IpAddr),
    SrcPort(u16),
    DstPort(u16),
    Port(u16),
    Protocol(Protocol),
}

#[derive(Debug, Clone)]
pub struct Filter {
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

struct PacketPort {
    src_port: u16,
    dst_port: u16,
}

impl FilterType {
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
                None => {
                    error!("rebuild ipv4 packet failed");
                    None
                }
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
                None => {
                    error!("rebuild ipv6 packet failed");
                    None
                }
            },
            _ => None,
        }
    }
    fn get_ipv4_tcp_udp_port(&self, packet: &[u8]) -> Option<PacketPort> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => Some(PacketPort {
                            src_port: tcp_packet.get_source(),
                            dst_port: tcp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    IpNextHeaderProtocols::Udp => match UdpPacket::new(ipv4_packet.payload()) {
                        Some(udp_packet) => Some(PacketPort {
                            src_port: udp_packet.get_source(),
                            dst_port: udp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    _ => None,
                },
                None => {
                    error!("rebuild ipv4 packet failed");
                    None
                }
            },
            EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(ipv6_packet) => match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => Some(PacketPort {
                            src_port: tcp_packet.get_source(),
                            dst_port: tcp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    IpNextHeaderProtocols::Udp => match UdpPacket::new(ipv6_packet.payload()) {
                        Some(udp_packet) => Some(PacketPort {
                            src_port: udp_packet.get_source(),
                            dst_port: udp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    _ => None,
                },
                None => {
                    error!("rebuild ipv6 packet failed");
                    None
                }
            },
            _ => None,
        }
    }
    fn get_layer3_protocol(&self, packet: &[u8]) -> Option<EtherType> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return None;
            }
        };
        Some(ethernet_packet.get_ethertype())
    }
    fn get_layer4_protocol(&self, packet: &[u8]) -> Option<IpNextHeaderProtocol> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                error!("rebuild ethernet packet failed");
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => Some(ipv4_packet.get_next_level_protocol()),
                None => {
                    error!("rebuild ipv4 packet failed");
                    None
                }
            },
            EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(ipv6_packet) => Some(ipv6_packet.get_next_header()),
                None => {
                    error!("rebuild ipv6 packet failed");
                    None
                }
            },
            _ => None,
        }
    }
    pub fn check(&self, packet: &[u8]) -> bool {
        match *self {
            FilterType::SrcMac(mac) => match self.get_mac(packet) {
                Some(packet_mac) => {
                    if mac == packet_mac.src_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterType::DstMac(mac) => match self.get_mac(packet) {
                Some(packet_mac) => {
                    if mac == packet_mac.dst_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterType::Mac(mac) => match self.get_mac(packet) {
                Some(packet_mac) => {
                    if mac == packet_mac.src_mac || mac == packet_mac.dst_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterType::SrcAddr(addr) => match addr {
                IpAddr::V4(ipv4_addr) => match self.get_ipv4_addr(packet) {
                    Some(packet_ipv4_addr) => {
                        if ipv4_addr == packet_ipv4_addr.src_ipv4 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
                IpAddr::V6(ipv6_addr) => match self.get_ipv6_addr(packet) {
                    Some(packet_ipv6_addr) => {
                        if ipv6_addr == packet_ipv6_addr.src_ipv6 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            },
            FilterType::DstAddr(addr) => match addr {
                IpAddr::V4(ipv4_addr) => match self.get_ipv4_addr(packet) {
                    Some(packet_ipv4_addr) => {
                        if ipv4_addr == packet_ipv4_addr.dst_ipv4 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
                IpAddr::V6(ipv6_addr) => match self.get_ipv6_addr(packet) {
                    Some(packet_ipv6_addr) => {
                        if ipv6_addr == packet_ipv6_addr.dst_ipv6 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            },
            FilterType::Addr(addr) => match addr {
                IpAddr::V4(ipv4_addr) => match self.get_ipv4_addr(packet) {
                    Some(packet_ipv4_addr) => {
                        if ipv4_addr == packet_ipv4_addr.src_ipv4
                            || ipv4_addr == packet_ipv4_addr.dst_ipv4
                        {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
                IpAddr::V6(ipv6_addr) => match self.get_ipv6_addr(packet) {
                    Some(packet_ipv6_addr) => {
                        if ipv6_addr == packet_ipv6_addr.src_ipv6
                            || ipv6_addr == packet_ipv6_addr.dst_ipv6
                        {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            },
            FilterType::SrcPort(port) => match self.get_ipv4_tcp_udp_port(packet) {
                Some(packet_port) => {
                    if port == packet_port.src_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterType::DstPort(port) => match self.get_ipv4_tcp_udp_port(packet) {
                Some(packet_port) => {
                    if port == packet_port.dst_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterType::Port(port) => match self.get_ipv4_tcp_udp_port(packet) {
                Some(packet_port) => {
                    if port == packet_port.src_port || port == packet_port.dst_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterType::Protocol(protocol) => match protocol {
                Protocol::Layer3(layer3_protocol) => match self.get_layer3_protocol(packet) {
                    Some(p) => {
                        if p == layer3_protocol {
                            true
                        } else {
                            false
                        }
                    }
                    None => {
                        error!("failed to get layer3 protocol");
                        false
                    }
                },
                Protocol::Layer4(layer4_protocol) => match self.get_layer4_protocol(packet) {
                    Some(p) => {
                        if p == layer4_protocol {
                            true
                        } else {
                            false
                        }
                    }
                    None => {
                        error!("failed to get layer4 protocol");
                        false
                    }
                },
            },
        }
    }
    pub fn parser(input: &str) -> Option<FilterType> {
        let input_split: Vec<&str> = input.split("=").map(|x| x.trim()).collect();
        if input_split.len() == 2 {
            // ip=192.168.1.1 => ['ip', '192.168.1.1']
            let filter_name = input_split[0].to_lowercase();
            let filter_parameter = input_split[1];
            match filter_name.as_str() {
                "mac" | "srcmac" | "dstmac" => {
                    let mac: MacAddr = match filter_parameter.parse() {
                        Ok(i) => i,
                        Err(e) => panic!(
                            "convert [{}] to MacAddr struct failed: {}",
                            filter_parameter, e
                        ),
                    };
                    if filter_name == "mac" {
                        Some(FilterType::Mac(mac))
                    } else if filter_name == "srcmac" {
                        Some(FilterType::SrcMac(mac))
                    } else {
                        Some(FilterType::DstMac(mac))
                    }
                }
                "ip" | "srcip" | "dstip" => {
                    let ip_addr: IpAddr = match filter_parameter.parse() {
                        Ok(i) => i,
                        Err(e) => panic!(
                            "convert [{}] to IpAddr struct failed: {}",
                            filter_parameter, e
                        ),
                    };
                    if filter_name == "ip" {
                        Some(FilterType::Addr(ip_addr))
                    } else if filter_name == "srcip" {
                        Some(FilterType::SrcAddr(ip_addr))
                    } else {
                        Some(FilterType::DstAddr(ip_addr))
                    }
                }
                "port" | "srcport" | "dstport" => {
                    let port: u16 = match filter_parameter.parse() {
                        Ok(p) => p,
                        Err(e) => panic!("convert [{}] to u16 failed: {}", filter_parameter, e),
                    };
                    if filter_name == "port" {
                        Some(FilterType::Port(port))
                    } else if filter_name == "srcport" {
                        Some(FilterType::SrcPort(port))
                    } else {
                        Some(FilterType::DstPort(port))
                    }
                }
                "procotol" => {
                    // wait
                }
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Operator {
    And,
    Or,
    LeftBracket,
    RightBracket,
}

#[derive(Debug, Clone)]
pub enum ShuntingYardElem {
    Filter(Filter),
    Operator(Operator),
}

/// shunting yard alg.
#[derive(Debug, Clone)]
pub struct FiltersParser {
    pub output_queue: Vec<ShuntingYardElem>,
    pub operator_stack: Vec<ShuntingYardElem>,
}

impl FiltersParser {
    pub fn parser(input: &str) {
        let mut output_queue: Vec<ShuntingYardElem> = Vec::new();
        let mut operator_stack: Vec<ShuntingYardElem> = Vec::new();
        let mut found_space = false;
        let mut read_part = String::new();

        for ch in input.chars() {
            if ch == '(' {
                operator_stack.push(ShuntingYardElem::Operator(Operator::LeftBracket));
            } else if ch == ')' {
                while let Some(op) = operator_stack.pop() {
                    match op {
                        ShuntingYardElem::Operator(o) => match o {
                            Operator::LeftBracket => break,
                            _ => output_queue.push(ShuntingYardElem::Operator(o)),
                        },
                        _ => error!("should not be here"),
                    }
                }
            } else if ch == ' ' {
                if found_space && read_part.len() > 0 {
                    output_queue.push(read_part);
                    read_part = String::new();
                } else {
                    found_space = true;
                }
            } else {
                if found_space && ch != ' ' {
                    read_part.push(ch);
                }
            }
        }
    }
    pub fn examples(show: bool) {
        let exs = vec![
            "ip=192.168.1.1",
            "ip=192.168.1.1 and tcp",
            "ip=192.168.1.1 and port=80",
            "(ip=192.168.1.1 and tcp) or port=80",
        ];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_filter_parser() {}
}
