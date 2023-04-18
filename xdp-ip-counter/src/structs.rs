use aya::{
    maps::{self, MapRefMut},
    Bpf,
};
use log::info;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    net::IpAddr,
};

#[derive(PartialEq, Eq, Hash, Clone, Serialize)]
pub enum L3Proto {
    #[serde(rename = "IPv4")]
    Ipv4,
    #[serde(rename = "IPv6")]
    Ipv6,
}
impl Display for L3Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L3Proto::Ipv4 => write!(f, "IPv4"),
            L3Proto::Ipv6 => write!(f, "IPv6"),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Serialize)]
pub enum L4Proto {
    #[serde(rename = "TCP")]
    Tcp,
    #[serde(rename = "UDP")]
    Udp,
}
impl Display for L4Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L4Proto::Tcp => write!(f, "TCP"),
            L4Proto::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Serialize)]
pub struct IpItem {
    pub ip: IpAddr,
    #[serde(rename = "network")]
    pub l3_proto: L3Proto,
    pub port: u16,
    #[serde(rename = "transport")]
    pub l4_proto: L4Proto,
}
impl IpItem {
    pub fn new<T>(ip: T, port: u16, l4_proto: L4Proto) -> Option<Self>
    where
        IpAddr: From<T>,
    {
        let ip = IpAddr::from(ip);
        if ip.is_global() {
            let l3_proto = match ip {
                IpAddr::V4(_) => L3Proto::Ipv4,
                IpAddr::V6(_) => L3Proto::Ipv6,
            };
            return Some(Self {
                ip,
                l3_proto,
                port,
                l4_proto,
            });
        }
        None
    }
}

pub struct LocalMaps {
    pub tcp_v4: HashMap<u16, HashSet<IpItem>>,
    pub udp_v4: HashMap<u16, HashSet<IpItem>>,
    pub tcp_v6: HashMap<u16, HashSet<IpItem>>,
    pub udp_v6: HashMap<u16, HashSet<IpItem>>,
}
impl LocalMaps {
    pub fn new() -> Self {
        Self {
            tcp_v4: HashMap::new(),
            udp_v4: HashMap::new(),
            tcp_v6: HashMap::new(),
            udp_v6: HashMap::new(),
        }
    }
}

/// SharedMaps respresents maps that are used to share data between kernel-space and user-space
pub struct SharedMaps {
    pub tcp_v4: maps::HashMap<MapRefMut, [u8; 4], u16>,
    pub udp_v4: maps::HashMap<MapRefMut, [u8; 4], u16>,
    pub tcp_v6: maps::HashMap<MapRefMut, [u16; 8], u16>,
    pub udp_v6: maps::HashMap<MapRefMut, [u16; 8], u16>,
}
impl SharedMaps {
    /// SharedMaps respresents maps that are used to share data between kernel-space and user-space
    pub fn new(ebpf: &Bpf) -> Self {
        Self {
            tcp_v4: maps::HashMap::try_from(
                ebpf.map_mut("TCP_IP_V4")
                    .expect("unable to borrow TCP_IP_V4 mutably"),
            )
            .expect("failed to create a map from TCP_IP_V4"),
            udp_v4: maps::HashMap::try_from(
                ebpf.map_mut("UDP_IP_V4")
                    .expect("unable to borrow UDP_IP_V4 mutably"),
            )
            .expect("failed to create a map from UDP_IP_V4"),

            tcp_v6: maps::HashMap::try_from(
                ebpf.map_mut("TCP_IP_V6")
                    .expect("unable to borrow TCP_IP_V6 mutably"),
            )
            .expect("failed to create a map from TCP_IP_V6"),
            udp_v6: maps::HashMap::try_from(
                ebpf.map_mut("UDP_IP_V6")
                    .expect("unable to borrow UDP_IP_V6 mutably"),
            )
            .expect("failed to create a map from UDP_IP_V6"),
        }
    }
    pub fn remove_from_tcp_v4(&mut self, ip: &[u8; 4]) {
        if self.tcp_v4.get(ip, 0).is_ok() {
            match self.tcp_v4.remove(ip) {
                Ok(_) => {}
                Err(err) => info!("err removeing from TCP_IP_V4: {}", err),
            }
        }
    }
    pub fn remove_from_udp_v4(&mut self, ip: &[u8; 4]) {
        if self.udp_v4.get(ip, 0).is_ok() {
            match self.udp_v4.remove(ip) {
                Ok(_) => {}
                Err(err) => info!("err removeing from UDP_IP_V4: {}", err),
            }
        }
    }
    pub fn remove_from_tcp_v6(&mut self, ip: &[u16; 8]) {
        if self.tcp_v6.get(ip, 0).is_ok() {
            match self.tcp_v6.remove(ip) {
                Ok(_) => {}
                Err(err) => info!("err removeing from TCP_IP_V6: {}", err),
            }
        }
    }
    pub fn remove_from_udp_v6(&mut self, ip: &[u16; 8]) {
        if self.udp_v6.get(ip, 0).is_ok() {
            match self.udp_v6.remove(ip) {
                Ok(_) => {}
                Err(err) => info!("err removeing from UDP_IP_V6: {}", err),
            }
        }
    }
}
