use aya::{
    maps::{self, MapRefMut},
    Bpf,
};
use log::info;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

pub struct LocalMaps {
    pub tcp_v4: HashMap<u16, HashSet<IpAddr>>,
    pub udp_v4: HashMap<u16, HashSet<IpAddr>>,
    pub tcp_v6: HashMap<u16, HashSet<IpAddr>>,
    pub udp_v6: HashMap<u16, HashSet<IpAddr>>,
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
