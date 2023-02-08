use aya::{
    maps::{self, MapRefMut},
    Bpf,
};
use log::info;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

pub struct LocalMaps {
    pub tcp: HashMap<u16, HashSet<Ipv4Addr>>,
    pub udp: HashMap<u16, HashSet<Ipv4Addr>>,
}
impl LocalMaps {
    pub fn new() -> Self {
        Self {
            tcp: HashMap::new(),
            udp: HashMap::new(),
        }
    }
}

pub struct SharedMaps {
    pub tcp: maps::HashMap<MapRefMut, u32, u16>,
    pub udp: maps::HashMap<MapRefMut, u32, u16>,
}
impl SharedMaps {
    /// SharedMaps respresents maps that are used to share data between kernel-space and user-space
    pub fn new(ebpf: &Bpf) -> Self {
        Self {
            tcp: maps::HashMap::try_from(
                ebpf.map_mut("TCP_IP_PORT_MAP")
                    .expect("unable to borrow TCP_IP_PORT_MAP mutably"),
            )
            .expect("failed to create a map from TCP_IP_PORT_MAP"),
            udp: maps::HashMap::try_from(
                ebpf.map_mut("UDP_IP_PORT_MAP")
                    .expect("unable to borrow UDP_IP_PORT_MAP mutably"),
            )
            .expect("failed to create a map from UDP_IP_PORT_MAP"),
        }
    }
    pub fn remove_from_tcp(&mut self, ip: &u32) {
        if self.tcp.get(ip, 0).is_ok() {
            match self.tcp.remove(ip) {
                Ok(_) => {}
                Err(err) => info!("err removeing from TCP_IP_PORT_MAP: {}", err),
            }
        }
    }
    pub fn remove_from_udp(&mut self, ip: &u32) {
        if self.udp.get(ip, 0).is_ok() {
            match self.udp.remove(ip) {
                Ok(_) => {}
                Err(err) => info!("err removeing from TCP_IP_PORT_MAP: {}", err),
            }
        }
    }
}
