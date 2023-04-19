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

#[derive(PartialEq, Eq, Hash, Clone, Serialize, Debug)]
#[non_exhaustive]
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

#[derive(PartialEq, Eq, Hash, Clone, Copy, Serialize, Debug)]
#[non_exhaustive]
pub enum L4Proto {
    #[serde(rename = "TCP")]
    Tcp(u16),
    #[serde(rename = "UDP")]
    Udp(u16),
}
impl Display for L4Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L4Proto::Tcp(_) => write!(f, "TCP"),
            L4Proto::Udp(_) => write!(f, "UDP"),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Serialize, Debug)]
pub struct IpItem {
    pub ip: IpAddr,
    #[serde(rename = "network")]
    pub l3_proto: L3Proto,
    #[serde(rename = "transport")]
    pub l4_proto: L4Proto,
}
impl IpItem {
    pub fn new<T>(ip: T, l4_proto: &L4Proto) -> Option<Self>
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
                l4_proto: *l4_proto,
            });
        }
        None
    }
}

// pub struct LocalMaps {
//     pub tcp_v4: HashMap<u16, HashSet<IpItem>>,
//     pub udp_v4: HashMap<u16, HashSet<IpItem>>,
//     pub tcp_v6: HashMap<u16, HashSet<IpItem>>,
//     pub udp_v6: HashMap<u16, HashSet<IpItem>>,
// }
// impl LocalMaps {
//     pub fn new() -> Self {
//         Self {
//             tcp_v4: HashMap::new(),
//             udp_v4: HashMap::new(),
//             tcp_v6: HashMap::new(),
//             udp_v6: HashMap::new(),
//         }
//     }
// }

#[derive(Debug)]
pub struct LocalMap {
    pub inner_aggr: HashMap<L3Proto, HashMap<L4Proto, HashSet<IpItem>>>,
    pub inner_tmp: HashMap<L3Proto, HashMap<L4Proto, HashSet<IpItem>>>,
}
impl LocalMap {
    pub fn new() -> Self {
        Self {
            inner_aggr: HashMap::new(),
            inner_tmp: HashMap::new(),
        }
    }

    pub fn aggr(&mut self) {
        self.inner_aggr = self.inner_tmp.clone();
        self.inner_tmp.clear();
    }

    pub fn add_tmp<T>(&mut self, l3_proto: L3Proto, l4_proto: L4Proto, ip: T)
    where
        IpAddr: From<T>,
    {
        if let Some(ip_item) = IpItem::new(ip, &l4_proto) {
            if let Some(map) = self.inner_tmp.get_mut(&l3_proto) {
                if let Some(set) = map.get_mut(&l4_proto) {
                    set.insert(ip_item);
                } else {
                    let mut set = HashSet::new();
                    set.insert(ip_item);
                    map.insert(l4_proto, set);
                }
            } else {
                let mut set = HashSet::new();
                set.insert(ip_item);

                let mut map = HashMap::new();
                map.insert(l4_proto, set);

                self.inner_tmp.insert(l3_proto, map);
            }
        } else {
            // ip is local
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
