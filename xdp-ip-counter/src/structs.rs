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

/// L3Proto represents the layer 3 protocol of a packet.
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

/// L4Proto represents the layer 4 protocol of a packet and the port number.  
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
    ip: IpAddr,
    #[serde(rename = "network")]
    l3_proto: L3Proto,
    #[serde(rename = "transport")]
    l4_proto: String,
    port: u16,
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
            let port = match l4_proto {
                L4Proto::Tcp(port) => *port,
                L4Proto::Udp(port) => *port,
            };
            return Some(Self {
                ip,
                l3_proto,
                l4_proto: (*l4_proto.to_string()).to_string(),
                port,
            });
        }
        None
    }
}

/// LocalMap respresents maps that are used to store data in an appropriate format to be served to users
pub struct LocalMap {
    inner_aggr: HashMap<L3Proto, HashMap<L4Proto, HashSet<IpItem>>>,
    inner_tmp: HashMap<L3Proto, HashMap<L4Proto, HashSet<IpItem>>>,
}
impl LocalMap {
    pub fn new() -> Self {
        Self {
            inner_aggr: HashMap::new(),
            inner_tmp: HashMap::new(),
        }
    }

    /// Saves the collected data from the past aggregate_window to be served for the next aggregate_window.
    /// Check ebpf::collect() for more details.  
    pub fn aggr(&mut self) {
        self.inner_aggr.clear();
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

    pub fn get_prom_metrics(&self) -> &HashMap<L3Proto, HashMap<L4Proto, HashSet<IpItem>>> {
        &self.inner_aggr
    }

    pub fn get_ip_list(&self) -> Vec<&IpItem> {
        let mut ip_list: Vec<&IpItem> = vec![];
        for (_, l4_set) in self.inner_aggr.iter() {
            for (_, set) in l4_set {
                let mut items: Vec<&IpItem> = set.iter().collect();
                ip_list.append(&mut items)
            }
        }
        ip_list
    }
}

/// SharedMaps respresents maps that are used to share data between kernel-space and user-space
pub struct SharedMaps {
    pub use_custom_ports: maps::Array<MapRefMut, u8>,
    pub custom_ports: maps::HashMap<MapRefMut, u16, u8>,
    pub tcp_v4: maps::HashMap<MapRefMut, [u8; 4], u16>,
    pub udp_v4: maps::HashMap<MapRefMut, [u8; 4], u16>,
    pub tcp_v6: maps::HashMap<MapRefMut, [u16; 8], u16>,
    pub udp_v6: maps::HashMap<MapRefMut, [u16; 8], u16>,
}
impl SharedMaps {
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

            custom_ports: maps::HashMap::try_from(
                ebpf.map_mut("CUSTOM_PORTS")
                    .expect("unable to borrow CUSTOM_PORTS mutably"),
            )
            .expect("failed to create a map from CUSTOM_PORTS"),

            use_custom_ports: maps::Array::try_from(
                ebpf.map_mut("USE_CUSTOM_PORTS")
                    .expect("unable to borrow USE_CUSTOM_PORTS mutably"),
            )
            .expect("failed to create a map from USE_CUSTOM_PORTS"),
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
