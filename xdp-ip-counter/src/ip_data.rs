use std::sync::{Arc, Mutex};

use crate::map::LocalMaps;
use serde::Serialize;

#[derive(Serialize)]
pub struct IpData {
    pub ip: String,
    pub r#type: String,
    pub port: u16,
    pub proto: String,
}

pub fn generate_list(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
) -> Vec<IpData> {
    let mut ip_list: Vec<IpData> = vec![];

    let maps = local_maps.lock().unwrap();

    match custom_ports {
        Some(ports) => {
            for (port, ips) in maps.tcp_v4.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(IpData {
                            ip: ip.to_string(),
                            r#type: "v4".to_owned(),
                            port: *port,
                            proto: "tcp".to_owned(),
                        })
                    }
                }
            }
            for (port, ips) in maps.udp_v4.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(IpData {
                            ip: ip.to_string(),
                            r#type: "v4".to_owned(),
                            port: *port,
                            proto: "udp".to_owned(),
                        })
                    }
                }
            }

            for (port, ips) in maps.tcp_v6.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(IpData {
                            ip: ip.to_string(),
                            r#type: "v6".to_owned(),
                            port: *port,
                            proto: "tcp".to_owned(),
                        })
                    }
                }
            }
            for (port, ips) in maps.udp_v6.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(IpData {
                            ip: ip.to_string(),
                            r#type: "v6".to_owned(),
                            port: *port,
                            proto: "udp".to_owned(),
                        })
                    }
                }
            }
        }
        None => {
            for (port, ips) in maps.tcp_v4.iter() {
                for ip in ips.iter() {
                    ip_list.push(IpData {
                        ip: ip.to_string(),
                        r#type: "v4".to_owned(),
                        port: *port,
                        proto: "tcp".to_owned(),
                    })
                }
            }
            for (port, ips) in maps.udp_v4.iter() {
                for ip in ips.iter() {
                    ip_list.push(IpData {
                        ip: ip.to_string(),
                        r#type: "v4".to_owned(),
                        port: *port,
                        proto: "udp".to_owned(),
                    })
                }
            }

            for (port, ips) in maps.tcp_v6.iter() {
                for ip in ips.iter() {
                    ip_list.push(IpData {
                        ip: ip.to_string(),
                        r#type: "v6".to_owned(),
                        port: *port,
                        proto: "tcp".to_owned(),
                    })
                }
            }
            for (port, ips) in maps.udp_v6.iter() {
                for ip in ips.iter() {
                    ip_list.push(IpData {
                        ip: ip.to_string(),
                        r#type: "v6".to_owned(),
                        port: *port,
                        proto: "udp".to_owned(),
                    })
                }
            }
        }
    }

    ip_list
}
