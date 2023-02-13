use std::sync::{Arc, Mutex};

use crate::map::{IpItem, LocalMaps};

pub fn generate_list(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
) -> Vec<IpItem> {
    let mut ip_list: Vec<IpItem> = vec![];

    let maps = local_maps.lock().unwrap();

    match custom_ports {
        Some(ports) => {
            for (port, ips) in maps.tcp_v4.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(ip.clone())
                    }
                }
            }
            for (port, ips) in maps.udp_v4.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(ip.clone())
                    }
                }
            }

            for (port, ips) in maps.tcp_v6.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(ip.clone())
                    }
                }
            }
            for (port, ips) in maps.udp_v6.iter() {
                if ports.contains(port) {
                    for ip in ips.iter() {
                        ip_list.push(ip.clone())
                    }
                }
            }
        }
        None => {
            for (_, ips) in maps.tcp_v4.iter() {
                for ip in ips.iter() {
                    ip_list.push(ip.clone())
                }
            }
            for (_, ips) in maps.udp_v4.iter() {
                for ip in ips.iter() {
                    ip_list.push(ip.clone())
                }
            }

            for (_, ips) in maps.tcp_v6.iter() {
                for ip in ips.iter() {
                    ip_list.push(ip.clone())
                }
            }
            for (_, ips) in maps.udp_v6.iter() {
                for ip in ips.iter() {
                    ip_list.push(ip.clone())
                }
            }
        }
    }

    ip_list
}
