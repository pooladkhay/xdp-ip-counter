use aya_bpf::{
    macros::map,
    maps::{Array, HashMap},
};
use network_types::ip::IpProto;

pub const PORTS_MAP_SIZE: u32 = 100;
pub const PACKETS_MAP_SIZE: u32 = 10240;

#[map(name = "USE_CUSTOM_PORTS")]
pub static mut USE_CUSTOM_PORTS: Array<u8> = Array::with_max_entries(1, 0);

#[map(name = "CUSTOM_PORTS")]
pub static mut CUSTOM_PORTS: HashMap<u16, u8> =
    HashMap::<u16, u8>::with_max_entries(PORTS_MAP_SIZE, 0);

#[map(name = "TCP_IP_V4")]
pub static mut TCP_IP_V4: HashMap<[u8; 4], u16> =
    HashMap::<[u8; 4], u16>::with_max_entries(PACKETS_MAP_SIZE, 0);

#[map(name = "UDP_IP_V4")]
pub static mut UDP_IP_V4: HashMap<[u8; 4], u16> =
    HashMap::<[u8; 4], u16>::with_max_entries(PACKETS_MAP_SIZE, 0);

#[map(name = "TCP_IP_V6")]
pub static mut TCP_IP_V6: HashMap<[u16; 8], u16> =
    HashMap::<[u16; 8], u16>::with_max_entries(PACKETS_MAP_SIZE, 0);

#[map(name = "UDP_IP_V6")]
pub static mut UDP_IP_V6: HashMap<[u16; 8], u16> =
    HashMap::<[u16; 8], u16>::with_max_entries(PACKETS_MAP_SIZE, 0);

pub fn add_v4<'a>(ip_proto: IpProto, ip: &[u8; 4], port: &u16) -> Result<(), &'a str> {
    // Converting IP and Port from Network's endianness to host's endianness
    let ip = ipv4_from_be(ip);
    let port = u16::from_be(*port);

    match unsafe { USE_CUSTOM_PORTS.get(0) } {
        Some(use_custom_ports) => {
            if *use_custom_ports == 1 {
                if unsafe { CUSTOM_PORTS.get(&port).is_some() } {
                    match ip_proto {
                        IpProto::Tcp => {
                            if unsafe { TCP_IP_V4.get(&ip).is_none() } {
                                match unsafe { TCP_IP_V4.insert(&ip, &port, 0) } {
                                    Ok(_) => {}
                                    Err(_) => return Err("failed to insert into TCP_IP_V4"),
                                }
                            }
                        }
                        IpProto::Udp => {
                            if unsafe { UDP_IP_V4.get(&ip).is_none() } {
                                match unsafe { UDP_IP_V4.insert(&ip, &port, 0) } {
                                    Ok(_) => {}
                                    Err(_) => return Err("failed to insert into UDP_IP_V4"),
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                match ip_proto {
                    IpProto::Tcp => {
                        if unsafe { TCP_IP_V4.get(&ip).is_none() } {
                            match unsafe { TCP_IP_V4.insert(&ip, &port, 0) } {
                                Ok(_) => {}
                                Err(_) => return Err("failed to insert into TCP_IP_V4"),
                            }
                        }
                    }
                    IpProto::Udp => {
                        if unsafe { UDP_IP_V4.get(&ip).is_none() } {
                            match unsafe { UDP_IP_V4.insert(&ip, &port, 0) } {
                                Ok(_) => {}
                                Err(_) => return Err("failed to insert into UDP_IP_V4"),
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        None => return Err("failed to get element 0 from USE_CUSTOM_PORTS array"),
    }

    Ok(())
}

pub fn add_v6<'a>(ip_proto: IpProto, ip: &[u16; 8], port: &u16) -> Result<(), &'a str> {
    // Converting IP and Port from Network's endianness to host's endianness
    let ip = ipv6_from_be(ip);
    let port = u16::from_be(*port);

    match unsafe { USE_CUSTOM_PORTS.get(0) } {
        Some(use_custom_ports) => {
            if *use_custom_ports == 1 {
                if unsafe { CUSTOM_PORTS.get(&port).is_some() } {
                    match ip_proto {
                        IpProto::Tcp => {
                            if unsafe { TCP_IP_V6.get(&ip).is_none() } {
                                match unsafe { TCP_IP_V6.insert(&ip, &port, 0) } {
                                    Ok(_) => {}
                                    Err(_) => return Err("failed to insert into TCP_IP_V6"),
                                }
                            }
                        }
                        IpProto::Udp => {
                            if unsafe { UDP_IP_V6.get(&ip).is_none() } {
                                match unsafe { UDP_IP_V6.insert(&ip, &port, 0) } {
                                    Ok(_) => {}
                                    Err(_) => return Err("failed to insert into UDP_IP_V6"),
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                match ip_proto {
                    IpProto::Tcp => {
                        if unsafe { TCP_IP_V6.get(&ip).is_none() } {
                            match unsafe { TCP_IP_V6.insert(&ip, &port, 0) } {
                                Ok(_) => {}
                                Err(_) => return Err("failed to insert into TCP_IP_V6"),
                            }
                        }
                    }
                    IpProto::Udp => {
                        if unsafe { UDP_IP_V6.get(&ip).is_none() } {
                            match unsafe { UDP_IP_V6.insert(&ip, &port, 0) } {
                                Ok(_) => {}
                                Err(_) => return Err("failed to insert into UDP_IP_V6"),
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        None => return Err("failed to get element 0 from USE_CUSTOM_PORTS array"),
    }

    Ok(())
}

/// Converts an array of type [u16; 8] (IPv6) from big endian to the target's endianness
fn ipv6_from_be(ipv6: &[u16; 8]) -> [u16; 8] {
    let mut ip_tmp: [u16; 8] = [0u16; 8];

    for (i, ip) in ipv6.iter().enumerate() {
        ip_tmp[i] = u16::from_be(*ip)
    }

    ip_tmp
}
/// Converts an array of type [u8; 4] (IPv4) from big endian to the target's endianness
fn ipv4_from_be(ipv6: &[u8; 4]) -> [u8; 4] {
    let mut ip_tmp: [u8; 4] = [0u8; 4];

    for (i, ip) in ipv6.iter().enumerate() {
        ip_tmp[i] = u8::from_be(*ip)
    }

    ip_tmp
}
