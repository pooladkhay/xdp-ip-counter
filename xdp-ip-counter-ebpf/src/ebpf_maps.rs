use aya_bpf::{macros::map, maps::HashMap};
use network_types::ip::IpProto;

pub const MAP_SIZE: u32 = 10240;

#[map(name = "TCP_IP_V4")]
pub static mut TCP_IP_V4: HashMap<[u8; 4], u16> =
    HashMap::<[u8; 4], u16>::with_max_entries(MAP_SIZE, 0);

#[map(name = "UDP_IP_V4")]
pub static mut UDP_IP_V4: HashMap<[u8; 4], u16> =
    HashMap::<[u8; 4], u16>::with_max_entries(MAP_SIZE, 0);

#[map(name = "TCP_IP_V6")]
pub static mut TCP_IP_V6: HashMap<[u16; 8], u16> =
    HashMap::<[u16; 8], u16>::with_max_entries(MAP_SIZE, 0);

#[map(name = "UDP_IP_V6")]
pub static mut UDP_IP_V6: HashMap<[u16; 8], u16> =
    HashMap::<[u16; 8], u16>::with_max_entries(MAP_SIZE, 0);

pub fn add_v4<'a>(ip_proto: IpProto, ip: &[u8; 4], port: &u16) -> Result<(), &'a str> {
    // Converting IP and Port from Network's endianness to host's endianness
    let ip = ipv4_from_be(ip);
    let port = u16::from_be(*port);

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

    Ok(())
}

pub fn add_v6<'a>(ip_proto: IpProto, ip: &[u16; 8], port: &u16) -> Result<(), &'a str> {
    // Converting IP and Port from Network's endianness to host's endianness
    let ip = ipv6_from_be(ip);
    let port = u16::from_be(*port);

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
