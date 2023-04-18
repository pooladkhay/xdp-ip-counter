use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    hash::Hash,
    sync::{Arc, Mutex},
};

use crate::structs::{L3Proto, L4Proto, LocalMaps};

pub fn generate_mertics(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
) -> Result<String, std::fmt::Error> {
    let local_maps = local_maps.lock().unwrap();
    let mut metrics_buffer = String::new();

    metrics_buffer
        .write_str("# HELP active_users Number of users actively hitting on a specific port.\n")?;

    metrics_buffer.write_str("# TYPE active_users counter\n")?;

    metrics_to_buff(
        &mut metrics_buffer,
        &local_maps.tcp_v4,
        L3Proto::Ipv4,
        L4Proto::Tcp,
        &custom_ports,
    )?;
    metrics_to_buff(
        &mut metrics_buffer,
        &local_maps.udp_v4,
        L3Proto::Ipv4,
        L4Proto::Udp,
        &custom_ports,
    )?;
    metrics_to_buff(
        &mut metrics_buffer,
        &local_maps.tcp_v6,
        L3Proto::Ipv6,
        L4Proto::Tcp,
        &custom_ports,
    )?;
    metrics_to_buff(
        &mut metrics_buffer,
        &local_maps.udp_v6,
        L3Proto::Ipv6,
        L4Proto::Udp,
        &custom_ports,
    )?;

    metrics_buffer.write_str("# EOF\n")?;

    Ok(metrics_buffer)
}

fn metrics_to_buff<T>(
    buf: &mut String,
    data: &HashMap<u16, HashSet<T>>,
    l3_proto: L3Proto,
    l4_proto: L4Proto,
    ports: &Option<Vec<u16>>,
) -> Result<(), std::fmt::Error>
where
    T: Eq + Hash,
{
    match ports {
        Some(ports) => {
            for (port, ips) in data.iter() {
                let count = ips.len();
                if ports.contains(&port) {
                    buf.write_str(
                        format!(
                            "active_users{{network=\"{}\",transport=\"{}\",port=\"{}\"}} {}\n",
                            l3_proto, l4_proto, port, count
                        )
                        .as_str(),
                    )?;
                }
            }
        }
        None => {
            for (port, ips) in data.iter() {
                let count = ips.len();
                buf.write_str(
                    format!(
                        "active_users{{network=\"{}\",transport=\"{}\",port=\"{}\"}} {}\n",
                        l3_proto, l4_proto, port, count
                    )
                    .as_str(),
                )?
            }
        }
    }

    Ok(())
}

// Replace it with the prometheus crate.
