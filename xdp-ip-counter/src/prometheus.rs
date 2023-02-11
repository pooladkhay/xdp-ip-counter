use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    hash::Hash,
    sync::{Arc, Mutex},
};

use crate::map::LocalMaps;

pub fn generate_mertics(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
) -> Result<String, std::fmt::Error> {
    let local_maps = local_maps.lock().unwrap();
    let mut metrics_buffer = String::new();

    metrics_buffer
        .write_str("# HELP active_users Number of users actively hitting on a specific port.\n")?;

    metrics_buffer.write_str("# TYPE active_users counter\n")?;

    match custom_ports {
        Some(ports) => {
            let ports = ports.clone();
            metrics_custom_ports(&mut metrics_buffer, &local_maps.tcp_v4, "tcp", &ports)?;
            metrics_custom_ports(&mut metrics_buffer, &local_maps.udp_v4, "udp", &ports)?;
        }
        None => {
            metrics_all_ports(&mut metrics_buffer, &local_maps.tcp_v4, "tcp")?;
            metrics_all_ports(&mut metrics_buffer, &local_maps.udp_v4, "udp")?;
        }
    }

    metrics_buffer.write_str("# EOF\n")?;
    Ok(metrics_buffer)
}

fn metrics_all_ports<T>(
    buf: &mut String,
    data: &HashMap<u16, HashSet<T>>,
    proto: &str,
) -> Result<(), std::fmt::Error>
where
    T: Eq + Hash,
{
    for (port, ips) in data.iter() {
        let count = ips.len();
        buf.write_str(
            format!(
                "active_users{{port=\"{}\",proto=\"{}\"}} {}\n",
                port, proto, count
            )
            .as_str(),
        )?
    }

    Ok(())
}
fn metrics_custom_ports<T>(
    buf: &mut String,
    data: &HashMap<u16, HashSet<T>>,
    proto: &str,
    ports: &Vec<u16>,
) -> Result<(), std::fmt::Error>
where
    T: Eq + Hash,
{
    for (port, ips) in data.iter() {
        let count = ips.len();
        if ports.contains(&port) {
            buf.write_str(
                format!(
                    "active_users{{port=\"{}\",proto=\"{}\"}} {}\n",
                    port, proto, count
                )
                .as_str(),
            )?;
        }
    }

    Ok(())
}

// Replace it with the prometheus crate.
