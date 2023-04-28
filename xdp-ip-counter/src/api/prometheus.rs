use std::{
    fmt::Write,
    sync::{Arc, RwLock},
};

use crate::structs::{L4Proto, LocalMap};

pub fn generate_mertics(local_map: Arc<RwLock<LocalMap>>) -> Result<String, std::fmt::Error> {
    let prom_metrics = local_map.read().unwrap();
    let prom_metrics = prom_metrics.get_prom_metrics();
    let mut metrics_buffer = String::new();

    metrics_buffer
        .write_str("# HELP active_users Number of users actively hitting on a specific port.\n")?;

    metrics_buffer.write_str("# TYPE active_users counter\n")?;

    for (l3, l4_ips) in prom_metrics.iter() {
        for (l4, ips) in l4_ips {
            let port = match l4 {
                L4Proto::Tcp(port) => port,
                L4Proto::Udp(port) => port,
            };
            metrics_buffer.write_str(
                format!(
                    "active_users{{network=\"{}\",transport=\"{}\",port=\"{}\"}} {}\n",
                    l3,
                    l4,
                    port,
                    ips.len()
                )
                .as_str(),
            )?;
        }
    }

    metrics_buffer.write_str("# EOF\n")?;

    Ok(metrics_buffer)
}
