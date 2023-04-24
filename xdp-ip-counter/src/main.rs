#![feature(ip)]

use clap::Parser;
use log::info;
use std::sync::{Arc, Mutex};
use tokio::signal;

mod api;
// mod api_data;
mod args;
mod ebpf;
mod structs;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let args = args::Args::parse();
    let ebpf = ebpf::init(&args);
    let mut shared_maps = structs::SharedMaps::new(&ebpf);
    let local_map = Arc::new(Mutex::new(structs::LocalMap::new()));

    // Passing custom ports to ebpf side (if there are any)
    match args.parse_custom_ports() {
        Some(ports) => {
            shared_maps.use_custom_ports.set(0, 1, 0)?;
            for port in ports {
                shared_maps.custom_ports.insert(port, 1, 0)?;
            }
        }
        None => {
            shared_maps.use_custom_ports.set(0, 0, 0)?;
        }
    }

    tokio::spawn({
        let local_map = local_map.clone();
        let aggregate_window = args.parse_window();
        async move { ebpf::collect(&mut shared_maps, local_map, aggregate_window).await }
    });

    tokio::spawn({
        let local_map = local_map.clone();
        let server_port = args.parse_server_port();
        let serve_ip_list = args.serve_ip_list;
        async move { api::server::serve(local_map, server_port, serve_ip_list).await }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("\nExiting...");
    Ok(())
}
