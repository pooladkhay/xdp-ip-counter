#![feature(ip)]

use clap::Parser;
use log::info;
use std::sync::{Arc, Mutex};
use tokio::signal;

mod api;
mod args;
mod ebpf;
mod structs;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let args = args::Args::parse();

    let ebpf = ebpf::init(&args);

    let mut shared_maps = structs::SharedMaps::new(&ebpf);
    let local_maps = Arc::new(Mutex::new(structs::LocalMaps::new()));

    tokio::spawn({
        let local_maps = local_maps.clone();
        let aggregate_window = args.parse_window();
        async move { ebpf::generate_metrics(&mut shared_maps, local_maps, aggregate_window).await }
    });

    tokio::spawn({
        let local_maps = local_maps.clone();
        let custom_ports = args.parse_custom_ports();
        let server_port = args.parse_server_port();
        let serve_ip_list = args.serve_ip_list;
        async move { api::server::serve(local_maps, custom_ports, server_port, serve_ip_list).await }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("\nExiting...");
    Ok(())
}
