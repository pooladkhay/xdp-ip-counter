#![feature(ip)]

use clap::Parser;
use log::info;
use std::sync::{Arc, Mutex};
use tokio::{signal, sync::mpsc};

// mod api;
mod args;
mod ebpf;
mod metrics;
mod structs;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let args = args::Args::parse();
    let ebpf = ebpf::init(&args);
    let mut shared_maps = structs::SharedMaps::new(&ebpf);
    let local_map = Arc::new(Mutex::new(structs::LocalMap::new()));
    let (tx, rx) = mpsc::channel::<bool>(1);

    tokio::spawn({
        let local_map = local_map.clone();
        let aggregate_window = args.parse_window();
        async move { ebpf::collect(&mut shared_maps, local_map, tx, aggregate_window).await }
    });

    // tokio::spawn({
    //     let local_map = local_map.clone();
    //     let custom_ports = args.parse_custom_ports();
    //     async move { metrics::generate(local_map, custom_ports, rx).await }
    // });

    // tokio::spawn({
    //     let _lm = local_map.clone();

    //     let local_maps = local_maps.clone();
    //     let custom_ports = args.parse_custom_ports();
    //     let server_port = args.parse_server_port();
    //     let serve_ip_list = args.serve_ip_list;
    //     async move { api::server::serve(local_maps, custom_ports, server_port, serve_ip_list).await }
    // });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("\nExiting...");
    Ok(())
}
