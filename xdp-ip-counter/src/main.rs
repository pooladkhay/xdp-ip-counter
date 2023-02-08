use clap::Parser;
use log::info;
use std::sync::{Arc, Mutex};
use tokio::signal;

mod args;
mod ebpf;
mod map;
mod prometheus;
mod server;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let args = args::Args::parse();

    let ebpf = ebpf::init(&args);
    
    let mut shared_maps = map::SharedMaps::new(&ebpf);
    let local_maps = Arc::new(Mutex::new(map::LocalMaps::new()));

    let lm1 = local_maps.clone();
    let aggregate_window = args.parse_window();
    tokio::spawn(
        async move { ebpf::generate_metrics(&mut shared_maps, lm1, aggregate_window).await },
    );

    let lm2 = local_maps.clone();
    let custom_ports = args.parse_custom_ports();
    let server_port = args.parse_server_port();
    tokio::spawn(async move { server::serve_metrics(lm2, custom_ports, server_port).await });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("\nExiting...");
    Ok(())
}
