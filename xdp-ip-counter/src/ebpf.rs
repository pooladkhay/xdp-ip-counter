use anyhow::Context;
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use log::warn;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};
use tokio::time::{sleep, Duration};

use crate::args::Args;
use crate::map::{LocalMaps, SharedMaps};

pub fn init(args: &Args) -> Bpf {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-ip-counter"
    ))
    .expect("error while loding ebpf bytecode");

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-ip-counter"
    ))
    .expect("error while loding ebpf bytecode");

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf
        .program_mut("xdp_ip_counter")
        .unwrap()
        .try_into()
        .expect("error while getting the program");

    program
        .load()
        .expect("error while loading the ebpf program");
    program
        .attach(&args.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with the provided flag")
        .unwrap();

    bpf
}

pub async fn generate_metrics(
    shared_maps: &mut SharedMaps,
    local_maps: Arc<Mutex<LocalMaps>>,
    aggregate_window: u64,
) {
    // Program reads from ebpf_maps each SAMPLING_SECONDS seconds then clears ebpf maps since their capacity is limited.
    const SAMPLING_SECONDS: u64 = 10;
    let sampling_duration = Duration::from_secs(SAMPLING_SECONDS);

    // Program aggregates final results to be served in prometheus format
    // and clears local maps when aggr_counter >= aggregate_window
    let mut aggr_counter = 0;

    // tcp_map and udp_map are updated each SAMPLING_SECONDS seconds with the data from ebpf_maps.
    // Their is added to local_maps each aggregate_window seconds
    let mut tcp_map: HashMap<u16, HashSet<Ipv4Addr>> = HashMap::new();
    let mut udp_map: HashMap<u16, HashSet<Ipv4Addr>> = HashMap::new();

    // Records ip addresses as u32 to later be used to empty ebpf maps.
    let mut ipv4_u32: HashSet<u32> = HashSet::new();

    loop {
        sleep(sampling_duration).await;

        for i in shared_maps.tcp.iter() {
            let (ip, port) = i.unwrap();
            add_to_map(&mut tcp_map, ip, port);
            ipv4_u32.insert(ip);
        }
        for i in shared_maps.udp.iter() {
            let (ip, port) = i.unwrap();
            add_to_map(&mut udp_map, ip, port);
            ipv4_u32.insert(ip);
        }

        // Removing items from original ebpf maps, each {duration} seconds
        for ip in ipv4_u32.iter() {
            shared_maps.remove_from_tcp(ip);
            shared_maps.remove_from_udp(ip);
        }

        aggr_counter += SAMPLING_SECONDS;
        if aggr_counter >= aggregate_window {
            aggr_counter = 0;

            let mut cd = local_maps.lock().unwrap();
            cd.tcp = tcp_map.clone();
            cd.udp = udp_map.clone();

            tcp_map.clear();
            udp_map.clear();
            ipv4_u32.clear();
        }
    }
}

fn add_to_map(map: &mut HashMap<u16, HashSet<Ipv4Addr>>, ip: u32, port: u16) {
    if map.get(&port).is_some() {
        if let Some(ips) = map.get_mut(&port) {
            ips.insert(Ipv4Addr::from(ip));
        }
    } else {
        let mut ip_set = HashSet::new();
        ip_set.insert(Ipv4Addr::from(ip));
        map.insert(port, ip_set);
    }
}
