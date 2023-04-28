use anyhow::Context;
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use log::warn;
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};
use tokio::time::{sleep, Duration};

use crate::{
    args::Args,
    structs::{L3Proto, L4Proto, LocalMap, SharedMaps},
};

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

pub async fn collect(
    shared_maps: &mut SharedMaps,
    local_map: Arc<RwLock<LocalMap>>,
    aggregate_window: u64,
) {
    // Program reads from ebpf maps (shared maps) to local_map's tmp area each SAMPLING_SECONDS seconds then clears ebpf maps.
    const SAMPLING_SECONDS: u64 = 10;
    let sampling_duration = Duration::from_secs(SAMPLING_SECONDS);

    // Each aggregate_window seconds (when aggr_counter >= aggregate_window), data read to local_map's tmp area is added to local_map's aggr area.
    // The idea is to clear ebps maps every sampling_duration seconds no matter what aggregate_window user wants since ebpf maps' capacities are limited.
    // See the definition of LocalMap for more details.
    let mut aggr_counter = 0;

    // Records ip addresses as in their original type to later be used to empty ebpf maps.
    let mut ipv4_orig: HashSet<[u8; 4]> = HashSet::new();
    let mut ipv6_orig: HashSet<[u16; 8]> = HashSet::new();

    loop {
        sleep(sampling_duration).await;

        for i in shared_maps.get_tcp_v4().iter() {
            let (ip, port) = i.unwrap();
            if let Ok(ref mut map) = local_map.write() {
                map.add_tmp(L3Proto::Ipv4, L4Proto::Tcp(port), ip)
            } else {
                println!("failed")
            }
            ipv4_orig.insert(ip);
        }
        for i in shared_maps.get_udp_v4().iter() {
            let (ip, port) = i.unwrap();
            if let Ok(ref mut map) = local_map.write() {
                map.add_tmp(L3Proto::Ipv4, L4Proto::Udp(port), ip)
            } else {
                println!("failed")
            }
            ipv4_orig.insert(ip);
        }

        for i in shared_maps.get_tcp_v6().iter() {
            let (ip, port) = i.unwrap();
            if let Ok(ref mut map) = local_map.write() {
                map.add_tmp(L3Proto::Ipv6, L4Proto::Tcp(port), ip)
            } else {
                println!("failed")
            }
            ipv6_orig.insert(ip);
        }
        for i in shared_maps.get_udp_v6().iter() {
            let (ip, port) = i.unwrap();
            if let Ok(ref mut map) = local_map.write() {
                map.add_tmp(L3Proto::Ipv6, L4Proto::Udp(port), ip)
            } else {
                println!("failed")
            }
            ipv6_orig.insert(ip);
        }

        // Removing items from original ebpf maps, each {duration} seconds
        for ip in ipv4_orig.iter() {
            shared_maps.remove_from_tcp_v4(ip);
            shared_maps.remove_from_udp_v4(ip);
        }
        ipv4_orig.clear();
        for ip in ipv6_orig.iter() {
            shared_maps.remove_from_tcp_v6(ip);
            shared_maps.remove_from_udp_v6(ip);
        }
        ipv6_orig.clear();

        aggr_counter += SAMPLING_SECONDS;
        if aggr_counter >= aggregate_window {
            aggr_counter = 0;

            if let Ok(ref mut local_map) = local_map.write() {
                local_map.aggr();
            }
        }
    }
}
