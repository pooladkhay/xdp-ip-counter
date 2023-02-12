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
    net::IpAddr,
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

    // tcp_v4 and udp_v4 are updated each SAMPLING_SECONDS seconds with the data from ebpf_maps.
    // Their is added to local_maps each aggregate_window seconds
    let mut tcp_v4_tmp: HashMap<u16, HashSet<IpAddr>> = HashMap::new();
    let mut udp_v4_tmp: HashMap<u16, HashSet<IpAddr>> = HashMap::new();
    let mut tcp_v6_tmp: HashMap<u16, HashSet<IpAddr>> = HashMap::new();
    let mut udp_v6_tmp: HashMap<u16, HashSet<IpAddr>> = HashMap::new();

    // Records ip addresses as in their original type to later be used to empty ebpf maps.
    let mut ipv4_orig: HashSet<[u8; 4]> = HashSet::new();
    let mut ipv6_orig: HashSet<[u16; 8]> = HashSet::new();

    loop {
        sleep(sampling_duration).await;

        for i in shared_maps.tcp_v4.iter() {
            let (ip, port) = i.unwrap();
            add_to_map(&mut tcp_v4_tmp, ip, port);
            ipv4_orig.insert(ip);
        }
        for i in shared_maps.udp_v4.iter() {
            let (ip, port) = i.unwrap();
            add_to_map(&mut udp_v4_tmp, ip, port);
            ipv4_orig.insert(ip);
        }

        for i in shared_maps.tcp_v6.iter() {
            let (ip, port) = i.unwrap();
            add_to_map(&mut tcp_v6_tmp, ip, port);
            ipv6_orig.insert(ip);
        }
        for i in shared_maps.udp_v6.iter() {
            let (ip, port) = i.unwrap();
            add_to_map(&mut udp_v6_tmp, ip, port);
            ipv6_orig.insert(ip);
        }

        // Removing items from original ebpf maps, each {duration} seconds
        for ip in ipv4_orig.iter() {
            shared_maps.remove_from_tcp_v4(ip);
            shared_maps.remove_from_udp_v4(ip);
        }
        for ip in ipv6_orig.iter() {
            shared_maps.remove_from_tcp_v6(ip);
            shared_maps.remove_from_udp_v6(ip);
        }

        aggr_counter += SAMPLING_SECONDS;
        if aggr_counter >= aggregate_window {
            aggr_counter = 0;

            let mut cd = local_maps.lock().unwrap();
            cd.tcp_v4 = tcp_v4_tmp.clone();
            cd.udp_v4 = udp_v4_tmp.clone();
            cd.tcp_v6 = tcp_v6_tmp.clone();
            cd.udp_v6 = udp_v6_tmp.clone();

            tcp_v4_tmp.clear();
            udp_v4_tmp.clear();
            tcp_v6_tmp.clear();
            udp_v6_tmp.clear();
            ipv4_orig.clear();
            ipv6_orig.clear();
        }
    }
}

fn add_to_map<U>(map: &mut HashMap<u16, HashSet<IpAddr>>, ip: U, port: u16)
where
    IpAddr: From<U>,
{
    if map.get(&port).is_some() {
        if let Some(ips) = map.get_mut(&port) {
            ips.insert(IpAddr::from(ip));
        }
    } else {
        let mut ip_set = HashSet::new();
        ip_set.insert(IpAddr::from(ip));
        map.insert(port, ip_set);
    }
}
