#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const MAP_SIZE: u32 = 10240;

#[map(name = "TCP_IP_PORT_MAP")]
static mut TCP_IP_PORT_MAP: HashMap<u32, u16> = HashMap::<u32, u16>::with_max_entries(MAP_SIZE, 0);

#[map(name = "UDP_IP_PORT_MAP")]
static mut UDP_IP_PORT_MAP: HashMap<u32, u16> = HashMap::<u32, u16>::with_max_entries(MAP_SIZE, 0);

#[xdp(name = "xdp_ip_counter")]
pub fn xdp_ip_counter(ctx: XdpContext) -> u32 {
    match try_xdp_ip_counter(&ctx) {
        Ok(_) => xdp_action::XDP_PASS,
        Err(err) => {
            info!(&ctx, "error: {}", err);
            xdp_action::XDP_PASS
        }
    }
}

fn try_xdp_ip_counter<'a>(ctx: &XdpContext) -> Result<(), &'a str> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(()),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            let port = u16::from_be(unsafe { (*tcphdr).dest });
            add_tcp(&source_addr, &port)?;
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            let port = u16::from_be(unsafe { (*udphdr).dest });
            add_udp(&source_addr, &port)?;
        }
        _ => return Err("only TCP and UDP are supported"),
    };

    Ok(())
}

#[inline(always)]
unsafe fn ptr_at<'a, T>(ctx: &XdpContext, offset: usize) -> Result<*const T, &'a str> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err("out of bounds access");
    }

    Ok((start + offset) as *const T)
}

fn add_tcp<'a>(ip: &u32, port: &u16) -> Result<(), &'a str> {
    if unsafe { TCP_IP_PORT_MAP.get(ip).is_none() } {
        match unsafe { TCP_IP_PORT_MAP.insert(ip, port, 0) } {
            Ok(_) => {}
            Err(_) => return Err("failed to insert into TCP map"),
        }
    }
    Ok(())
}

fn add_udp<'a>(ip: &u32, port: &u16) -> Result<(), &'a str> {
    unsafe {
        if UDP_IP_PORT_MAP.get(ip).is_none() {
            match UDP_IP_PORT_MAP.insert(ip, port, 0) {
                Ok(_) => {}
                Err(_) => return Err("failed to insert into UDP map"),
            }
        }
        Ok(())
    }
}
