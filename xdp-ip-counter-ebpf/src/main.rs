#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

mod map;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

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
        EtherType::Ipv4 => count_v4(&ctx)?,
        EtherType::Ipv6 => count_v6(&ctx)?,
        _ => return Ok(()),
    }

    Ok(())
}

fn count_v4<'a>(ctx: &XdpContext) -> Result<(), &'a str> {
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_addr = unsafe { (*ipv4_hdr).src_addr };

    match unsafe { (*ipv4_hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            let port = unsafe { (*tcphdr).dest };
            map::add_v4(IpProto::Tcp, &source_addr, &port)?;
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            let port = unsafe { (*udphdr).dest };
            map::add_v4(IpProto::Udp, &source_addr, &port)?;
        }
        _ => return Err("only TCP and UDP are supported"),
    };

    Ok(())
}

fn count_v6<'a>(ctx: &XdpContext) -> Result<(), &'a str> {
    let ipv6_hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_addr = unsafe { (*ipv6_hdr).src_addr.in6_u.u6_addr16 };

    match unsafe { (*ipv6_hdr).next_hdr } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
            let port = unsafe { (*tcphdr).dest };
            map::add_v6(IpProto::Tcp, &src_addr, &port)?;
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
            let port = unsafe { (*udphdr).dest };
            map::add_v6(IpProto::Udp, &src_addr, &port)?;
        }
        _ => return Err("only TCP and UDP are supported"),
    }

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
