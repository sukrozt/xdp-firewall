#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, programs::XdpContext, maps::HashMap};
use aya_log_ebpf::info;
use core::ptr::read_unaligned;

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;

#[map(name = "BLOCKED_IPS")]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    src: u32,
    dst: u32,
}

#[xdp]
pub fn xdp_firewall_aya(ctx: XdpContext) -> u32 {
    match try_xdp_firewall_aya(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall_aya(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    // Check there's enough data for Ethernet header
    if ctx.data_end() - ctx.data() < ETH_HDR_LEN as usize {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse (read) Ethernet header
    let eth_hdr = ctx.data() as *const EthHdr;
    let eth_proto =  u16::from_be((*eth_hdr).ethertype);
    let ethertype_be = unsafe { read_unaligned(&(*eth_hdr).ethertype) };

    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    if ctx.data_end() - ctx.data() < (ETH_HDR_LEN + core::mem::size_of::<Ipv4Hdr>()) as isize {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IPv4 header
    let ip_hdr = (ctx.data() + ETH_HDR_LEN) as *const Ipv4Hdr;
    let src_ip = u32::from_be((*ip_hdr).src);
    let src_be = unsafe { read_unaligned(&(*ip_hdr).src) };


    // Check blocklist map for src_ip
    unsafe {
        
        if BLOCKED_IPS.get(&src_ip).is_some() {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

//panic handler
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
