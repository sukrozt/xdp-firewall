#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, HashMap},
    programs::XdpContext,
};
use aya_bpf::helpers::bpf_ktime_get_ns;
use core::mem;
use core::cmp::min;
use memoffset::offset_of;
use network_types::{ethhdr, iphdr};


#[repr(C)]
pub struct TokenBucket {
    pub tokens: u64,
    pub last_ns: u64,
    pub rate_per_ns: u64,
    pub burst: u64,
}

#[map(name = "IP_BUCKETS")]
static mut IP_BUCKETS: LruHashMap<u32, TokenBucket> = 
    LruHashMap::<u32, TokenBucket>::with_max_entries(4096, 0);

#[inline(always)]
unsafe fn parse_ipv4(ctx: &XdpContext) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // step 1: ethernet header
    let eth = data as *const ethhdr;
    if (eth as usize + mem::size_of::<ethhdr>()) > data_end as usize {
        return None;
    }

    let eth_proto = u16::from_be((*eth).h_proto);
    if eth_proto != 0x0800 {
        // not IPv4
        return None;
    }

    // step 2: ipv4 header
    let ip = (eth.add(1)) as *const iphdr;
    if (ip as usize + mem::size_of::<iphdr>()) > data_end as usize {
        return None;
    }

    Some(u32::from_be((*ip).saddr))
}

#[xdp(name="xdp_throttle")]
pub fn xdp_throttle(ctx: XdpContext) -> u32 {
    match try_xdp_throttle(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_throttle(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    let src_ip = unsafe {
            match parse_ipv4(ctx) {
                Some(ip) => ip,
                None => return Ok(xdp_action::XDP_PASS), // not IPv4, just pass
            }
        };

    let now = bpf_ktime_get_ns(); //curr time in ns
    
    // lookup or init
    let mut bucket = unsafe { IP_BUCKETS.get(&src_ip) };
    if bucket.is_none() {
        let init = TokenBucket { 
            tokens: 0, 
            last_ns: now, 
            rate_per_ns: 0, 
            burst: 0 
        };
        unsafe { IP_BUCKETS.insert(&src_ip, &init, 0)?; }
    }
    let mut b = unsafe { IP_BUCKETS.get_mut(&src_ip).ok_or(0)? };

    // refill
    let elapsed = now.saturating_sub(b.last_ns);
    if elapsed > 0 && b.rate_per_ns > 0 {
        let refill = elapsed.saturating_mul(b.rate_per_ns);
        b.tokens = min(b.tokens.saturating_add(refill), b.burst);
        b.last_ns = now;
    }

    let pkt_len = (data_end as usize).saturating_sub(data as usize) as u64;
    if pkt_len <= b.tokens {
        b.tokens = b.tokens.saturating_sub(pkt_len);
        return Ok(xdp_action::XDP_PASS);
    } else {
        return Ok(xdp_action::XDP_DROP);
    }
}
