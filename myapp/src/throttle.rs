use aya::{
    Bpf, 
    maps::LruHashMap
};
use std::{
    env, 
    net::Ipv4Addr, 
    str::FromStr
};
use clap::Parser;


#[repr(C)]
#[derive(Clone, Copy)]
struct TokenBucket {
    tokens: u64,
    last_ns: u64,
    rate_per_ns: u64,
    burst: u64,
}

//for cli arg
#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Opt {

    #[arg(short, long, default_value = "ens33")]
    pub iface: String,

    /// List of IPv4 addresses to throttle
    #[arg(short, long, value_parser)]
    pub ip: Vec<Ipv4Addr>,

    /// Rate in bytes per second (default: 1_000_000 B/s)
    #[arg(long, default_value_t = 1_000_000)]
    pub rate: u64,

    /// Burst size in bytes (default: 100_000 B)
    #[arg(long, default_value_t = 100_000)]
    pub burst: u64,
}

fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    let mut bpf = Bpf::load_file("ebpf/target/bpfel-unknown-none/release/ebpf.o")?;
    let mut map = LruHashMap::<u32, TokenBucket>::try_from(bpf.map_mut("IP_BUCKETS")?)?;

    let rate_per_ns = (opt.rate + 999_999_999) / 1_000_000_000; // ceil division

    for ip in &opt.ip {
        let ip_u32 = u32::from(*ip);
        let tb = TokenBucket {
            tokens: opt.burst,
            last_ns: 0,
            rate_per_ns,
            burst: opt.burst,
        };

        map.insert(ip_u32, tb, 0)?;
        println!(
            "Inserted token bucket for {}: rate={} B/s (~{} B/ns), burst={}",
            ip, opt.rate, rate_per_ns, opt.burst
        );
    }

    if opt.ip.is_empty() {
        println!(
            "No IPs provided, throttle running on iface {} with defaults (rate={} B/s, burst={})",
            opt.iface, opt.rate, opt.burst
        );
    }

    Ok(())
}
