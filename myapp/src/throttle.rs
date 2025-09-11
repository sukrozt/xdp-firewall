use aya::{
    Bpf, 
    maps::LruHashMap
};
use std::{
    env, 
    net::Ipv4Addr, 
    str::FromStr
};

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenBucket {
    tokens: u64,
    last_ns: u64,
    rate_per_ns: u64,
    burst: u64,
}

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <ip> <rate_bytes_per_sec> <burst_bytes>", args[0]);
        std::process::exit(1);
    }

    let ip = Ipv4Addr::from_str(&args[1])
        .expect("invalid IPv4 address format");
    let rate_bytes_per_sec: u64 = args[2].parse().expect("invalid rate");
    let burst: u64 = args[3].parse().expect("invalid burst");

    // convert IP to u32 (host order, like in eBPF map)
    let ip_u32 = u32::from(ip);

    // convert rate/sec into rate/ns (approximate)
    let rate_per_ns = (rate_bytes_per_sec + 999_999_999) / 1_000_000_000; 
    // ceil division to avoid zero for small rates

    let tb = TokenBucket {
        tokens: burst,   // start full
        last_ns: 0,
        rate_per_ns,
        burst,
    };

    let mut bpf = Bpf::load_file("ebpf/target/bpfel-unknown-none/release/ebpf.o")?;
    // attach xdp, etc (omitted)
    let mut map = LruHashMap::<u32, TokenBucket>::try_from(bpf.map_mut("IP_BUCKETS")?)?;

    map.insert(ip_u32, tb, 0)?;

    println!(
        "Inserted token bucket for {}: rate={} B/s (≈{} B/ns), burst={}",
        ip, rate_bytes_per_sec, rate_per_ns, burst
    );
    
    Ok(())
}
