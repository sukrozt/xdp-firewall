use aya::{Ebpf, maps::HashMap, programs::Xdp};
use std::net::Ipv4Addr;
use std::convert::TryInto;

fn main() -> Result<(), anyhow::Error> {
    // Load the compiled eBPF object
    let mut bpf = Ebpf::load_file("target/bpfel-unknown-none/release/xdp-firewall-aya-ebpf")?;

    // Attach the XDP program to the interface (e.g., "eth0")
    let program: &mut Xdp = bpf.program_mut("xdp_firewall_aya")
        .ok_or(anyhow::anyhow!("Program not found"))?
        .try_into()?;
    program.load()?;
    program.attach("eth0", aya::programs::XdpFlags::default())?;

    // Get the map
    let mut blocked_ips: HashMap<_, u32, u8> = HashMap::try_from(
        bpf.map_mut("BLOCKED_IPS").ok_or(anyhow::anyhow!("Map not found"))?
    )?;

    // Example: Block 192.168.1.100
    let ip = Ipv4Addr::new(192, 168, 1, 100);
    let ip_u32 = u32::from(ip).to_be(); // network byte order

    blocked_ips.insert(ip_u32, 1, 0)?;

    println!("Blocked IP: {}", ip);

    Ok(())
}