use anyhow::Context;
use aya::{ maps::HashMap, programs::{Xdp, XdpFlags},};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;
use std::net::Ipv4Addr;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens33")]
    iface: String, 
    /// List of IPv4 addresses to block
    #[clap(short, long, value_parser)]
    block: Vec<Ipv4Addr>,
}

#[tokio::main] 
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    // 
    // 
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/myapp"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut Xdp = bpf.program_mut("myapp").unwrap().try_into()?;
    program.load()?; 
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?; 
    /*let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();
    blocklist.insert(block_addr, 0, 0)?;*/
    //that was hardcoded ip blocking
    for ip in &opt.block {
        let addr: u32 = (*ip).into();
        blocklist.insert(addr, 0, 0)?;
        info!("Added {ip} to blocklist");
    }
    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}