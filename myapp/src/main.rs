use anyhow::Context;
use aya::{maps::HashMap, programs::{Xdp, XdpFlags}};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;
use std::{net::Ipv4Addr, sync::Arc};
use std::collections::HashMap as StdHashMap;
use axum::{
    extract::State,
    routing::{get, post},
    Router,
    extract::Json as AxumJson,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens33")]
    iface: String,
    /// List of IPv4 addresses to block initially
    #[clap(short, long, value_parser)]
    block: Vec<Ipv4Addr>,
}

#[derive(Deserialize)]
struct IpPayload {
    ip: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();
    let state = Arc::new(Mutex::new(StdHashMap::<Ipv4Addr, u32>::new()));

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/myapp"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut Xdp = bpf.program_mut("myapp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
    let blocklist = Arc::new(Mutex::new(blocklist));

    // Add initial IPs
    {
        let mut bl = blocklist.lock().await;
        for ip in &opt.block {
            let addr: u32 = (*ip).into();
            bl.insert(addr, 0, 0)?;
            info!("Added {ip} to blocklist");
        }
    }

    // Axum routes
    let app = Router::new()
    .route("/", get(|| async { "myapp is running" }))
    .route("/blocklist", get(get_blocklist))
    .with_state(state);
        /*.route("/block", post({
            let blocklist = blocklist.clone();
            move |payload: AxumJson<IpPayload>| {
                let blocklist = blocklist.clone();
                async move {
                    let ip: Ipv4Addr = payload.ip.parse().unwrap();
                    let addr: u32 = ip.into();
                    blocklist.lock().await.insert(addr, 0, 0).unwrap();
                    AxumJson(json!({"status": "blocked", "ip": ip.to_string()}))
                }
            }
        }))
        .route("/unblock", post({
            let blocklist = blocklist.clone();
            move |payload: AxumJson<IpPayload>| {
                let blocklist = blocklist.clone();
                async move {
                    let ip: Ipv4Addr = payload.ip.parse().unwrap();
                    let addr: u32 = ip.into();
                    blocklist.lock().await.remove(&addr).unwrap();
                    AxumJson(json!({"status": "unblocked", "ip": ip.to_string()}))
                }
            }
        }))
        .route("/blocklist", get({
            let blocklist = blocklist.clone();
            move || {
                let ips: Vec<String> = blocklist
                    .iter()
                    .filter_map(|res| {
                        match res {
                            Ok((k, _)) => Some(Ipv4Addr::from(k).to_string()),
                            Err(_) => None,
                        }
                    })
                    .collect();

                async move { Json(json!({ "blocklist": ips })) }
            }
        }))*/
    async fn get_blocklist(
        State(blocklist): State<Arc<Mutex<StdHashMap<Ipv4Addr, u32>>>>,
    ) -> Json<Value> {
        let blocklist = blocklist.lock().await;
        let ips: Vec<String> = blocklist.iter().map(|(k, _)| k.to_string()).collect();
        Json(json!({ "blocklist": ips }))
    }


    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("REST API running on http://0.0.0.0:3000");
    info!("Waiting for Ctrl-C...");

    tokio::select! {
        res = axum::serve(listener, app) => {
            if let Err(err) = res {
                eprintln!("server error: {err}");
            }
        }
        _ = signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down...");
        }
    }

    info!("Exiting...");
    Ok(())

}