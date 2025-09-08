use anyhow::Context;
use aya::{maps::{HashMap, MapData}, programs::{Xdp, XdpFlags}};
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
    response::Html,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower_http::services::ServeDir;

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

// Shared application state
struct AppState {
    user_blocklist: Mutex<StdHashMap<Ipv4Addr, u32>>,
    bpf: Mutex<aya::Ebpf>, // <-- store bpf here, we'll borrow maps from it inside handlers
}
type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // load BPF
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/myapp"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // load & attach program (do this before moving bpf into AppState)
    let program: &mut Xdp = bpf.program_mut("myapp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    // build shared state (move bpf into it)
    let state = Arc::new(AppState {
        user_blocklist: Mutex::new(StdHashMap::new()),
        bpf: Mutex::new(bpf),
    });

    // Add initial IPs to both user-side and ebpf map
    {
        // userspace map
        let mut users = state.user_blocklist.lock().await;
        for ip in &opt.block {
            users.insert(*ip, 0);
            info!("Added {ip} to user blocklist");
        }
        drop(users);

        // ebpf map
        let mut bpf_guard = state.bpf.lock().await;
        let map_opt = bpf_guard.map_mut("BLOCKLIST");
        if let Some(map_data) = map_opt {
            let mut ebpf_map = HashMap::try_from(map_data)?;
            for ip in &opt.block {
                let addr: u32 = (*ip).into();
                ebpf_map.insert(addr, 0, 0)?;
                info!("Added {ip} to ebpf blocklist");
            }
        } else {
            warn!("BLOCKLIST map not found in BPF object");
        }
    }

    // build router
    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("../static/index.html")) }))
        .route("/blocklist", get(|| async { Html(include_str!("../static/blocklist.html")) }),)
        .route("/api/blocklist", get(get_blocklist))
        .route("/block", get(|| async { Html(include_str!("../static/block.html")) }).post(block_ip))
        .route("/unblock", get(|| async { Html(include_str!("../static/unblock.html")) }).post(unblock_ip))
        .nest_service("/ui", ServeDir::new("static"))
        
        .with_state(state.clone());

    async fn get_blocklist(
        State(state): State<SharedState>,
    ) -> Json<Value> {
        let bl = state.user_blocklist.lock().await;
        let ips: Vec<String> = bl.iter().map(|(k, _)| k.to_string()).collect();
        Json(json!({ "blocklist": ips }))
    }

    async fn block_ip(
        State(state): State<SharedState>,
        AxumJson(payload): AxumJson<IpPayload>,
    ) -> Json<Value> {
        let ip: Ipv4Addr = match payload.ip.parse() {
            Ok(ip) => ip,
            Err(_) => return Json(json!({"error": "Invalid IP address"})),
        };

        // update userspace copy
        state.user_blocklist.lock().await.insert(ip, 0);

        // update ebpf map
        let addr: u32 = ip.into();
        let mut bpf_guard = state.bpf.lock().await;
        let map_opt = bpf_guard.map_mut("BLOCKLIST");
        let map_data = match map_opt {
            Some(m) => m,
            None => return Json(json!({"error": "BLOCKLIST map not found"})),
        };
        let mut ebpf_map = match HashMap::try_from(map_data) {
            Ok(m) => m,
            Err(e) => return Json(json!({"error": format!("failed to wrap ebpf map: {e}")})),
        };
        if let Err(e) = ebpf_map.insert(addr, 0, 0) {
            return Json(json!({"error": format!("ebpf insert failed: {e}")}));
        }

        Json(json!({ "status": "blocked", "ip": ip.to_string() }))
    }

    async fn unblock_ip(
    State(state): State<SharedState>,
    AxumJson(payload): AxumJson<IpPayload>,
) -> Json<Value> {
    let ip: Ipv4Addr = match payload.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return Json(json!({"error": "Invalid IP address"})),
    };

    // userspace remove
    state.user_blocklist.lock().await.remove(&ip);

    // ebpf remove
    let addr: u32 = ip.into();
    let mut bpf_guard = state.bpf.lock().await;
    let map_opt = bpf_guard.map_mut("BLOCKLIST");
    let map_data = match map_opt {
        Some(m) => m,
        None => return Json(json!({"error": "BLOCKLIST map not found"})),
    };
    let mut ebpf_map: HashMap<&mut MapData, u32, u32> = match HashMap::try_from(map_data) {
        Ok(m) => m,
        Err(e) => return Json(json!({"error": format!("failed to wrap ebpf map: {e}")})),
    };
    if let Err(e) = ebpf_map.remove(&addr) {
        return Json(json!({"error": format!("ebpf remove failed: {e}")}));
    }

    Json(json!({"status": "unblocked", "ip": ip.to_string()}))
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
