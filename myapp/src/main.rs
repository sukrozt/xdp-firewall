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
    .route("/block", get(block_page).post(block_ip))
    .route("/unblock", get(unblock_page).post(unblock_ip))
    .nest_service("/ui", ServeDir::new("static")) // <---- serves /ui/block.html
    .with_state(state);

    async fn get_blocklist(
        State(blocklist): State<Arc<Mutex<StdHashMap<Ipv4Addr, u32>>>>,
    ) -> Json<Value> {
        let blocklist = blocklist.lock().await;
        let ips: Vec<String> = blocklist.iter().map(|(k, _)| k.to_string()).collect();
        Json(json!({ "blocklist": ips }))
    }

    use axum::response::Html;

    async fn block_page() -> Html<&'static str> {
            Html(r#"
        <!doctype html>
        <html>
        <body>
            <h1>Block an IP</h1>
            <form id="f">
            <input id="ip" placeholder="e.g. 1.2.3.4" required />
            <button type="submit">Block</button>
            </form>
            <script>
            document.getElementById('f').addEventListener('submit', async (e) => {
                e.preventDefault();
                const ip = document.getElementById('ip').value.trim();
                const res = await fetch('/block', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ ip })
                });
                const data = await res.json();
                alert(JSON.stringify(data));
            });
            </script>
        </body>
        </html>
        "#)
        }

    async fn unblock_page() -> Html<&'static str> {
        Html(r#"
        <!doctype html>
        <html>
        <body>
            <h1>Unblock an IP</h1>
            <form id="f">
            <input id="ip" placeholder="e.g. 1.2.3.4" required />
            <button type="submit">Unblock</button>
            </form>
            <script>
            document.getElementById('f').addEventListener('submit', async (e) => {
                e.preventDefault();
                const ip = document.getElementById('ip').value.trim();
                const res = await fetch('/unblock', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({ ip })
                });
                const data = await res.json();
                alert(JSON.stringify(data));
            });
            </script>
        </body>
        </html>
        "#)
}


    async fn block_ip(
    State(blocklist): State<Arc<Mutex<StdHashMap<Ipv4Addr, u32>>>>,
    AxumJson(payload): AxumJson<IpPayload>,
) -> Json<Value> {
    let ip: Ipv4Addr = match payload.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return Json(json!({"error": "Invalid IP address"})),
    };
    blocklist.lock().await.insert(ip, 0);
    Json(json!({ "status": "blocked", "ip": ip.to_string() }))
}


    async fn unblock_ip(
        State(blocklist): State<Arc<Mutex<StdHashMap<Ipv4Addr, u32>>>>,
        AxumJson(payload): AxumJson<IpPayload>,
    ) -> Json<Value> {
        let ip: Ipv4Addr = match payload.ip.parse() {
            Ok(ip) => ip,
            Err(_) => return Json(json!({"error": "Invalid IP address"})),
        };
        let addr: u32 = ip.into();
        blocklist.lock().await.remove(&ip);
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