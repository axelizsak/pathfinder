use anyhow::Context;
use axum::{routing, Router};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::{net::SocketAddr, time::Duration};

// RUST_LOG=pathfinder_probe=debug ./target/release/pathfinder-probe 0.0.0.0:19999 https://alpha-mainnet.starknet.io http://127.0.0.1:9545 5
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("failed to install recorder");

    let setup = setup()?;
    tracing::debug!(setup=?setup, "pathfinder-probe starting");

    let listen_at: SocketAddr = setup.listen_at.parse().unwrap();
    tracing::info!(server=?listen_at, "pathfinder-probe running");

    tokio::spawn(async move {
        loop {
            if let Err(e) = tick(&setup).await {
                tracing::error!(cause=?e, "Probe failed");
            }
            tokio::time::sleep(setup.poll_delay).await;
        }
    });

    let app = Router::new().route("/metrics", routing::get(|| async move { handle.render() }));

    axum::Server::bind(&listen_at)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

#[derive(Debug)]
struct Setup {
    listen_at: String,
    gateway_url: String,
    pathfinder_url: String,
    poll_delay: Duration,
}

fn setup() -> anyhow::Result<Setup> {
    let args = std::env::args().collect::<Vec<String>>();
    args.get(1)
        .zip(args.get(2))
        .zip(args.get(3))
        .zip(args.get(4))
        .map(|(((listen_at, gateway_url), pathfinder_url), delay_seconds)| Ok(Setup {
            listen_at: listen_at.to_string(),
            gateway_url: gateway_url.to_string(),
            pathfinder_url: pathfinder_url.to_string(),
            poll_delay: Duration::from_secs(delay_seconds.parse().context("Failed to parse <poll-seconds> integer")?),
        }))
        .ok_or(anyhow::anyhow!("Failed to parse arguments: <listen-at> <gateway-url> <pathfinder-url> <poll-delay-seconds>"))?
}

// curl "https://alpha-mainnet.starknet.io/feeder_gateway/get_block?blockNumber=latest" 2>/dev/null | jq '.block_number'
async fn get_gateway_latest(gateway_url: &str) -> anyhow::Result<i64> {
    let json: serde_json::Value = reqwest::ClientBuilder::new()
        .build()?
        .get(&format!(
            "{}/feeder_gateway/get_block?blockNumber=latest",
            gateway_url
        ))
        .send()
        .await?
        .json()
        .await?;

    json["block_number"]
        .as_i64()
        .ok_or(anyhow::anyhow!("Failed to fetch block number"))
}

// curl -H 'Content-type: application/json' -d '{"jsonrpc":"2.0","method":"starknet_blockNumber","params":[],"id":1}' http://127.0.0.1:9000/rpc/v0.3
async fn get_pathfinder_head(pathfinder_url: &str) -> anyhow::Result<i64> {
    let json: serde_json::Value = reqwest::ClientBuilder::new().build()?
        .post(&format!("{}/rpc/v0.3", pathfinder_url))
        .header("Content-type", "application/json")
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"starknet_blockNumber","params":[],"id":1}))
        .send()
        .await?
        .json()
        .await?;

    json["result"]
        .as_i64()
        .ok_or(anyhow::anyhow!("Failed to fetch block number"))
}

async fn tick(setup: &Setup) -> anyhow::Result<()> {
    let gw_head = get_gateway_latest(&setup.gateway_url).await?;
    tracing::debug!(head = gw_head, "gateway");

    let pf_head = get_pathfinder_head(&setup.pathfinder_url).await?;
    tracing::debug!(head = pf_head, "pathfinder");

    metrics::gauge!("gw_head", gw_head as f64);
    metrics::gauge!("pf_head", pf_head as f64);

    let delay = gw_head - pf_head;
    metrics::gauge!("blocks_missing", delay as f64);

    Ok(())
}
