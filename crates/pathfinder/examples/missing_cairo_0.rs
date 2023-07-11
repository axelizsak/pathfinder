use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::Chain;
use pathfinder_storage::{JournalMode, Storage};
use starknet_gateway_client::GatewayApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let chain_name = std::env::args().nth(1).unwrap();
    let chain = match chain_name.as_str() {
        "mainnet" => Chain::Mainnet,
        "goerli" => Chain::Testnet,
        "testnet2" => Chain::Testnet2,
        "integration" => Chain::Integration,
        _ => panic!("Expected chain name: mainnet/goerli/testnet2/integration"),
    };

    let database_path = std::env::args().nth(2).unwrap();
    let start_block: u64 = std::env::args().nth(3).unwrap().parse().expect("Integer");
    let storage = Storage::migrate(database_path.into(), JournalMode::WAL)?
        .create_pool(NonZeroU32::new(1).unwrap())
        .unwrap();

    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let latest = {
        let tx = db.transaction().unwrap();
        tx.block_id(pathfinder_storage::BlockId::Latest)
            .context("Fetching latest block number")?
            .context("Latest block number does not exist")?
            .0
    };

    let gateway = starknet_gateway_client::Client::new(chain).unwrap();

    for i in start_block..=latest.get() {
        let cairo_classes = gateway
            .state_update(pathfinder_common::BlockNumber::new_or_panic(i).into())
            .await?
            .declared_cairo_classes
            .into_iter()
            .collect::<Vec<_>>();

        let tx = db.transaction().unwrap();
        let exist = tx.class_definitions_exist(&cairo_classes).unwrap();

        let classes = cairo_classes
            .into_iter()
            .zip(exist.into_iter())
            .filter_map(|(c, exist)| (!exist).then_some(c))
            .collect::<Vec<_>>();

        let count = classes.len();

        for c in classes {
            let def = gateway.class_by_hash(c).await.unwrap();

            tx.insert_cairo_class(c, &def).unwrap();
        }

        tx.commit().unwrap();

        println!("Block {i} - inserted {count} missing classes");
    }

    Ok(())
}
