use std::num::NonZeroU32;

use anyhow::Context;
use mimalloc::MiMalloc;
use pathfinder_common::{BlockNumber, BlockTimestamp, ChainId, SequencerAddress};
use pathfinder_storage::{BlockId, JournalMode, Storage};
use primitive_types::U256;
use starknet_gateway_types::reply::transaction::Transaction;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Re-execute transactions in a range of blocks.
///
/// Iterates over specified blocks in the database and re-executes all transactions within
/// those blocks
///
/// Usage:
/// `cargo run --release -p pathfinder --example re_execute ./mainnet.sqlite 50000 51000`
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let n_cpus = num_cpus::get();

    let database_path = std::env::args().nth(1).unwrap();
    let storage = Storage::migrate(database_path.into(), JournalMode::WAL)?
        .create_pool(NonZeroU32::new(n_cpus as u32 * 2).unwrap())?;
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let first_block = std::env::args().nth(2).unwrap();
    let first_block: u64 = first_block.parse().unwrap();

    let (latest_block, chain_id) = {
        let tx = db.transaction().unwrap();
        let (latest_block, _) = tx.block_id(BlockId::Latest)?.unwrap();
        let latest_block = latest_block.get();
        let chain_id = get_chain_id(&tx).unwrap();
        (latest_block, chain_id)
    };

    let last_block = std::env::args()
        .nth(3)
        .map(|s| str::parse(&s).unwrap())
        .unwrap_or(latest_block);

    let (tx, rx) = crossbeam_channel::bounded::<Work>(10);

    let executors = (0..num_cpus::get())
        .map(|_| {
            let storage = storage.clone();
            let rx = rx.clone();
            std::thread::spawn(move || execute(storage, chain_id, rx))
        })
        .collect::<Vec<_>>();

    tracing::info!(%first_block, %last_block, "Re-executing blocks");

    let start_time = std::time::Instant::now();
    let mut num_transactions: usize = 0;

    for block_number in first_block..=last_block {
        let transaction = db.transaction().unwrap();
        let block_id = BlockId::Number(BlockNumber::new_or_panic(block_number));
        let block_header = transaction.block_header(block_id)?.unwrap();
        let transactions_and_receipts = transaction
            .transaction_data_for_block(block_id)?
            .context("Getting transactions for block")?;
        drop(transaction);

        let (transactions, _): (Vec<_>, Vec<_>) = transactions_and_receipts.into_iter().unzip();

        num_transactions += transactions.len();

        tracing::debug!(%block_number, num_transactions=%transactions.len(), "Submitting block");

        let previous_block = if block_number > 0 {
            Some(BlockNumber::new_or_panic(block_number - 1))
        } else {
            None
        };

        tx.send(Work {
            block_number: block_header.number,
            block_timestamp: block_header.timestamp,
            sequencer_address: block_header.sequencer_address,
            state_at_block: previous_block,
            gas_price: block_header.gas_price.0.into(),
            transactions,
        })
        .unwrap();
    }

    drop(tx);

    for executor in executors {
        executor.join().expect("Executor expected to shut down");
    }

    let elapsed = start_time.elapsed().as_millis();

    tracing::debug!(%num_transactions, %elapsed, "Finished");

    Ok(())
}

fn get_chain_id(tx: &pathfinder_storage::Transaction<'_>) -> anyhow::Result<ChainId> {
    use pathfinder_common::consts::{
        INTEGRATION_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET2_GENESIS_HASH, TESTNET_GENESIS_HASH,
    };

    let (_, genesis_hash) = tx
        .block_id(BlockNumber::GENESIS.into())
        .unwrap()
        .context("Getting genesis hash")?;

    let chain = match genesis_hash {
        MAINNET_GENESIS_HASH => ChainId::MAINNET,
        TESTNET_GENESIS_HASH => ChainId::TESTNET,
        TESTNET2_GENESIS_HASH => ChainId::TESTNET2,
        INTEGRATION_GENESIS_HASH => ChainId::INTEGRATION,
        _ => anyhow::bail!("Unknown chain"),
    };

    Ok(chain)
}

#[derive(Debug)]
struct Work {
    block_number: BlockNumber,
    block_timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    state_at_block: Option<BlockNumber>,
    gas_price: U256,
    transactions: Vec<Transaction>,
}

fn execute(storage: Storage, chain_id: ChainId, rx: crossbeam_channel::Receiver<Work>) {
    while let Ok(work) = rx.recv() {
        let start_time = std::time::Instant::now();
        let num_transactions = work.transactions.len();

        match pathfinder_rpc::cairo::starknet_rs::estimate_fee_for_gateway_transactions(
            storage.clone(),
            chain_id,
            work.block_number,
            work.block_timestamp,
            work.sequencer_address,
            work.state_at_block,
            work.gas_price,
            work.transactions,
        ) {
            Ok(_) => {}
            Err(error) => {
                tracing::error!(block_number=%work.block_number, %error, "Transaction re-execution failed");
            }
        }

        let elapsed = start_time.elapsed().as_millis();

        tracing::debug!(block_number=%work.block_number, %num_transactions, %elapsed, "Re-executed block");
    }
}
