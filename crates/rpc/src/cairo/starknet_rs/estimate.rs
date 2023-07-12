use std::collections::HashMap;

use pathfinder_common::{BlockNumber, BlockTimestamp, ChainId, EthereumAddress, SequencerAddress};
use primitive_types::U256;

use stark_hash::Felt;
use starknet_in_rust::state::cached_state::CachedState;

use starknet_in_rust::transaction::error::TransactionError;
use starknet_in_rust::transaction::fee::calculate_tx_fee;
use starknet_in_rust::transaction::{L1Handler, Transaction};

use crate::v02::method::call::FunctionCall;
use crate::v02::types::request::BroadcastedTransaction;

use crate::cairo::ext_py::types::FeeEstimate;

use super::state_reader::PathfinderStateReader;
use super::transaction::{map_broadcasted_transaction, map_gateway_transaction};
use super::{block_context::construct_block_context, error::CallError};

pub fn estimate_fee(
    storage: pathfinder_storage::Storage,
    chain_id: ChainId,
    block_number: BlockNumber,
    block_timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    state_at_block: Option<BlockNumber>,
    gas_price: U256,
    transactions: Vec<BroadcastedTransaction>,
) -> Result<Vec<FeeEstimate>, CallError> {
    let transactions = transactions
        .into_iter()
        .map(|tx| map_broadcasted_transaction(tx, chain_id))
        .collect::<Result<Vec<_>, TransactionError>>()?;

    estimate_fee_impl(
        storage,
        chain_id,
        block_number,
        block_timestamp,
        sequencer_address,
        state_at_block,
        gas_price,
        transactions,
    )
}

pub fn estimate_fee_for_gateway_transactions(
    storage: pathfinder_storage::Storage,
    chain_id: ChainId,
    block_number: BlockNumber,
    block_timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    state_at_block: Option<BlockNumber>,
    gas_price: U256,
    transactions: Vec<starknet_gateway_types::reply::transaction::Transaction>,
) -> anyhow::Result<Vec<FeeEstimate>> {
    let mut db = storage.connection()?;
    let db_tx = db.transaction()?;

    let transactions = transactions
        .into_iter()
        .map(|tx| map_gateway_transaction(tx, chain_id, &db_tx))
        .collect::<Result<Vec<_>, _>>()?;

    drop(db_tx);

    let result = estimate_fee_impl(
        storage,
        chain_id,
        block_number,
        block_timestamp,
        sequencer_address,
        state_at_block,
        gas_price,
        transactions,
    )
    .map_err(|e| anyhow::anyhow!("Estimate fee failed: {:?}", e))?;

    Ok(result)
}

pub fn estimate_message_fee(
    storage: pathfinder_storage::Storage,
    chain_id: ChainId,
    block_number: BlockNumber,
    block_timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    state_at_block: Option<BlockNumber>,
    gas_price: U256,
    message: FunctionCall,
    sender_address: EthereumAddress,
) -> Result<FeeEstimate, CallError> {
    // prepend sender address to calldata
    let sender_address =
        Felt::from_be_slice(sender_address.0.as_bytes()).expect("Ethereum address is 160 bits");
    let calldata = std::iter::once(pathfinder_common::CallParam(sender_address))
        .chain(message.calldata.into_iter())
        .map(|p| p.0.into())
        .collect();

    let transaction = L1Handler::new(
        starknet_in_rust::utils::Address(message.contract_address.get().into()),
        message.entry_point_selector.0.into(),
        calldata,
        0.into(),
        chain_id.0.into(),
        None,
    )?;
    let transaction = Transaction::L1Handler(transaction);

    let mut result = estimate_fee_impl(
        storage,
        chain_id,
        block_number,
        block_timestamp,
        sequencer_address,
        state_at_block,
        gas_price,
        vec![transaction],
    )?;

    if result.len() != 1 {
        return Err(
            anyhow::anyhow!("Internal error: expected exactly one fee estimation result").into(),
        );
    }

    let result = result.pop().unwrap();

    Ok(result)
}

fn estimate_fee_impl(
    storage: pathfinder_storage::Storage,
    chain_id: ChainId,
    block_number: BlockNumber,
    block_timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    state_at_block: Option<BlockNumber>,
    gas_price: U256,
    transactions: Vec<Transaction>,
) -> Result<Vec<FeeEstimate>, CallError> {
    let state_reader = PathfinderStateReader {
        storage,
        block_number: state_at_block,
    };

    let block_context = construct_block_context(
        chain_id,
        block_number,
        block_timestamp,
        sequencer_address,
        gas_price,
    )?;

    let contract_class_cache = HashMap::new();
    let casm_class_cache = HashMap::new();
    let mut cached_state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_class_cache),
    );

    let mut fees = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.iter().enumerate() {
        let span = tracing::debug_span!("execute", transaction_hash=%super::transaction::transaction_hash(transaction), %block_number, %transaction_idx);
        let _enter = span.enter();

        // tracing::trace!(?transaction, "Estimating transaction");

        let transaction_for_simulation = transaction.create_for_simulation(false, false, true);
        let tx_info =
            transaction_for_simulation.execute(&mut cached_state, &block_context, 1_000_000);

        match tx_info {
            Ok(tx_info) => {
                tracing::trace!(actual_fee=%tx_info.actual_fee, "Transaction estimation finished");
                // L1Handler transactions don't normally calculate the fee -- we have to do that after execution.
                let actual_fee = match transaction {
                    Transaction::L1Handler(_) => calculate_tx_fee(
                        &tx_info.actual_resources,
                        gas_price.as_u128(),
                        &block_context,
                    )?,
                    _ => tx_info.actual_fee,
                };

                fees.push(FeeEstimate {
                    gas_consumed: U256::from(actual_fee) / std::cmp::max(1.into(), gas_price),
                    gas_price,
                    overall_fee: actual_fee.into(),
                });
            }
            Err(error) => {
                tracing::error!(%error, %transaction_idx, "Transaction estimation failed");
                return Err(error.into());
            }
        }
    }
    Ok(fees)
}
