use std::collections::HashMap;

use pathfinder_common::ContractAddress;
use primitive_types::U256;

use stark_hash::Felt;
use starknet_in_rust::state::cached_state::CachedState;
use starknet_in_rust::transaction::error::TransactionError;
use starknet_in_rust::transaction::Transaction;

use crate::cairo::ext_py::types::{
    CallType, Event, FeeEstimate, FunctionInvocation, TransactionSimulation, TransactionTrace,
};
use crate::v02::types::request::BroadcastedTransaction;
use crate::v03::method::simulate_transaction::dto::{EntryPointType, MsgToL1};

use super::state_reader::PathfinderStateReader;
use super::transaction::map_broadcasted_transaction;
use super::{block_context::construct_block_context, error::CallError, ExecutionState};

pub fn simulate(
    execution_state: ExecutionState,
    transactions: Vec<BroadcastedTransaction>,
    skip_validate: bool,
) -> Result<Vec<TransactionSimulation>, CallError> {
    let block_context = construct_block_context(&execution_state)?;

    let transactions = transactions
        .into_iter()
        .map(|tx| map_broadcasted_transaction(tx, execution_state.chain_id))
        .collect::<Result<Vec<_>, TransactionError>>()?;

    let state_reader = PathfinderStateReader {
        storage: execution_state.storage,
        block_number: execution_state.state_at_block,
    };

    let contract_class_cache = HashMap::new();
    let casm_class_cache = HashMap::new();
    let mut cached_state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_class_cache),
    );

    let mut simulations = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.iter().enumerate() {
        let span = tracing::debug_span!("execute", transaction_hash=%super::transaction::transaction_hash(transaction), block_number=%execution_state.block_number);
        let _enter = span.enter();

        // tracing::trace!(?transaction, "Simulating transaction");

        let transaction_for_simulation =
            transaction.create_for_simulation(skip_validate, false, true);
        let tx_info =
            transaction_for_simulation.execute(&mut cached_state, &block_context, 1_000_000);
        match tx_info {
            Ok(tx_info) => {
                tracing::trace!(actual_fee=%tx_info.actual_fee, "Transaction simulation finished");
                simulations.push(TransactionSimulation {
                    fee_estimation: FeeEstimate {
                        gas_consumed: U256::from(tx_info.actual_fee)
                            / std::cmp::max(1.into(), execution_state.gas_price),
                        gas_price: execution_state.gas_price,
                        overall_fee: tx_info.actual_fee.into(),
                    },
                    trace: to_trace(transaction, tx_info)?,
                });
            }
            Err(error) => {
                tracing::error!(%error, %transaction_idx, "Transaction simulation failed");
                return Err(error.into());
            }
        }
    }
    Ok(simulations)
}

fn to_trace(
    transaction: &Transaction,
    execution_info: starknet_in_rust::execution::TransactionExecutionInfo,
) -> Result<TransactionTrace, TransactionError> {
    let validate_invocation = execution_info
        .validate_info
        .map(TryInto::try_into)
        .transpose()?;
    let function_invocation = execution_info
        .call_info
        .map(TryInto::try_into)
        .transpose()?;
    let fee_transfer_invocation = execution_info
        .fee_transfer_info
        .map(TryInto::try_into)
        .transpose()?;

    Ok(TransactionTrace {
        validate_invocation,
        function_invocation,
        fee_transfer_invocation,
        signature: tx_signature(transaction),
    })
}

fn tx_signature(transaction: &Transaction) -> Vec<Felt> {
    let signature = match transaction {
        Transaction::Declare(tx) => tx.signature.as_slice(),
        Transaction::DeclareV2(tx) => tx.signature.as_slice(),
        Transaction::Deploy(_) => &[],
        Transaction::DeployAccount(tx) => tx.signature().as_slice(),
        Transaction::InvokeFunction(tx) => tx.signature().as_slice(),
        Transaction::L1Handler(_) => &[],
    };

    signature.iter().cloned().map(Into::into).collect()
}

impl TryFrom<starknet_in_rust::execution::CallInfo> for FunctionInvocation {
    type Error = TransactionError;

    fn try_from(call_info: starknet_in_rust::execution::CallInfo) -> Result<Self, Self::Error> {
        let messages = call_info
            .get_sorted_l2_to_l1_messages()?
            .into_iter()
            .map(Into::into)
            .collect();

        let internal_calls = call_info
            .internal_calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        let events = call_info.events.into_iter().map(Into::into).collect();

        let result = call_info.retdata.into_iter().map(Into::into).collect();

        Ok(Self {
            calldata: call_info.calldata.into_iter().map(Into::into).collect(),
            contract_address: ContractAddress::new_or_panic(call_info.contract_address.0.into()),
            selector: call_info
                .entry_point_selector
                .map(|s| s.into())
                .unwrap_or(Felt::ZERO),
            call_type: call_info.call_type.map(Into::into),
            caller_address: Some(call_info.caller_address.0.into()),
            internal_calls: Some(internal_calls),
            class_hash: call_info
                .class_hash
                .and_then(|class_hash| Felt::from_be_bytes(class_hash).ok()),
            entry_point_type: call_info.entry_point_type.map(Into::into),
            events: Some(events),
            messages: Some(messages),
            result: Some(result),
        })
    }
}

impl From<starknet_in_rust::execution::CallType> for CallType {
    fn from(value: starknet_in_rust::execution::CallType) -> Self {
        match value {
            starknet_in_rust::execution::CallType::Call => CallType::Call,
            starknet_in_rust::execution::CallType::Delegate => CallType::Delegate,
        }
    }
}

impl From<starknet_in_rust::services::api::contract_classes::deprecated_contract_class::EntryPointType> for EntryPointType {
    fn from(value: starknet_in_rust::services::api::contract_classes::deprecated_contract_class::EntryPointType) -> Self {
        match value {
            starknet_in_rust::EntryPointType::External => EntryPointType::External,
            starknet_in_rust::EntryPointType::L1Handler => EntryPointType::L1Handler,
            starknet_in_rust::EntryPointType::Constructor => EntryPointType::Constructor,
        }
    }
}

impl From<starknet_in_rust::execution::OrderedEvent> for Event {
    fn from(value: starknet_in_rust::execution::OrderedEvent) -> Self {
        Self {
            order: value.order as i64,
            data: value.data.into_iter().map(Into::into).collect(),
            keys: value.keys.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<starknet_in_rust::execution::L2toL1MessageInfo> for MsgToL1 {
    fn from(value: starknet_in_rust::execution::L2toL1MessageInfo) -> Self {
        Self {
            payload: value.payload.into_iter().map(Into::into).collect(),
            to_address: value.to_address.0.into(),
            from_address: value.from_address.0.into(),
        }
    }
}
