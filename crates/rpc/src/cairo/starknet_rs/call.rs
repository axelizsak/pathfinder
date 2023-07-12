use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{
    BlockNumber, BlockTimestamp, CallParam, CallResultValue, ChainId, ContractAddress, EntryPoint,
    SequencerAddress, StateUpdate,
};
use stark_hash::Felt;
use starknet_in_rust::execution::execution_entry_point::ExecutionEntryPoint;
use starknet_in_rust::execution::TransactionExecutionContext;

use starknet_in_rust::state::cached_state::CachedState;
use starknet_in_rust::state::ExecutionResourcesManager;
use starknet_in_rust::utils::Address;
use starknet_in_rust::{felt::Felt252, EntryPointType};

use super::{error::CallError, state_reader::PathfinderStateReader};

pub fn call(
    storage: pathfinder_storage::Storage,
    chain_id: ChainId,
    block_number: BlockNumber,
    block_timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    state_at_block: Option<BlockNumber>,
    contract_address: ContractAddress,
    entry_point_selector: EntryPoint,
    calldata: Vec<CallParam>,
    pending_update: Option<Arc<StateUpdate>>,
) -> Result<Vec<CallResultValue>, CallError> {
    let state_reader = PathfinderStateReader {
        storage,
        block_number: state_at_block,
    };

    let contract_class_cache = HashMap::new();
    let casm_class_cache = HashMap::new();
    let mut state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_class_cache),
    );

    pending_update.map(|pending_update| {
        super::pending::apply_pending_update(&mut state, pending_update.as_ref())
    });

    let contract_address = Address(Felt252::from_bytes_be(contract_address.get().as_be_bytes()));
    let calldata = calldata
        .iter()
        .map(|p| Felt252::from_bytes_be(p.0.as_be_bytes()))
        .collect();
    let entry_point_selector = Felt252::from_bytes_be(entry_point_selector.0.as_be_bytes());
    let caller_address = Address(0.into());
    let exec_entry_point = ExecutionEntryPoint::new(
        contract_address,
        calldata,
        entry_point_selector,
        caller_address.clone(),
        EntryPointType::External,
        None,
        None,
        0,
    );

    let block_context = super::block_context::construct_block_context(
        chain_id,
        block_number,
        block_timestamp,
        sequencer_address,
        1.into(),
    )?;

    let mut execution_context = TransactionExecutionContext::new(
        caller_address,
        0.into(),
        Vec::new(),
        0,
        1.into(),
        block_context.invoke_tx_max_n_steps(),
        1.into(),
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    let call_info = exec_entry_point.execute(
        &mut state,
        &block_context,
        &mut resources_manager,
        &mut execution_context,
        false,
    )?;

    let result = call_info
        .retdata
        .iter()
        .map(|f| Felt::from_be_slice(&f.to_bytes_be()).map(CallResultValue))
        .collect::<Result<Vec<CallResultValue>, _>>()
        .context("Converting results to felts")?;

    Ok(result)
}
