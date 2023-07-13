use std::collections::HashMap;

use anyhow::Context;
use pathfinder_common::{CallParam, CallResultValue, ContractAddress, EntryPoint};
use stark_hash::Felt;
use starknet_in_rust::execution::execution_entry_point::ExecutionEntryPoint;
use starknet_in_rust::execution::TransactionExecutionContext;

use starknet_in_rust::state::cached_state::CachedState;
use starknet_in_rust::state::ExecutionResourcesManager;
use starknet_in_rust::utils::Address;
use starknet_in_rust::{felt::Felt252, EntryPointType};

use super::{error::CallError, state_reader::PathfinderStateReader, ExecutionState};

pub fn call(
    execution_state: ExecutionState,
    contract_address: ContractAddress,
    entry_point_selector: EntryPoint,
    calldata: Vec<CallParam>,
) -> Result<Vec<CallResultValue>, CallError> {
    let block_context = super::block_context::construct_block_context(&execution_state, 1.into())?;

    let state_reader = PathfinderStateReader {
        storage: execution_state.storage,
        block_number: execution_state.state_at_block,
    };

    let contract_class_cache = HashMap::new();
    let casm_class_cache = HashMap::new();
    let mut state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_class_cache),
    );

    execution_state.pending_update.map(|pending_update| {
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
        starknet_in_rust::definitions::constants::INITIAL_GAS_COST,
    );

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
