use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::state_update::ContractUpdate;
use pathfinder_common::{
    BlockNumber, BlockTimestamp, CallParam, CallResultValue, ChainId, ContractAddress, EntryPoint,
    SequencerAddress, StateUpdate,
};
use stark_hash::Felt;
use starknet_in_rust::core::errors::state_errors::StateError;
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

    pending_update.map(|pending_update| apply_pending_update(&mut state, pending_update.as_ref()));

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

fn apply_pending_update<S: starknet_in_rust::state::state_api::State>(
    state: &mut S,
    pending_update: &StateUpdate,
) -> Result<(), StateError> {
    // NOTE: class _declarations_ are handled during sync. We download and insert new class declarations for the pending block
    // after downloading it -- here we build on the fact that those are already available in the database -- and thus in the state
    // as well...

    let mut address_to_class_hash: HashMap<Address, starknet_in_rust::utils::ClassHash> =
        Default::default();
    let mut address_to_nonce: HashMap<Address, Felt252> = Default::default();
    let mut storage_updates: HashMap<Address, HashMap<Felt252, Felt252>> = Default::default();

    for (
        contract_address,
        ContractUpdate {
            storage,
            class,
            nonce,
        },
    ) in &pending_update.contract_updates
    {
        let contract_address = Address(contract_address.get().into());

        let diff: HashMap<Felt252, Felt252> = storage
            .iter()
            .map(|(address, value)| (address.get().into(), value.0.into()))
            .collect();

        if !diff.is_empty() {
            storage_updates.insert(contract_address.clone(), diff);
        }

        if let Some(class) = class {
            use pathfinder_common::state_update::ContractClassUpdate::*;
            match class {
                Deploy(class_hash) | Replace(class_hash) => {
                    address_to_class_hash
                        .insert(contract_address.clone(), class_hash.0.to_be_bytes());
                }
            };
        }

        if let Some(nonce) = nonce {
            address_to_nonce.insert(contract_address, nonce.0.into());
        }
    }

    state.apply_state_update(&starknet_in_rust::state::StateDiff::new(
        address_to_class_hash,
        address_to_nonce,
        Default::default(),
        storage_updates,
    ))
}
