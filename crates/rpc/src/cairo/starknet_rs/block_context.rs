use pathfinder_common::ChainId;

use starknet_in_rust::definitions::block_context::{BlockContext, StarknetOsConfig};

use super::ExecutionState;

pub(super) fn construct_block_context(
    execution_state: &ExecutionState,
) -> anyhow::Result<BlockContext> {
    let chain_id = match execution_state.chain_id {
        ChainId::MAINNET => starknet_in_rust::definitions::block_context::StarknetChainId::MainNet,
        ChainId::TESTNET => starknet_in_rust::definitions::block_context::StarknetChainId::TestNet,
        ChainId::TESTNET2 => {
            starknet_in_rust::definitions::block_context::StarknetChainId::TestNet2
        }
        _ => return Err(anyhow::anyhow!("Unsupported chain id")),
    };

    let starknet_os_config = StarknetOsConfig::new(
        chain_id,
        starknet_in_rust::utils::Address(0.into()),
        execution_state.gas_price.as_u128(),
    );

    let mut block_context = BlockContext::default();
    *block_context.starknet_os_config_mut() = starknet_os_config;
    let block_info = block_context.block_info_mut();
    block_info.gas_price = execution_state.gas_price.as_u64();
    block_info.block_number = execution_state.block_number.get();
    block_info.block_timestamp = execution_state.block_timestamp.get();
    block_info.sequencer_address =
        starknet_in_rust::utils::Address(execution_state.sequencer_address.0.into());
    block_info.starknet_version = "0.11.2".to_owned();

    Ok(block_context)
}
