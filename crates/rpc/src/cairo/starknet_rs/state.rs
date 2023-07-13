use std::sync::Arc;

use pathfinder_common::{BlockNumber, BlockTimestamp, ChainId, SequencerAddress, StateUpdate};

pub struct ExecutionState {
    pub storage: pathfinder_storage::Storage,
    pub chain_id: ChainId,
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,
    pub sequencer_address: SequencerAddress,
    pub state_at_block: Option<BlockNumber>,
    pub pending_update: Option<Arc<StateUpdate>>,
}
