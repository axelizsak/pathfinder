mod estimate_fee;
pub(crate) mod estimate_message_fee;
mod get_events;
mod get_state_update;
pub(crate) mod simulate_transaction;

pub(super) use estimate_fee::estimate_fee;
pub(crate) use estimate_message_fee::estimate_message_fee;
pub(super) use get_events::get_events;
pub(super) use get_state_update::get_state_update;
pub(crate) use simulate_transaction::simulate_transaction;

pub(crate) mod common {
    use std::sync::Arc;

    use pathfinder_common::{BlockId, BlockTimestamp, StateUpdate};
    use starknet_gateway_types::pending::PendingData;

    use crate::{
        cairo::{
            ext_py::{BlockHashNumberOrLatest, GasPriceSource},
            starknet_rs::ExecutionState,
        },
        context::RpcContext,
    };

    use anyhow::Context;

    pub enum ExecutionStateError {
        BlockNotFound,
        Internal(anyhow::Error),
    }

    impl From<anyhow::Error> for ExecutionStateError {
        fn from(error: anyhow::Error) -> Self {
            Self::Internal(error)
        }
    }

    pub async fn execution_state(
        context: RpcContext,
        block_id: BlockId,
    ) -> Result<ExecutionState, ExecutionStateError> {
        let (gas_price, at_block, pending_timestamp, pending_update) =
            prepare_block(&context, block_id).await?;

        let storage = context.storage.clone();
        let span = tracing::Span::current();

        let block = tokio::task::spawn_blocking(move || {
            let _g = span.enter();

            let mut db = storage.connection()?;
            let tx = db.transaction().context("Creating database transaction")?;

            let block = tx
                .block_header(at_block.into())
                .context("Reading block")?
                .ok_or_else(|| ExecutionStateError::BlockNotFound)?;

            Ok::<_, ExecutionStateError>(block)
        })
        .await
        .context("Getting block")??;

        let gas_price = match gas_price {
            crate::cairo::ext_py::GasPriceSource::PastBlock => block.gas_price.0.into(),
            crate::cairo::ext_py::GasPriceSource::Current(c) => c,
        };

        let timestamp = pending_timestamp.unwrap_or(block.timestamp);

        let execution_state = ExecutionState {
            storage: context.storage,
            chain_id: context.chain_id,
            block_number: block.number,
            block_timestamp: timestamp,
            sequencer_address: block.sequencer_address,
            state_at_block: Some(block.number),
            gas_price,
            pending_update,
        };

        Ok(execution_state)
    }

    async fn prepare_block(
        context: &RpcContext,
        block_id: BlockId,
    ) -> anyhow::Result<(
        GasPriceSource,
        BlockHashNumberOrLatest,
        Option<BlockTimestamp>,
        Option<Arc<StateUpdate>>,
    )> {
        // discussed during estimateFee work: when user is requesting using block_hash use the
        // gasPrice from the starknet_blocks::gas_price column, otherwise (tags) get the latest
        // eth_gasPrice.
        //
        // the fact that [`base_block_and_pending_for_call`] transforms pending cases to use
        // actual parent blocks by hash is an internal transformation we do for correctness,
        // unrelated to this consideration.
        let gas_price = if matches!(block_id, BlockId::Pending | BlockId::Latest) {
            let gas_price = match context.eth_gas_price.as_ref() {
                Some(cached) => cached.get().await,
                None => None,
            };

            let gas_price =
                gas_price.ok_or_else(|| anyhow::anyhow!("Current eth_gasPrice is unavailable"))?;

            GasPriceSource::Current(gas_price)
        } else {
            GasPriceSource::PastBlock
        };

        let (when, pending_timestamp, pending_update) =
            base_block_and_pending_for_call(block_id, &context.pending_data).await?;

        Ok((gas_price, when, pending_timestamp, pending_update))
    }

    /// Transforms the request to call or estimate fee at some point in time to the type expected
    /// by [`crate::cairo::starknet_rs`] with the optional, latest pending data.
    async fn base_block_and_pending_for_call(
        at_block: BlockId,
        pending_data: &Option<PendingData>,
    ) -> Result<
        (
            BlockHashNumberOrLatest,
            Option<BlockTimestamp>,
            Option<Arc<StateUpdate>>,
        ),
        anyhow::Error,
    > {
        use crate::cairo::ext_py::Pending;

        match BlockHashNumberOrLatest::try_from(at_block) {
            Ok(when) => Ok((when, None, None)),
            Err(Pending) => {
                // we must have pending_data configured for pending requests, otherwise we fail
                // fast.
                match pending_data {
                    Some(pending) => {
                        // call on this particular parent block hash; if it's not found at query time over
                        // at python, it should fall back to latest and **disregard** the pending data.
                        let pending_on_top_of_a_block = pending
                            .state_update_on_parent_block()
                            .await
                            .map(|(parent_block, timestamp, data)| {
                                (parent_block.into(), Some(timestamp), Some(data))
                            });

                        // if there is no pending data available, just execute on whatever latest.
                        Ok(pending_on_top_of_a_block.unwrap_or((
                            BlockHashNumberOrLatest::Latest,
                            None,
                            None,
                        )))
                    }
                    None => Err(anyhow::anyhow!(
                        "Pending data not supported in this configuration"
                    )),
                }
            }
        }
    }
}
