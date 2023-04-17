use std::sync::Arc;

use crate::context::RpcContext;
use crate::felt::RpcFelt;
use anyhow::Context;
use pathfinder_common::{
    BlockId, BlockTimestamp, CallParam, CallResultValue, ContractAddress, EntryPoint, StateUpdate,
};
use starknet_gateway_types::pending::PendingData;

crate::error::generate_rpc_error_subset!(
    CallError: BlockNotFound,
    ContractNotFound,
    InvalidMessageSelector,
    InvalidCallData,
    ContractError
);

impl From<starknet_in_rust::transaction::error::TransactionError> for CallError {
    fn from(value: starknet_in_rust::transaction::error::TransactionError) -> Self {
        use starknet_in_rust::transaction::error::TransactionError;
        match value {
            TransactionError::EntryPointNotFound => Self::InvalidMessageSelector,
            TransactionError::FailToReadClassHash => Self::ContractNotFound,
            e => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
        }
    }
}

impl From<crate::cairo::starknet_rs::CallError> for CallError {
    fn from(value: crate::cairo::starknet_rs::CallError) -> Self {
        use crate::cairo::starknet_rs::CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::InvalidMessageSelector,
            Internal(e) => Self::Internal(e),
        }
    }
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct CallInput {
    request: FunctionCall,
    block_id: BlockId,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
pub struct FunctionCall {
    pub contract_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub calldata: Vec<CallParam>,
}

impl From<FunctionCall> for crate::v02::types::request::Call {
    fn from(call: FunctionCall) -> Self {
        Self {
            contract_address: call.contract_address,
            calldata: call.calldata,
            entry_point_selector: Some(call.entry_point_selector),
            // TODO: these fields are estimateFee-only and effectively ignored
            // by the underlying implementation. We can remove these once
            // JSON-RPC v0.1.0 is removed.
            signature: vec![],
            max_fee: Self::DEFAULT_MAX_FEE,
            version: Self::DEFAULT_VERSION,
            nonce: Self::DEFAULT_NONCE,
        }
    }
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct CallOutput(#[serde_as(as = "Vec<RpcFelt>")] Vec<CallResultValue>);

pub async fn call(context: RpcContext, input: CallInput) -> Result<CallOutput, CallError> {
    let (block_id, pending_timestamp, pending_update) =
        base_block_and_pending_for_call(input.block_id, &context.pending_data).await?;

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    // FIXME: handle pending data
    let result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction().context("Creating database transaction")?;

        let block = tx
            .block_header(block_id)
            .context("Reading block")?
            .ok_or_else(|| CallError::BlockNotFound)?;

        let timestamp = pending_timestamp.unwrap_or(block.timestamp);

        let result = crate::cairo::starknet_rs::call(
            context.storage,
            context.chain_id,
            block.number,
            timestamp,
            block.sequencer_address,
            Some(block.number),
            input.request.contract_address,
            input.request.entry_point_selector,
            input.request.calldata,
            pending_update,
        )?;

        Ok(result)
    })
    .await
    .context("Executing call")?;

    result.map(CallOutput)
}

/// Transforms pending requests into latest + optional pending data to apply.
pub(super) async fn base_block_and_pending_for_call(
    at_block: BlockId,
    pending_data: &Option<PendingData>,
) -> Result<
    (
        pathfinder_storage::BlockId,
        Option<BlockTimestamp>,
        Option<Arc<StateUpdate>>,
    ),
    anyhow::Error,
> {
    match at_block {
        BlockId::Pending => {
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
                        pathfinder_storage::BlockId::Latest,
                        None,
                        None,
                    )))
                }
                None => Err(anyhow::anyhow!(
                    "Pending data not supported in this configuration"
                )),
            }
        }
        BlockId::Number(n) => Ok((pathfinder_storage::BlockId::Number(n), None, None)),
        BlockId::Hash(h) => Ok((pathfinder_storage::BlockId::Hash(h), None, None)),
        BlockId::Latest => Ok((pathfinder_storage::BlockId::Latest, None, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pathfinder_common::macro_prelude::*;

    mod parsing {
        use super::*;
        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                { "block_hash": "0xbbbbbbbb" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<CallInput>().unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: contract_address!("0xabcde"),
                    entry_point_selector: entry_point!("0xee"),
                    calldata: vec![call_param!("0x1234"), call_param!("0x2345")],
                },
                block_id: block_hash!("0xbbbbbbbb").into(),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = r#"{
                "request": { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                "block_id": { "block_hash": "0xbbbbbbbb" }
            }"#;
            let named = Params::new(Some(named));

            let input = named.parse::<CallInput>().unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: contract_address!("0xabcde"),
                    entry_point_selector: entry_point!("0xee"),
                    calldata: vec![call_param!("0x1234"), call_param!("0x2345")],
                },
                block_id: block_hash!("0xbbbbbbbb").into(),
            };
            assert_eq!(input, expected);
        }
    }

    mod in_memory {
        use std::sync::Arc;

        use super::*;

        use pathfinder_common::{
            felt, BlockHash, BlockHeader, BlockNumber, BlockTimestamp, Chain, ChainId,
            ContractAddress, GasPrice, StateUpdate, StorageAddress, StorageValue,
        };
        use pathfinder_storage::Storage;
        use starknet_gateway_test_fixtures::class_definitions::{
            CONTRACT_DEFINITION, CONTRACT_DEFINITION_CLASS_HASH,
        };

        async fn test_context() -> (RpcContext, ContractAddress, StorageAddress, StorageValue) {
            let storage = Storage::in_memory().unwrap();
            let mut db = storage.connection().unwrap();
            let tx = db.transaction().unwrap();

            // Empty genesis block
            let header = BlockHeader::builder()
                .with_number(BlockNumber::GENESIS)
                .with_timestamp(BlockTimestamp::new_or_panic(0))
                .finalize_with_hash(BlockHash(felt!("0xb00")));
            tx.insert_block_header(&header).unwrap();

            // Declare & deploy two classes: a dummy account (does no signature verification)
            // and a test class providing an entry point reading from storage
            let block1_number = BlockNumber::GENESIS + 1;
            let block1_hash = BlockHash(felt!("0xb01"));

            tx.insert_cairo_class(CONTRACT_DEFINITION_CLASS_HASH, CONTRACT_DEFINITION)
                .unwrap();

            let header = BlockHeader::builder()
                .with_number(block1_number)
                .with_timestamp(BlockTimestamp::new_or_panic(1))
                .with_gas_price(GasPrice(1))
                .finalize_with_hash(block1_hash);
            tx.insert_block_header(&header).unwrap();

            let test_contract_address = ContractAddress::new_or_panic(felt!("0xc01"));
            let test_contract_key = StorageAddress::new_or_panic(felt!("0x123"));
            let test_contract_value = StorageValue(felt!("0x3"));

            let state_update = StateUpdate::default()
                .with_block_hash(block1_hash)
                .with_declared_cairo_class(CONTRACT_DEFINITION_CLASS_HASH)
                .with_deployed_contract(test_contract_address, CONTRACT_DEFINITION_CLASS_HASH)
                .with_storage_update(
                    test_contract_address,
                    test_contract_key,
                    test_contract_value,
                );
            tx.insert_state_update(block1_number, &state_update)
                .unwrap();

            tx.commit().unwrap();

            let sync_state = Arc::new(crate::SyncState::default());
            let sequencer = starknet_gateway_client::Client::new(Chain::Mainnet).unwrap();

            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);

            (
                context,
                test_contract_address,
                test_contract_key,
                test_contract_value,
            )
        }

        #[tokio::test]
        async fn storage_access() {
            let (context, contract_address, test_key, test_value) = test_context().await;

            let input = CallInput {
                request: FunctionCall {
                    contract_address: contract_address,
                    entry_point_selector: EntryPoint::hashed(b"get_value"),
                    calldata: vec![CallParam(*test_key.get())],
                },
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            };
            let result = call(context, input).await.unwrap();
            assert_eq!(result, CallOutput(vec![CallResultValue(test_value.0)]));
        }
    }

    mod mainnet {
        use super::*;
        use pathfinder_common::Chain;
        use pathfinder_storage::JournalMode;
        use std::num::NonZeroU32;
        use std::path::PathBuf;
        use std::sync::Arc;

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(block_hash!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        ));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_call() -> FunctionCall {
            FunctionCall {
                contract_address: contract_address!(
                    "020cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6"
                ),
                entry_point_selector: entry_point!(
                    "03d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3"
                ),
                calldata: vec![
                    call_param!("e150b6c2db6ed644483b01685571de46d2045f267d437632b508c19f3eb877"),
                    call_param!("0494196e88ce16bff11180d59f3c75e4ba3475d9fba76249ab5f044bcd25add6"),
                ],
            }
        }

        async fn test_context() -> (tempfile::TempDir, RpcContext) {
            use pathfinder_common::ChainId;

            let mut source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            source_path.push("fixtures/mainnet.sqlite");

            let db_dir = tempfile::TempDir::new().unwrap();
            let mut db_path = PathBuf::from(db_dir.path());
            db_path.push("mainnet.sqlite");

            std::fs::copy(&source_path, &db_path).unwrap();

            let storage = pathfinder_storage::Storage::migrate(db_path, JournalMode::WAL)
                .unwrap()
                .create_pool(NonZeroU32::new(10).unwrap())
                .unwrap();
            let sync_state = Arc::new(crate::SyncState::default());

            let sequencer = starknet_gateway_client::Client::new(Chain::Mainnet).unwrap();

            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);
            (db_dir, context)
        }

        #[tokio::test]
        async fn no_such_block() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BlockId::Hash(block_hash_bytes!(b"nonexistent")),
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: FunctionCall {
                    contract_address: contract_address!("0xdeadbeef"),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::ContractNotFound));
        }

        #[tokio::test]
        async fn invalid_message_selector() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: FunctionCall {
                    entry_point_selector: EntryPoint(Default::default()),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::InvalidMessageSelector));
        }

        #[tokio::test]
        async fn successful_call() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BLOCK_5,
            };

            let result = call(context, input).await.unwrap();
            assert_eq!(result.0, vec![]);
        }
    }
}
