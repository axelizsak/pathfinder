use anyhow::Context;

use crate::{
    cairo::ext_py::types::FeeEstimate, context::RpcContext,
    v02::types::request::BroadcastedTransaction,
};
use pathfinder_common::BlockId;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateFeeInput {
    request: Vec<BroadcastedTransaction>,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError,
    InvalidMessageSelector,
    InvalidCallData
);

impl From<crate::cairo::starknet_rs::CallError> for EstimateFeeError {
    fn from(value: crate::cairo::starknet_rs::CallError) -> Self {
        use crate::cairo::starknet_rs::CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::InvalidMessageSelector,
            Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<Vec<FeeEstimate>, EstimateFeeError> {
    let (gas_price, at_block, _pending_timestamp, _pending_update) =
        super::common::prepare_block(&context, input.block_id).await?;

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    // FIXME: handle pending data
    let block = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction().context("Creating database transaction")?;

        let block = tx
            .block_header(at_block.into())
            .context("Reading block")?
            .ok_or_else(|| EstimateFeeError::BlockNotFound)?;

        Ok::<_, EstimateFeeError>(block)
    })
    .await
    .context("Getting block")??;

    let gas_price = match gas_price {
        crate::cairo::ext_py::GasPriceSource::PastBlock => block.gas_price.0.into(),
        crate::cairo::ext_py::GasPriceSource::Current(c) => c,
    };

    let result = tokio::task::spawn_blocking(move || {
        let result = crate::cairo::starknet_rs::estimate_fee(
            context.storage,
            context.chain_id,
            block.number,
            block.timestamp,
            block.sequencer_address,
            Some(block.number),
            gas_price,
            input.request,
        )?;

        Ok::<_, EstimateFeeError>(result)
    })
    .await
    .context("Executing transaction")??;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransaction;
    use pathfinder_common::{
        felt, BlockHash, CallParam, ContractAddress, Fee, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };
    use stark_hash::Felt;

    mod parsing {
        use super::*;

        fn test_invoke_txn() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                crate::v02::types::request::BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(felt!("0x6")),
                    signature: vec![TransactionSignatureElem(felt!("0x7"))],
                    nonce: TransactionNonce(felt!("0x8")),
                    sender_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                    calldata: vec![CallParam(felt!("0xff"))],
                },
            ))
        }

        #[test]
        fn positional_args() {
            use jsonrpsee::types::Params;

            let positional = r#"[
                [
                    {
                        "type": "INVOKE",
                        "version": "0x100000000000000000000000000000001",
                        "max_fee": "0x6",
                        "signature": [
                            "0x7"
                        ],
                        "nonce": "0x8",
                        "sender_address": "0xaaa",
                        "calldata": [
                            "0xff"
                        ]
                    }
                ],
                { "block_hash": "0xabcde" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named_args = r#"{
                "request": [
                    {
                        "type": "INVOKE",
                        "version": "0x100000000000000000000000000000001",
                        "max_fee": "0x6",
                        "signature": [
                            "0x7"
                        ],
                        "nonce": "0x8",
                        "sender_address": "0xaaa",
                        "calldata": [
                            "0xff"
                        ]
                    }
                ],
                "block_id": { "block_hash": "0xabcde" }
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    // These tests require a mainnet database with the first six blocks.
    mod mainnet {
        use std::sync::Arc;

        use super::*;
        use crate::v02::method::estimate_fee::tests::mainnet::{
            test_storage_with_account, valid_invoke_v1, BLOCK_5,
        };
        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV1,
            BroadcastedDeclareTransactionV2, BroadcastedInvokeTransactionV1,
        };
        use crate::v02::types::{ContractClass, SierraContractClass};
        use pathfinder_common::{felt_bytes, CasmHash, Chain, GasPrice};

        pub(crate) async fn test_context(
        ) -> (tempfile::TempDir, RpcContext, ContractAddress, BlockHash) {
            use pathfinder_common::ChainId;

            let (db_dir, storage, account_address, latest_block_hash, _) =
                test_storage_with_account(GasPrice(1));

            let sync_state = Arc::new(crate::SyncState::default());

            let sequencer = starknet_gateway_client::Client::new(Chain::Mainnet).unwrap();
            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);
            (db_dir, context, account_address, latest_block_hash)
        }

        #[tokio::test]
        async fn no_such_block() {
            let (_db_dir, context, account_address, _) = test_context().await;

            let input = EstimateFeeInput {
                request: vec![valid_invoke_v1(account_address)],
                block_id: BlockId::Hash(BlockHash(felt_bytes!(b"nonexistent"))),
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (_db_dir, context, account_address, _) = test_context().await;

            let mainnet_invoke = valid_invoke_v1(account_address)
                .into_invoke()
                .unwrap()
                .into_v1()
                .unwrap();
            let input = EstimateFeeInput {
                request: vec![BroadcastedTransaction::Invoke(
                    BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                        sender_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
                        ..mainnet_invoke
                    }),
                )],
                block_id: BLOCK_5,
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::ContractNotFound));
        }

        #[tokio::test]
        async fn successful_invoke_v1() {
            let (_db_dir, context, account_address, latest_block_hash) = test_context().await;

            let transaction0 = valid_invoke_v1(account_address);
            let transaction1 = BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                BroadcastedInvokeTransactionV1 {
                    nonce: TransactionNonce(felt!("0x1")),
                    ..transaction0
                        .clone()
                        .into_invoke()
                        .unwrap()
                        .into_v1()
                        .unwrap()
                },
            ));
            let input = EstimateFeeInput {
                request: vec![transaction0, transaction1],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let expected0 = FeeEstimate {
                gas_consumed: 2460.into(),
                gas_price: 1.into(),
                overall_fee: 2460.into(),
            };
            let expected1 = FeeEstimate {
                gas_consumed: 2460.into(),
                gas_price: 1.into(),
                overall_fee: 2460.into(),
            };
            assert_eq!(result, vec![expected0, expected1]);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v1() {
            let (_db_dir, context, account_address, latest_block_hash) = test_context().await;

            let contract_class = {
                let json = starknet_gateway_test_fixtures::class_definitions::CONTRACT_DEFINITION;
                ContractClass::from_definition_bytes(json)
                    .unwrap()
                    .as_cairo()
                    .unwrap()
            };

            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V1(BroadcastedDeclareTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(Felt::from_u64(10_000_000)),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class,
                    sender_address: account_address,
                }),
            );

            let input = EstimateFeeInput {
                request: vec![declare_transaction],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let expected = FeeEstimate {
                gas_consumed: 10.into(),
                gas_price: 1.into(),
                overall_fee: 10.into(),
            };
            assert_eq!(result, vec![expected]);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v2() {
            let (_db_dir, context, account_address, latest_block_hash) = test_context().await;

            let contract_class: SierraContractClass = {
                let definition =
                    starknet_gateway_test_fixtures::class_definitions::CAIRO_1_1_0_RC0_SIERRA;
                ContractClass::from_definition_bytes(definition)
                    .unwrap()
                    .as_sierra()
                    .unwrap()
            };

            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V2(BroadcastedDeclareTransactionV2 {
                    version: TransactionVersion::TWO_WITH_QUERY_VERSION,
                    max_fee: Fee(Felt::from_u64(10_000_000)),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class,
                    sender_address: account_address,
                    // Taken from
                    // https://external.integration.starknet.io/feeder_gateway/get_state_update?blockNumber=289143
                    compiled_class_hash: CasmHash::new_or_panic(felt!(
                        "0xf2056a217cc9cabef54d4b1bceea5a3e8625457cb393698ba507259ed6f3c"
                    )),
                }),
            );

            let input = EstimateFeeInput {
                request: vec![declare_transaction],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let expected = FeeEstimate {
                gas_consumed: 10.into(),
                gas_price: 1.into(),
                overall_fee: 10.into(),
            };
            assert_eq!(result, vec![expected]);
        }
    }
}
