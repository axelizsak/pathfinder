use crate::{
    cairo::ext_py::types::{
        FeeEstimate, FunctionInvocation, TransactionSimulation, TransactionTrace,
    },
    cairo::starknet_rs::{CallError, ExecutionState},
    context::RpcContext,
    v02::{
        method::call::FunctionCall,
        types::{reply, request::BroadcastedTransaction},
    },
};

use anyhow::{anyhow, Context};
use pathfinder_common::{BlockId, CallParam, EntryPoint};
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

use super::common::prepare_block;

#[derive(Deserialize, Debug)]
pub struct SimulateTrasactionInput {
    block_id: BlockId,
    // `transactions` used to be called `transaction` in the JSON-RPC 0.3.0 specification.
    #[serde(alias = "transaction")]
    transactions: Vec<BroadcastedTransaction>,
    simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct SimulateTransactionOutput(pub Vec<dto::SimulatedTransaction>);

crate::error::generate_rpc_error_subset!(
    SimulateTransactionError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<CallError> for SimulateTransactionError {
    fn from(value: CallError) -> Self {
        match value {
            CallError::ContractNotFound => Self::ContractNotFound,
            CallError::InvalidMessageSelector => Self::ContractError,
            CallError::Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionOutput, SimulateTransactionError> {
    let (gas_price, at_block, pending_timestamp, pending_update) =
        prepare_block(&context, input.block_id).await?;

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
            .ok_or_else(|| SimulateTransactionError::BlockNotFound)?;

        Ok::<_, SimulateTransactionError>(block)
    })
    .await
    .context("Getting block")??;

    let gas_price = match gas_price {
        crate::cairo::ext_py::GasPriceSource::PastBlock => block.gas_price.0.into(),
        crate::cairo::ext_py::GasPriceSource::Current(c) => c,
    };

    let skip_validate = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipValidate);

    let timestamp = pending_timestamp.unwrap_or(block.timestamp);

    let execution_state = ExecutionState {
        storage: context.storage,
        chain_id: context.chain_id,
        block_number: block.number,
        block_timestamp: timestamp,
        sequencer_address: block.sequencer_address,
        state_at_block: Some(block.number),
        pending_update,
    };

    let span = tracing::Span::current();

    let txs = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        crate::cairo::starknet_rs::simulate(
            execution_state,
            gas_price,
            input.transactions,
            skip_validate,
        )
    })
    .await
    .context("Simulating transaction")??;

    let txs: Result<Vec<dto::SimulatedTransaction>, SimulateTransactionError> =
        txs.into_iter().map(map_tx).collect();
    Ok(SimulateTransactionOutput(txs?))
}

fn map_tx(
    tx: TransactionSimulation,
) -> Result<dto::SimulatedTransaction, SimulateTransactionError> {
    Ok(dto::SimulatedTransaction {
        fee_estimation: Some(map_fee(tx.fee_estimation)),
        transaction_trace: Some(map_trace(tx.trace)?),
    })
}

fn map_fee(fee: FeeEstimate) -> reply::FeeEstimate {
    reply::FeeEstimate {
        gas_consumed: fee.gas_consumed,
        gas_price: fee.gas_price,
        overall_fee: fee.overall_fee,
    }
}

fn map_function_invocation(mut fi: FunctionInvocation) -> dto::FunctionInvocation {
    use crate::cairo::ext_py::types;
    dto::FunctionInvocation {
        call_type: fi.call_type.map(|call_type| match call_type {
            types::CallType::Call => dto::CallType::Call,
            types::CallType::Delegate => dto::CallType::LibraryCall,
        }),
        caller_address: fi.caller_address,
        calls: fi
            .internal_calls
            .take()
            .map(|calls| calls.into_iter().map(map_function_invocation).collect()),
        code_address: fi.class_hash,
        entry_point_type: fi.entry_point_type,
        events: fi.events.map(|events| {
            events
                .into_iter()
                .map(|event| dto::Event {
                    data: event.data,
                    keys: event.keys,
                })
                .collect()
        }),
        messages: fi.messages,
        function_call: FunctionCall {
            calldata: fi.calldata.into_iter().map(CallParam).collect(),
            contract_address: fi.contract_address,
            entry_point_selector: EntryPoint(fi.selector),
        },
        result: fi.result,
    }
}

fn map_trace(
    mut trace: TransactionTrace,
) -> Result<dto::TransactionTrace, SimulateTransactionError> {
    let invocations = (
        trace.validate_invocation.take(),
        trace.function_invocation.take(),
        trace.fee_transfer_invocation.take(),
    );
    match invocations {
        (Some(val), Some(fun), fee)
            if fun.entry_point_type == Some(dto::EntryPointType::Constructor) =>
        {
            Ok(dto::TransactionTrace::DeployAccount(
                dto::DeployAccountTxnTrace {
                    fee_transfer_invocation: fee.map(map_function_invocation),
                    validate_invocation: Some(map_function_invocation(val)),
                    constructor_invocation: Some(map_function_invocation(fun)),
                },
            ))
        }
        (Some(val), Some(fun), fee)
            if fun.entry_point_type == Some(dto::EntryPointType::External) =>
        {
            Ok(dto::TransactionTrace::Invoke(dto::InvokeTxnTrace {
                fee_transfer_invocation: fee.map(map_function_invocation),
                validate_invocation: Some(map_function_invocation(val)),
                execute_invocation: Some(map_function_invocation(fun)),
            }))
        }
        (Some(val), _, fee) => Ok(dto::TransactionTrace::Declare(dto::DeclareTxnTrace {
            fee_transfer_invocation: fee.map(map_function_invocation),
            validate_invocation: Some(map_function_invocation(val)),
        })),
        (_, Some(fun), _) => Ok(dto::TransactionTrace::L1Handler(dto::L1HandlerTxnTrace {
            function_invocation: Some(map_function_invocation(fun)),
        })),
        _ => Err(SimulateTransactionError::Internal(anyhow!(
            "Unmatched transaction trace: '{trace:?}'"
        ))),
    }
}

pub mod dto {
    use serde_with::serde_as;

    use crate::felt::RpcFelt;
    use crate::v02::method::call::FunctionCall;
    use crate::v02::types::reply::FeeEstimate;

    use super::*;

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[serde_with::serde_as]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Signature(#[serde_as(as = "Vec<RpcFelt>")] pub Vec<Felt>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum CallType {
        #[serde(rename = "CALL")]
        Call,
        #[serde(rename = "LIBRARY_CALL")]
        LibraryCall,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum EntryPointType {
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    #[serde_with::serde_as]
    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct FunctionInvocation {
        #[serde(default)]
        pub call_type: Option<CallType>,
        #[serde(default)]
        #[serde_as(as = "Option<RpcFelt>")]
        pub caller_address: Option<Felt>,
        #[serde(default)]
        pub calls: Option<Vec<FunctionInvocation>>,
        #[serde(default)]
        #[serde_as(as = "Option<RpcFelt>")]
        pub code_address: Option<Felt>,
        #[serde(default)]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        pub events: Option<Vec<Event>>,
        #[serde(flatten)]
        pub function_call: FunctionCall,
        #[serde(default)]
        pub messages: Option<Vec<MsgToL1>>,
        #[serde(default)]
        #[serde_as(as = "Option<Vec<RpcFelt>>")]
        pub result: Option<Vec<Felt>>,
    }

    #[serde_with::serde_as]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct MsgToL1 {
        #[serde_as(as = "Vec<RpcFelt>")]
        pub payload: Vec<Felt>,
        #[serde_as(as = "RpcFelt")]
        pub to_address: Felt,
        #[serde_as(as = "RpcFelt")]
        pub from_address: Felt,
    }

    #[serde_with::serde_as]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Event {
        #[serde_as(as = "Vec<RpcFelt>")]
        pub data: Vec<Felt>,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub keys: Vec<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    #[serde(untagged)]
    pub enum TransactionTrace {
        Declare(DeclareTxnTrace),
        DeployAccount(DeployAccountTxnTrace),
        Invoke(InvokeTxnTrace),
        L1Handler(L1HandlerTxnTrace),
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct DeclareTxnTrace {
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct DeployAccountTxnTrace {
        #[serde(default)]
        pub constructor_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        pub execute_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct L1HandlerTxnTrace {
        #[serde(default)]
        pub function_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulatedTransaction {
        #[serde(default)]
        pub fee_estimation: Option<FeeEstimate>,
        #[serde(default)]
        pub transaction_trace: Option<TransactionTrace>,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        felt, BlockHash, BlockHeader, BlockNumber, BlockTimestamp, GasPrice, StateUpdate,
        TransactionVersion,
    };
    use pathfinder_storage::{JournalMode, Storage};
    use starknet_gateway_test_fixtures::class_definitions::{
        DUMMY_ACCOUNT, DUMMY_ACCOUNT_CLASS_HASH,
    };
    use tempfile::tempdir;

    use crate::v02::types::reply::FeeEstimate;

    use super::*;

    #[tokio::test]
    async fn test_simulate_transaction() {
        let dir = tempdir().expect("tempdir");
        let mut db_path = dir.path().to_path_buf();
        db_path.push("db.sqlite");

        let storage = Storage::migrate(db_path, JournalMode::WAL)
            .expect("storage")
            .create_pool(NonZeroU32::new(1).unwrap())
            .unwrap();

        {
            let mut db = storage.connection().unwrap();
            let tx = db.transaction().expect("tx");

            tx.insert_cairo_class(DUMMY_ACCOUNT_CLASS_HASH, DUMMY_ACCOUNT)
                .expect("insert class");

            let header = BlockHeader::builder()
                .with_number(BlockNumber::GENESIS)
                .with_timestamp(BlockTimestamp::new_or_panic(0))
                .finalize_with_hash(BlockHash(felt!("0xb00")));
            tx.insert_block_header(&header).unwrap();

            let block1_number = BlockNumber::GENESIS + 1;
            let block1_hash = BlockHash(felt!("0xb01"));

            let header = BlockHeader::builder()
                .with_number(block1_number)
                .with_timestamp(BlockTimestamp::new_or_panic(1))
                .with_gas_price(GasPrice(1))
                .finalize_with_hash(block1_hash);
            tx.insert_block_header(&header).unwrap();

            let state_update = StateUpdate::default()
                .with_block_hash(block1_hash)
                .with_declared_cairo_class(DUMMY_ACCOUNT_CLASS_HASH);
            tx.insert_state_update(block1_number, &state_update)
                .unwrap();

            tx.commit().unwrap();
        }

        let rpc = RpcContext::for_tests().with_storage(storage);

        let input_json = serde_json::json!({
            "block_id": {"block_number": 1},
            "transaction": [
                {
                    "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                    "max_fee": "0x100000000000",
                    "signature": [
                        "0x296ab4b0b7cb0c6929c4fb1e04b782511dffb049f72a90efe5d53f0515eab88",
                        "0x4e80d8bb98a9baf47f6f0459c2329a5401538576e76436acaf5f56c573c7d77"
                    ],
                    "class_hash": "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
                    "signature": [],
                    "class_hash": DUMMY_ACCOUNT_CLASS_HASH,
                    "nonce": "0x0",
                    "version": "0x100000000000000000000000000000001",
                    "constructor_calldata": [
                        "0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
                    ],
                    "version": TransactionVersion::ONE_WITH_QUERY_VERSION,
                    "constructor_calldata": [],
                    "type": "DEPLOY_ACCOUNT"
                }
            ],
            "simulation_flags": []
        });
        let input = SimulateTrasactionInput::deserialize(&input_json).unwrap();

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            vec![
            SimulatedTransaction {
                fee_estimation: Some(
                    FeeEstimate {
                        gas_consumed: 1236.into(),
                        gas_price: 1.into(),
                        overall_fee: 1236.into(),
                    }
                ),
                transaction_trace: Some(
                    TransactionTrace::DeployAccount(
                        DeployAccountTxnTrace {
                            constructor_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: Some(felt!("0x0")),
                                    calls: Some(vec![]),
                                    code_address: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: Some(EntryPointType::Constructor),
                                    events: Some(vec![]),
                                    function_call: FunctionCall {
                                        calldata: vec![],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"),
                                    },
                                    messages: Some(vec![]),
                                    result: Some(vec![]),
                                },
                            ),
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: Some(felt!("0x0")),
                                    calls: Some(vec![]),
                                    code_address: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: Some(EntryPointType::External),
                                    events: Some(vec![]),
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(DUMMY_ACCOUNT_CLASS_HASH.0),
                                            call_param!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971"),
                                        ],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895"),
                                    },
                                    messages: Some(vec![]),
                                    result: Some(vec![]),
                                },
                            ),
                            fee_transfer_invocation: None,
                        },
                    ),
                ),
            }]
        };

        let result = simulate_transaction(rpc, input).await.expect("result");
        pretty_assertions::assert_eq!(result.0, expected);
    }
}
