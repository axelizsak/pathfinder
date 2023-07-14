use crate::{
    cairo::starknet_rs::types::TransactionSimulation, cairo::starknet_rs::CallError,
    context::RpcContext, v02::types::request::BroadcastedTransaction,
};

use anyhow::Context;
use pathfinder_common::{BlockId, CallParam, EntryPoint};
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

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

impl From<super::common::ExecutionStateError> for SimulateTransactionError {
    fn from(error: super::common::ExecutionStateError) -> Self {
        match error {
            super::common::ExecutionStateError::BlockNotFound => Self::BlockNotFound,
            super::common::ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionOutput, SimulateTransactionError> {
    let execution_state = super::common::execution_state(context, input.block_id).await?;

    let skip_validate = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipValidate);

    let span = tracing::Span::current();

    let txs = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        crate::cairo::starknet_rs::simulate(execution_state, input.transactions, skip_validate)
    })
    .await
    .context("Simulating transaction")??;

    let txs = txs.into_iter().map(Into::into).collect();
    Ok(SimulateTransactionOutput(txs))
}

pub(crate) mod dto {
    use serde_with::serde_as;

    use crate::felt::RpcFelt;
    use crate::v02::method::call::FunctionCall;
    use crate::v02::types::reply::FeeEstimate;

    use super::*;

    impl From<crate::cairo::starknet_rs::types::FeeEstimate> for FeeEstimate {
        fn from(value: crate::cairo::starknet_rs::types::FeeEstimate) -> Self {
            Self {
                gas_consumed: value.gas_consumed,
                gas_price: value.gas_price,
                overall_fee: value.overall_fee,
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub enum CallType {
        #[serde(rename = "CALL")]
        Call,
        #[serde(rename = "LIBRARY_CALL")]
        LibraryCall,
    }

    impl From<crate::cairo::starknet_rs::types::CallType> for CallType {
        fn from(value: crate::cairo::starknet_rs::types::CallType) -> Self {
            use crate::cairo::starknet_rs::types::CallType::*;
            match value {
                Call => Self::Call,
                Delegate => Self::LibraryCall,
            }
        }
    }

    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub enum EntryPointType {
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    impl From<crate::cairo::starknet_rs::types::EntryPointType> for EntryPointType {
        fn from(value: crate::cairo::starknet_rs::types::EntryPointType) -> Self {
            use crate::cairo::starknet_rs::types::EntryPointType::*;
            match value {
                Constructor => Self::Constructor,
                External => Self::External,
                L1Handler => Self::L1Handler,
            }
        }
    }

    #[serde_with::serde_as]
    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct FunctionInvocation {
        #[serde(default)]
        pub call_type: Option<CallType>,
        #[serde_as(as = "RpcFelt")]
        pub caller_address: Felt,
        #[serde(default)]
        pub calls: Vec<FunctionInvocation>,
        #[serde(default)]
        #[serde_as(as = "Option<RpcFelt>")]
        pub code_address: Option<Felt>,
        #[serde(default)]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        pub events: Vec<Event>,
        #[serde(flatten)]
        pub function_call: FunctionCall,
        #[serde(default)]
        pub messages: Vec<MsgToL1>,
        #[serde(default)]
        #[serde_as(as = "Vec<RpcFelt>")]
        pub result: Vec<Felt>,
    }

    impl From<crate::cairo::starknet_rs::types::FunctionInvocation> for FunctionInvocation {
        fn from(fi: crate::cairo::starknet_rs::types::FunctionInvocation) -> Self {
            Self {
                call_type: fi.call_type.map(Into::into),
                caller_address: fi.caller_address,
                calls: fi.internal_calls.into_iter().map(Into::into).collect(),
                code_address: fi.class_hash,
                entry_point_type: fi.entry_point_type.map(Into::into),
                events: fi.events.into_iter().map(Into::into).collect(),
                function_call: FunctionCall {
                    contract_address: fi.contract_address,
                    entry_point_selector: EntryPoint(fi.selector),
                    calldata: fi.calldata.into_iter().map(CallParam).collect(),
                },
                messages: fi.messages.into_iter().map(Into::into).collect(),
                result: fi.result.into_iter().map(Into::into).collect(),
            }
        }
    }

    #[serde_with::serde_as]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct MsgToL1 {
        #[serde_as(as = "Vec<RpcFelt>")]
        pub payload: Vec<Felt>,
        #[serde_as(as = "RpcFelt")]
        pub to_address: Felt,
        #[serde_as(as = "RpcFelt")]
        pub from_address: Felt,
    }

    impl From<crate::cairo::starknet_rs::types::MsgToL1> for MsgToL1 {
        fn from(value: crate::cairo::starknet_rs::types::MsgToL1) -> Self {
            Self {
                payload: value.payload,
                to_address: value.to_address,
                from_address: value.from_address,
            }
        }
    }

    #[serde_with::serde_as]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct Event {
        #[serde_as(as = "Vec<RpcFelt>")]
        pub data: Vec<Felt>,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub keys: Vec<Felt>,
    }

    impl From<crate::cairo::starknet_rs::types::Event> for Event {
        fn from(value: crate::cairo::starknet_rs::types::Event) -> Self {
            Self {
                data: value.data,
                keys: value.keys,
            }
        }
    }

    #[derive(Debug, Serialize, Eq, PartialEq)]
    #[serde(untagged)]
    pub enum TransactionTrace {
        Declare(DeclareTxnTrace),
        DeployAccount(DeployAccountTxnTrace),
        Invoke(InvokeTxnTrace),
        L1Handler(L1HandlerTxnTrace),
    }

    impl From<crate::cairo::starknet_rs::types::TransactionTrace> for TransactionTrace {
        fn from(trace: crate::cairo::starknet_rs::types::TransactionTrace) -> Self {
            use crate::cairo::starknet_rs::types::TransactionTrace::*;
            match trace {
                Declare(t) => Self::Declare(t.into()),
                DeployAccount(t) => Self::DeployAccount(t.into()),
                Invoke(t) => Self::Invoke(t.into()),
                L1Handler(t) => Self::L1Handler(t.into()),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct DeclareTxnTrace {
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    impl From<crate::cairo::starknet_rs::types::DeclareTransactionTrace> for DeclareTxnTrace {
        fn from(trace: crate::cairo::starknet_rs::types::DeclareTransactionTrace) -> Self {
            Self {
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
                validate_invocation: trace.validate_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct DeployAccountTxnTrace {
        #[serde(default)]
        pub constructor_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    impl From<crate::cairo::starknet_rs::types::DeployAccountTransactionTrace>
        for DeployAccountTxnTrace
    {
        fn from(trace: crate::cairo::starknet_rs::types::DeployAccountTransactionTrace) -> Self {
            Self {
                constructor_invocation: trace.constructor_invocation.map(Into::into),
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
                validate_invocation: trace.validate_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub execute_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
    }

    impl From<crate::cairo::starknet_rs::types::InvokeTransactionTrace> for InvokeTxnTrace {
        fn from(trace: crate::cairo::starknet_rs::types::InvokeTransactionTrace) -> Self {
            Self {
                validate_invocation: trace.validate_invocation.map(Into::into),
                execute_invocation: trace.execute_invocation.map(Into::into),
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct L1HandlerTxnTrace {
        #[serde(default)]
        pub function_invocation: Option<FunctionInvocation>,
    }

    impl From<crate::cairo::starknet_rs::types::L1HandlerTransactionTrace> for L1HandlerTxnTrace {
        fn from(trace: crate::cairo::starknet_rs::types::L1HandlerTransactionTrace) -> Self {
            Self {
                function_invocation: trace.function_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct SimulatedTransaction {
        pub fee_estimation: FeeEstimate,
        pub transaction_trace: TransactionTrace,
    }

    impl From<TransactionSimulation> for SimulatedTransaction {
        fn from(tx: TransactionSimulation) -> Self {
            dto::SimulatedTransaction {
                fee_estimation: tx.fee_estimation.into(),
                transaction_trace: tx.trace.into(),
            }
        }
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

    use crate::v02::method::call::FunctionCall;
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
            "simulation_flags": [
                "SKIP_VALIDATE"
            ]
        });
        let input = SimulateTrasactionInput::deserialize(&input_json).unwrap();

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            vec![
            SimulatedTransaction {
                fee_estimation:
                    FeeEstimate {
                        gas_consumed: 1236.into(),
                        gas_price: 1.into(),
                        overall_fee: 1236.into(),
                    }
                ,
                transaction_trace:
                    TransactionTrace::DeployAccount(
                        DeployAccountTxnTrace {
                            constructor_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    code_address: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: Some(EntryPointType::Constructor),
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                },
                            ),
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    code_address: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: Some(EntryPointType::External),
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(DUMMY_ACCOUNT_CLASS_HASH.0),
                                            call_param!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971"),
                                        ],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                },
                            ),
                            fee_transfer_invocation: None,
                        },
                    ),
            }]
        };

        let result = simulate_transaction(rpc, input).await.expect("result");
        pretty_assertions::assert_eq!(result.0, expected);
    }
}
