//! Sync related data retrieval from other peers
//!
//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a bootstrap node
//! that syncs from the gateway and a "proper" p2p node which only syncs via p2p.

use pathfinder_common::{
    BlockHash, BlockId, BlockNumber, CallParam, CasmHash, ClassHash, ContractAddress,
    ContractAddressSalt, Fee, TransactionHash, TransactionNonce, TransactionSignatureElem,
    TransactionVersion,
};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::reply::{self, Block};
use starknet_gateway_types::request::add_transaction::ContractDefinition;

#[derive(Clone, Debug)]
pub enum Client {
    /// Syncs from the feeder gateway, propagates new headers via p2p
    /// Proxies blockchain data to non propagating nodes via p2p
    ///
    /// Ofc bootstrapping can be split from proxying but let's keep two types
    /// of nodes for PoC
    Bootstrap {
        p2p_client: p2p::Client,
        sequencer: starknet_gateway_client::Client,
    },
    /// Syncs from p2p network
    NonPropagating {
        p2p_client: p2p::Client,
        sequencer: starknet_gateway_client::Client,
        head_receiver: (), // TODO
    },
}

impl Client {
    pub fn new(
        i_am_boot: bool,
        p2p_client: p2p::Client,
        sequencer: starknet_gateway_client::Client,
        head_receiver: (), // TODO
    ) -> Self {
        if i_am_boot {
            Self::Bootstrap {
                p2p_client,
                sequencer,
            }
        } else {
            Self::NonPropagating {
                p2p_client,
                sequencer,
                head_receiver,
            }
        }
    }

    fn as_sequencer(&self) -> &starknet_gateway_client::Client {
        match self {
            Client::Bootstrap { sequencer, .. } => sequencer,
            Client::NonPropagating { sequencer, .. } => sequencer,
        }
    }
}

/// A hacky temporary way to wrap p2p related errors
mod error {
    use starknet_gateway_types::error::{
        KnownStarknetErrorCode, SequencerError, StarknetError, StarknetErrorCode,
    };

    pub fn block_not_found(message: impl ToString) -> SequencerError {
        SequencerError::StarknetError(StarknetError {
            code: StarknetErrorCode::Known(KnownStarknetErrorCode::BlockNotFound),
            message: message.to_string(),
        })
    }

    pub fn class_not_found(message: impl ToString) -> SequencerError {
        SequencerError::StarknetError(StarknetError {
            code: StarknetErrorCode::Known(KnownStarknetErrorCode::UndeclaredClass),
            message: message.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl GatewayApi for Client {
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => sequencer.block(block).await,
            Client::NonPropagating { p2p_client, .. } => match block {
                BlockId::Number(_n) => todo!(),
                BlockId::Latest => {
                    unreachable!("GatewayApi.head() is used in sync and sync status instead")
                }
                BlockId::Hash(_) => unreachable!("not used in sync"),
                BlockId::Pending => {
                    unreachable!("pending should be disabled when p2p is enabled")
                }
            },
        }
    }

    async fn block_without_retry(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingBlock, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => sequencer.block_without_retry(block).await,
            Client::NonPropagating { .. } => unreachable!("used for gas price and not in sync"),
        }
    }

    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => sequencer.class_by_hash(class_hash).await,
            Client::NonPropagating { p2p_client, .. } => todo!(),
        }
    }

    async fn pending_class_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => {
                sequencer.pending_class_by_hash(class_hash).await
            }
            Client::NonPropagating { .. } => {
                unreachable!("pending should be disabled when p2p is enabled")
            }
        }
    }

    async fn transaction(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        self.as_sequencer().transaction(transaction_hash).await
    }

    async fn state_update(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingStateUpdate, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => sequencer.state_update(block).await,
            Client::NonPropagating { p2p_client, .. } => match block {
                BlockId::Hash(hash) => todo!(),
                _ => unreachable!("not used in sync"),
            },
        }
    }

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        self.as_sequencer().eth_contract_addresses().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_invoke_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address: ContractAddress,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        self.as_sequencer()
            .add_invoke_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_address,
                calldata,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_declare_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        compiled_class_hash: Option<CasmHash>,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
        self.as_sequencer()
            .add_declare_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_definition,
                sender_address,
                compiled_class_hash,
                token,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_deploy_account(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address_salt: ContractAddressSalt,
        class_hash: ClassHash,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError> {
        self.as_sequencer()
            .add_deploy_account(
                version,
                max_fee,
                signature,
                nonce,
                contract_address_salt,
                class_hash,
                calldata,
            )
            .await
    }

    /// This is a **temporary** measure to keep the sync logic unchanged
    ///
    /// TODO remove me when sync is changed to use the high level (ie. peer unaware) p2p API
    /// TODO use a block header type which should be in pathfinder_common (?)
    async fn propagate_block_header(&self, _block: &Block) {
        match self {
            Client::Bootstrap { p2p_client, .. } => todo!(),
            Client::NonPropagating { .. } => {
                // This is why it's called non-propagating
            }
        }
    }

    /// This is a **temporary** measure to keep the sync logic unchanged
    ///
    /// TODO remove me when sync is changed to use the high level (ie. peer unaware) p2p API
    async fn head(&self) -> Result<(BlockNumber, BlockHash), SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => Ok(sequencer.head().await?),
            Client::NonPropagating { head_receiver, .. } => todo!(),
        }
    }
}

/// Workaround for the orphan rule - implement conversion fns for types ourside our crate.
pub mod conv {
    pub mod header {
        use pathfinder_common::{
            BlockHash, BlockHeader, BlockNumber, BlockTimestamp, ClassCommitment, EventCommitment,
            GasPrice, SequencerAddress, StarknetVersion, StateCommitment, StorageCommitment,
            TransactionCommitment,
        };

        pub fn from_p2p(header: p2p_proto::common::BlockHeader) -> BlockHeader {
            BlockHeader {
                hash: BlockHash(header.hash),
                parent_hash: BlockHash(header.parent_hash),
                number: BlockNumber::new_or_panic(header.number),
                timestamp: BlockTimestamp::new_or_panic(header.timestamp),
                gas_price: GasPrice::from_be_slice(&header.gas_price.as_be_bytes()[16..])
                    .expect("larger to smaller array is ok"),
                sequencer_address: SequencerAddress(header.sequencer_address),
                starknet_version: StarknetVersion::from(header.starknet_version),
                class_commitment: ClassCommitment::new_or_panic(header.class_commitment),
                event_commitment: EventCommitment(header.event_commitment),
                state_commitment: StateCommitment(header.state_commitment),
                storage_commitment: StorageCommitment(header.storage_commitment),
                transaction_commitment: TransactionCommitment(header.transaction_commitment),
            }
        }
    }

    pub mod body {
        use p2p_proto::common::{BlockBody, Receipt, Transaction};
        use pathfinder_common::{
            CallParam, CasmHash, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
            EntryPoint, Fee, TransactionHash, TransactionNonce, TransactionSignatureElem,
            TransactionVersion,
        };
        use primitive_types::H256;
        use stark_hash::Felt;
        use starknet_gateway_types::reply::transaction::{self as gw, EntryPointType};

        pub fn try_from_p2p(
            body: BlockBody,
        ) -> anyhow::Result<(Vec<gw::Transaction>, Vec<gw::Receipt>)> {
            fn version(felt: Felt) -> u8 {
                felt.to_be_bytes()[31]
            }

            fn entry_point(
                entry_point: Option<p2p_proto::common::invoke_transaction::EntryPoint>,
            ) -> anyhow::Result<(EntryPoint, Option<EntryPointType>)> {
                match entry_point {
                    Some(p2p_proto::common::invoke_transaction::EntryPoint::Unspecified(e)) => {
                        Ok((EntryPoint(e), None))
                    }
                    Some(p2p_proto::common::invoke_transaction::EntryPoint::External(e)) => {
                        Ok((EntryPoint(e), Some(EntryPointType::External)))
                    }
                    Some(p2p_proto::common::invoke_transaction::EntryPoint::L1Handler(e)) => {
                        Ok((EntryPoint(e), Some(EntryPointType::L1Handler)))
                    }
                    None => anyhow::bail!("Missing entry point selector for Invoke v0 transaction"),
                }
            }

            let (gw_t, gw_r) = body
                .transactions
                .into_iter()
                .zip(body.receipts.into_iter())
                .map(|(t, r)| {
                    match (t, &r) {
                        (Transaction::Invoke(t), Receipt::Invoke(r)) => match version(t.version) {
                            0 => {
                                let (entry_point_selector, entry_point_type) =
                                    entry_point(t.deprecated_entry_point_selector)?;

                                Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V0(
                                    gw::InvokeTransactionV0 {
                                        calldata: t.calldata.into_iter().map(CallParam).collect(),
                                        sender_address: ContractAddress::new_or_panic(
                                            t.sender_address,
                                        ),
                                        entry_point_selector,
                                        entry_point_type,
                                        max_fee: Fee(t.max_fee),
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                    },
                                )))
                            }
                            1 => Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V1(
                                gw::InvokeTransactionV1 {
                                    calldata: t.calldata.into_iter().map(CallParam).collect(),
                                    sender_address: ContractAddress::new_or_panic(t.sender_address),
                                    max_fee: Fee(t.max_fee),
                                    signature: t
                                        .signature
                                        .into_iter()
                                        .map(TransactionSignatureElem)
                                        .collect(),
                                    nonce: TransactionNonce(t.nonce),
                                    transaction_hash: TransactionHash(r.common.transaction_hash),
                                },
                            ))),
                            _ => anyhow::bail!("Invalid invoke transaction version {}", t.version),
                        },
                        (Transaction::Declare(t), Receipt::Declare(r)) => {
                            match version(t.version) {
                                0 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V0(
                                    gw::DeclareTransactionV0V1 {
                                        class_hash: ClassHash(t.class_hash),
                                        max_fee: Fee(t.max_fee),
                                        nonce: TransactionNonce(t.nonce),
                                        sender_address: ContractAddress::new_or_panic(
                                            t.sender_address,
                                        ),
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                    },
                                ))),
                                1 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V1(
                                    gw::DeclareTransactionV0V1 {
                                        class_hash: ClassHash(t.class_hash),
                                        max_fee: Fee(t.max_fee),
                                        nonce: TransactionNonce(t.nonce),
                                        sender_address: ContractAddress::new_or_panic(
                                            t.sender_address,
                                        ),
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                    },
                                ))),
                                2 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V2(
                                    gw::DeclareTransactionV2 {
                                        class_hash: ClassHash(t.class_hash),
                                        max_fee: Fee(t.max_fee),
                                        nonce: TransactionNonce(t.nonce),
                                        sender_address: ContractAddress::new_or_panic(
                                            t.sender_address,
                                        ),
                                        signature: t
                                            .signature
                                            .into_iter()
                                            .map(TransactionSignatureElem)
                                            .collect(),
                                        transaction_hash: TransactionHash(
                                            r.common.transaction_hash,
                                        ),
                                        compiled_class_hash: CasmHash(t.casm_hash),
                                    },
                                ))),
                                _ => anyhow::bail!(
                                    "Invalid declare transaction version {}",
                                    t.version
                                ),
                            }
                        }
                        (Transaction::Deploy(t), Receipt::Deploy(r)) => {
                            Ok(gw::Transaction::Deploy(gw::DeployTransaction {
                                contract_address: ContractAddress::new_or_panic(r.contract_address),
                                contract_address_salt: ContractAddressSalt(t.contract_address_salt),
                                class_hash: ClassHash(t.class_hash),
                                constructor_calldata: t
                                    .constructor_calldata
                                    .into_iter()
                                    .map(ConstructorParam)
                                    .collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                                version: TransactionVersion(H256::from_slice(
                                    t.version.as_be_bytes(),
                                )),
                            }))
                        }
                        (Transaction::L1Handler(t), Receipt::L1Handler(r)) => {
                            Ok(gw::Transaction::L1Handler(gw::L1HandlerTransaction {
                                contract_address: ContractAddress::new_or_panic(t.contract_address),
                                entry_point_selector: EntryPoint(t.entry_point_selector),
                                nonce: TransactionNonce(t.nonce),
                                calldata: t.calldata.into_iter().map(CallParam).collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                                version: TransactionVersion(H256::from_slice(
                                    t.version.as_be_bytes(),
                                )),
                            }))
                        }
                        (Transaction::DeployAccount(t), Receipt::DeployAccount(r)) => Ok(
                            gw::Transaction::DeployAccount(gw::DeployAccountTransaction {
                                contract_address: ContractAddress::new_or_panic(r.contract_address),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                                max_fee: Fee(t.max_fee),
                                version: TransactionVersion(H256::from_slice(
                                    t.version.as_be_bytes(),
                                )),
                                signature: t
                                    .signature
                                    .into_iter()
                                    .map(TransactionSignatureElem)
                                    .collect(),
                                nonce: TransactionNonce(t.nonce),
                                contract_address_salt: ContractAddressSalt(t.contract_address_salt),
                                constructor_calldata: t
                                    .constructor_calldata
                                    .into_iter()
                                    .map(CallParam)
                                    .collect(),
                                class_hash: ClassHash(t.class_hash),
                            }),
                        ),
                        _ => anyhow::bail!(
                            "Transaction receipt type differs from its respective transaction type"
                        ),
                    }
                    .map(|t| (t, receipt::from_p2p(r)))
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .into_iter()
                .unzip();

            Ok((gw_t, gw_r))
        }

        mod receipt {
            use super::gw;
            use p2p_proto::common::{
                DeclareTransactionReceipt, DeployAccountTransactionReceipt,
                DeployTransactionReceipt, InvokeTransactionReceipt, L1HandlerTransactionReceipt,
                Receipt,
            };
            use pathfinder_common::{
                event::Event, ContractAddress, EntryPoint, EthereumAddress, EventData, EventKey,
                Fee, L1ToL2MessageNonce, L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem,
                TransactionHash, TransactionIndex,
            };

            pub(super) fn from_p2p(r: Receipt) -> gw::Receipt {
                match r {
                    Receipt::Declare(DeclareTransactionReceipt { common })
                    | Receipt::Deploy(DeployTransactionReceipt { common, .. })
                    | Receipt::DeployAccount(DeployAccountTransactionReceipt { common, .. })
                    | Receipt::Invoke(InvokeTransactionReceipt { common })
                    | Receipt::L1Handler(L1HandlerTransactionReceipt { common }) => gw::Receipt {
                        actual_fee: Some(Fee(common.actual_fee)),
                        events: common
                            .events
                            .into_iter()
                            .map(|e| Event {
                                data: e.data.into_iter().map(EventData).collect(),
                                from_address: ContractAddress::new_or_panic(e.from_address),
                                keys: e.keys.into_iter().map(EventKey).collect(),
                            })
                            .collect(),
                        execution_resources: Some(gw::ExecutionResources {
                            builtin_instance_counter: {
                                let b = common.execution_resources.builtin_instance_counter;
                                gw::execution_resources::BuiltinInstanceCounter::Normal(
                                    gw::execution_resources::NormalBuiltinInstanceCounter {
                                        bitwise_builtin: b.bitwise_builtin,
                                        ecdsa_builtin: b.ecdsa_builtin,
                                        ec_op_builtin: b.ec_op_builtin,
                                        output_builtin: b.output_builtin,
                                        pedersen_builtin: b.pedersen_builtin,
                                        range_check_builtin: b.range_check_builtin,
                                    },
                                )
                            },
                            n_steps: common.execution_resources.n_steps,
                            n_memory_holes: common.execution_resources.n_memory_holes,
                        }),
                        l1_to_l2_consumed_message: common.consumed_message.map(|x| {
                            gw::L1ToL2Message {
                                from_address: EthereumAddress(x.from_address),
                                payload: x
                                    .payload
                                    .into_iter()
                                    .map(L1ToL2MessagePayloadElem)
                                    .collect(),
                                selector: EntryPoint(x.entry_point_selector),
                                to_address: ContractAddress::new_or_panic(x.to_address),
                                nonce: Some(L1ToL2MessageNonce(x.nonce)),
                            }
                        }),
                        l2_to_l1_messages: common
                            .messages_sent
                            .into_iter()
                            .map(|m| gw::L2ToL1Message {
                                from_address: ContractAddress::new_or_panic(m.from_address),
                                payload: m
                                    .payload
                                    .into_iter()
                                    .map(L2ToL1MessagePayloadElem)
                                    .collect(),
                                to_address: EthereumAddress(m.to_address),
                            })
                            .collect(),
                        transaction_hash: TransactionHash(common.transaction_hash),
                        transaction_index: TransactionIndex::new_or_panic(
                            common.transaction_index.into(),
                        ),
                    },
                }
            }
        }
    }

    pub mod state_diff {
        use std::collections::HashMap;

        use p2p_proto::sync::BlockStateUpdateWithHash;
        use pathfinder_common::{
            BlockHash, CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash,
            StorageAddress, StorageValue,
        };
        use starknet_gateway_types::reply::state_update as gw;

        pub fn from_p2p(su: BlockStateUpdateWithHash) -> (BlockHash, gw::StateDiff) {
            (
                BlockHash(su.block_hash),
                gw::StateDiff {
                    storage_diffs: su
                        .state_update
                        .contract_diffs
                        .iter()
                        .map(|contract_diff| {
                            (
                                ContractAddress::new_or_panic(contract_diff.contract_address),
                                contract_diff
                                    .storage_diffs
                                    .iter()
                                    .map(|x| gw::StorageDiff {
                                        key: StorageAddress::new_or_panic(x.key),
                                        value: StorageValue(x.value),
                                    })
                                    .collect(),
                            )
                        })
                        .collect::<HashMap<_, _>>(),
                    deployed_contracts: su
                        .state_update
                        .deployed_contracts
                        .into_iter()
                        .map(|x| gw::DeployedContract {
                            address: ContractAddress::new_or_panic(x.contract_address),
                            class_hash: ClassHash(x.class_hash),
                        })
                        .collect(),
                    old_declared_contracts: su
                        .state_update
                        .declared_cairo_classes
                        .into_iter()
                        .map(ClassHash)
                        .collect(),
                    declared_classes: su
                        .state_update
                        .declared_classes
                        .into_iter()
                        .map(|x| gw::DeclaredSierraClass {
                            class_hash: SierraHash(x.sierra_hash),
                            compiled_class_hash: CasmHash(x.casm_hash),
                        })
                        .collect(),
                    nonces: su
                        .state_update
                        .contract_diffs
                        .iter()
                        .map(|contract_diff| {
                            (
                                ContractAddress::new_or_panic(contract_diff.contract_address),
                                ContractNonce(contract_diff.nonce),
                            )
                        })
                        .collect::<HashMap<_, _>>(),
                    replaced_classes: su
                        .state_update
                        .replaced_classes
                        .into_iter()
                        .map(|x| gw::ReplacedClass {
                            address: ContractAddress::new_or_panic(x.contract_address),
                            class_hash: ClassHash(x.class_hash),
                        })
                        .collect(),
                },
            )
        }
    }
}
