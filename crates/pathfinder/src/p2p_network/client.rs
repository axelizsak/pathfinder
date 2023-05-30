//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a bootstrap node
//! that syncs from the gateway and a "proper" p2p node which only syncs via p2p.

use std::collections::HashMap;

use p2p::SyncClient;
use p2p_proto;
use p2p_proto::common::CompressedContractClass;
use pathfinder_common::{
    BlockHash, BlockId, BlockNumber, BlockTimestamp, CallParam, CasmHash, ClassHash,
    ContractAddress, ContractAddressSalt, ContractNonce, Fee, GasPrice, SequencerAddress,
    SierraHash, StateCommitment, StorageAddress, StorageValue, TransactionHash, TransactionNonce,
    TransactionSignatureElem, TransactionVersion,
};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::reply::{self, state_update, Block};
use starknet_gateway_types::request::add_transaction::ContractDefinition;

#[derive(Clone, Debug)]
pub enum Client {
    Bootstrap {
        p2p_client: SyncClient,
        sequencer: starknet_gateway_client::Client,
    },
    NonPropagating {
        p2p_client: SyncClient,
        sequencer: starknet_gateway_client::Client,
    },
}

impl Client {
    pub fn new(
        i_am_boot: bool,
        p2p_client: SyncClient,
        sequencer: starknet_gateway_client::Client,
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
            }
        }
    }
}

#[async_trait::async_trait]
impl GatewayApi for Client {
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => sequencer.block(block).await,
            Client::NonPropagating { p2p_client, .. } => match block {
                BlockId::Number(n) => {
                    let mut headers = p2p_client
                        .block_headers(n, 1)
                        .await
                        .expect("TODO map error");
                    assert_eq!(headers.len(), 1, "TODO handle len issues");
                    let header = headers.swap_remove(0);

                    let mut bodies = p2p_client
                        .block_bodies(BlockHash(header.block_hash), 1)
                        .await
                        .expect("TODO map error");
                    assert_eq!(bodies.len(), 1, "TODO handle len issues");
                    let body = bodies.swap_remove(0);
                    let (transactions, transaction_receipts) =
                        body::try_from_p2p(body).expect("TODO");

                    Ok(reply::MaybePendingBlock::Block(Block {
                        block_hash: BlockHash(header.block_hash),
                        block_number: BlockNumber::new_or_panic(header.block_number),
                        gas_price: Some(GasPrice(u128::from_be_bytes(
                            header.gas_price.to_be_bytes()[16..]
                                .try_into()
                                .expect("larger to smaller array is ok"),
                        ))),
                        parent_block_hash: BlockHash(header.parent_block_hash),
                        sequencer_address: Some(SequencerAddress(header.sequencer_address)),
                        state_commitment: StateCommitment(header.global_state_root),
                        status: starknet_gateway_types::reply::Status::AcceptedOnL2, // FIXME
                        timestamp: BlockTimestamp::new_or_panic(header.block_timestamp),
                        transaction_receipts,
                        transactions,
                        starknet_version: {
                            if header.starknet_version.is_empty() {
                                None
                            } else {
                                Some(header.starknet_version)
                            }
                            .into()
                        },
                    }))
                }
                BlockId::Latest => todo!(),
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
            Client::NonPropagating { p2p_client, .. } => {
                let classes = p2p_client
                    .contract_classes(vec![class_hash])
                    .await
                    .expect("TODO map error");
                let mut classes = classes.contract_classes;
                assert_eq!(
                    classes.len(),
                    1,
                    "TODO where to handle insufficient data len"
                );
                let CompressedContractClass { class } = classes.swap_remove(0);
                Ok(class.into())
            }
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
        match self {
            Client::Bootstrap { sequencer, .. } | Client::NonPropagating { sequencer, .. } => {
                sequencer.transaction(transaction_hash).await
            }
        }
    }

    async fn state_update(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingStateUpdate, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } => sequencer.state_update(block).await,
            Client::NonPropagating { p2p_client, .. } => match block {
                BlockId::Hash(hash) => {
                    let mut state_updates = p2p_client
                        .state_updates(hash, 1)
                        .await
                        .expect("TODO map error");
                    assert_eq!(
                        state_updates.len(),
                        1,
                        "TODO where to handle insufficient data len"
                    );
                    let state_update = state_updates.swap_remove(0);

                    Ok(reply::MaybePendingStateUpdate::StateUpdate(
                        reply::StateUpdate {
                            block_hash: BlockHash(state_update.block_hash),
                            // FIXME
                            new_root: StateCommitment::ZERO,
                            // FIXME
                            old_root: StateCommitment::ZERO,
                            state_diff: state_update::StateDiff {
                                storage_diffs: state_update
                                    .state_update
                                    .contract_diffs
                                    .iter()
                                    .map(|contract_diff| {
                                        (
                                            ContractAddress::new_or_panic(
                                                contract_diff.contract_address,
                                            ),
                                            contract_diff
                                                .storage_diffs
                                                .iter()
                                                .map(|x| state_update::StorageDiff {
                                                    key: StorageAddress::new_or_panic(x.key),
                                                    value: StorageValue(x.value),
                                                })
                                                .collect(),
                                        )
                                    })
                                    .collect::<HashMap<_, _>>(),
                                deployed_contracts: state_update
                                    .state_update
                                    .deployed_contracts
                                    .into_iter()
                                    .map(|x| state_update::DeployedContract {
                                        address: ContractAddress::new_or_panic(x.contract_address),
                                        class_hash: ClassHash(x.contract_class_hash),
                                    })
                                    .collect(),
                                old_declared_contracts: state_update
                                    .state_update
                                    .declared_deprecated_contract_class_hashes
                                    .into_iter()
                                    .map(|x| ClassHash(x))
                                    .collect(),
                                declared_classes: state_update
                                    .state_update
                                    .declared_contract_classes
                                    .into_iter()
                                    .map(|x| state_update::DeclaredSierraClass {
                                        class_hash: SierraHash(x.contract_class_hash),
                                        compiled_class_hash: CasmHash(x.contract_class_hash),
                                    })
                                    .collect(),
                                nonces: state_update
                                    .state_update
                                    .contract_diffs
                                    .iter()
                                    .map(|contract_diff| {
                                        (
                                            ContractAddress::new_or_panic(
                                                contract_diff.contract_address,
                                            ),
                                            ContractNonce(contract_diff.nonce),
                                        )
                                    })
                                    .collect::<HashMap<_, _>>(),
                                replaced_classes: state_update
                                    .state_update
                                    .replaced_contract_classes
                                    .into_iter()
                                    .map(|x| state_update::ReplacedClass {
                                        address: ContractAddress::new_or_panic(x.contract_address),
                                        class_hash: ClassHash(x.contract_class_hash),
                                    })
                                    .collect(),
                            },
                        },
                    ))
                }
                _ => unreachable!("not used in sync"),
            },
        }
    }

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        match self {
            Client::Bootstrap { sequencer, .. } | Client::NonPropagating { sequencer, .. } => {
                sequencer.eth_contract_addresses().await
            }
        }
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
        match self {
            Client::Bootstrap { sequencer, .. } | Client::NonPropagating { sequencer, .. } => {
                sequencer
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
        }
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
        match self {
            Client::Bootstrap { sequencer, .. } | Client::NonPropagating { sequencer, .. } => {
                sequencer
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
        }
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
        match self {
            Client::Bootstrap { sequencer, .. } | Client::NonPropagating { sequencer, .. } => {
                sequencer
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
        }
    }
}

mod body {
    use p2p_proto::common::{BlockBody, Receipt, Transaction};
    use pathfinder_common::{
        CallParam, ContractAddress, EntryPoint, Fee, TransactionHash, TransactionNonce,
        TransactionSignatureElem,
    };
    use stark_hash::Felt;
    use starknet_gateway_types::reply::transaction::{self as gw, EntryPointType};

    pub(super) fn try_from_p2p(
        body: BlockBody,
    ) -> anyhow::Result<(Vec<gw::Transaction>, Vec<gw::Receipt>)> {
        fn version(felt: Felt) -> u8 {
            felt.to_be_bytes()[31]
        }

        fn entry_point(
            entry_point: p2p_proto::common::EntryPoint,
        ) -> (EntryPoint, Option<EntryPointType>) {
            match entry_point {
                p2p_proto::common::EntryPoint::EntryPoint(e) => (EntryPoint(e), None),
                p2p_proto::common::EntryPoint::LegacyExternal(e) => {
                    (EntryPoint(e), Some(EntryPointType::External))
                }
                p2p_proto::common::EntryPoint::LegacyL1Handler(e) => {
                    (EntryPoint(e), Some(EntryPointType::L1Handler))
                }
            }
        }

        let (gw_t, gw_r) = body
            .transactions
            .into_iter()
            .zip(body.receipts.into_iter())
            .map(|(t, r)| match (t, r) {
                (Transaction::Invoke(t), Receipt::Invoke(r)) => match version(t.version) {
                    0 => {
                        let (entry_point_selector, entry_point_type) =
                            entry_point(t.entry_point_selector);

                        Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V0(
                            gw::InvokeTransactionV0 {
                                calldata: t.calldata.into_iter().map(CallParam).collect(),
                                sender_address: ContractAddress::new_or_panic(t.contract_address),
                                entry_point_selector,
                                entry_point_type,
                                max_fee: Fee(t.max_fee),
                                signature: t
                                    .signature
                                    .into_iter()
                                    .map(TransactionSignatureElem)
                                    .collect(),
                                transaction_hash: TransactionHash(r.common.transaction_hash),
                            },
                        )))
                    }
                    1 => Ok(gw::Transaction::Invoke(gw::InvokeTransaction::V1(
                        gw::InvokeTransactionV1 {
                            calldata: t.calldata.into_iter().map(CallParam).collect(),
                            sender_address: ContractAddress::new_or_panic(t.contract_address),
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
                }
                .map(|t| {
                    (
                        t,
                        gw::Receipt {
                            actual_fee: Some(Fee(r.common.actual_fee)),
                            events: todo!(),
                            execution_resources: todo!(),
                            l1_to_l2_consumed_message: todo!(),
                            l2_to_l1_messages: todo!(),
                            transaction_hash: TransactionHash(r.common.transaction_hash),
                            transaction_index: todo!(),
                        },
                    )
                }),
                // Transaction::Declare(t) => match version(t.version) {
                //     0 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V0(
                //         gw::DeclareTransactionV0V1 {
                //             class_hash: todo!(),
                //             max_fee: todo!(),
                //             nonce: todo!(),
                //             sender_address: todo!(),
                //             signature: todo!(),
                //             transaction_hash: todo!(),
                //         },
                //     ))),
                //     1 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V1(
                //         gw::DeclareTransactionV0V1 {
                //             class_hash: todo!(),
                //             max_fee: todo!(),
                //             nonce: todo!(),
                //             sender_address: todo!(),
                //             signature: todo!(),
                //             transaction_hash: todo!(),
                //         },
                //     ))),
                //     2 => Ok(gw::Transaction::Declare(gw::DeclareTransaction::V2(
                //         gw::DeclareTransactionV2 {
                //             class_hash: todo!(),
                //             max_fee: todo!(),
                //             nonce: todo!(),
                //             sender_address: todo!(),
                //             signature: todo!(),
                //             transaction_hash: todo!(),
                //             compiled_class_hash: todo!(),
                //         },
                //     ))),
                //     _ => anyhow::bail!("Invalid declare transaction version {}", t.version),
                // },
                // Transaction::Deploy(t) => Ok(gw::Transaction::Deploy(gw::DeployTransaction {
                //     contract_address: todo!(),
                //     contract_address_salt: todo!(),
                //     class_hash: todo!(),
                //     constructor_calldata: todo!(),
                //     transaction_hash: todo!(),
                //     version: todo!(),
                // })),
                // Transaction::L1Handler(t) => {
                //     Ok(gw::Transaction::L1Handler(gw::L1HandlerTransaction {
                //         contract_address: todo!(),
                //         entry_point_selector: todo!(),
                //         nonce: todo!(),
                //         calldata: todo!(),
                //         transaction_hash: todo!(),
                //         version: todo!(),
                //     }))
                // }
                // Transaction::DeployAccount(t) => Ok(gw::Transaction::DeployAccount(
                //     gw::DeployAccountTransaction {
                //         contract_address: todo!(),
                //         transaction_hash: todo!(),
                //         max_fee: todo!(),
                //         version: todo!(),
                //         signature: todo!(),
                //         nonce: todo!(),
                //         contract_address_salt: todo!(),
                //         constructor_calldata: todo!(),
                //         class_hash: todo!(),
                //     },
                // )),
                _ => anyhow::bail!("TODO"),
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .unzip();

        Ok((gw_t, gw_r))
    }
}

#[cfg(feature = "p2p")]
#[derive(Clone, Debug)]
pub struct BootstrapClient {
    p2p_client: SyncClient,
}

#[cfg(feature = "p2p")]
impl BootstrapClient {
    pub async fn propagate_new_head(&self, block: &Block) -> anyhow::Result<()> {
        self.p2p_client
            .propagate_new_head(p2p_proto::common::BlockHeader {
                block_hash: block.block_hash.0,
                parent_block_hash: block.parent_block_hash.0,
                block_number: block.block_number.get(),
                global_state_root: block.state_commitment.0,
                sequencer_address: block.sequencer_address.unwrap_or(SequencerAddress::ZERO).0,
                block_timestamp: block.timestamp.get(),
                gas_price: block.gas_price.unwrap_or(GasPrice::ZERO).0.into(),

                transaction_count: block.transactions.len().try_into()?,
                transaction_commitment: block.state_commitment.0,

                // FIXME
                event_count: 0,
                event_commitment: stark_hash::Felt::ZERO,
                protocol_version: 0,
                starknet_version: Default::default(),
            })
            .await
    }
}
