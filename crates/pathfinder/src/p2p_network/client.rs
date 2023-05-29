//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a bootstrap node
//! that syncs from the gateway and a "proper" p2p node which only syncs via p2p.

use std::collections::HashMap;

use p2p::SyncClient;
use p2p_proto;
use p2p_proto::common::CompressedContractClass;
use pathfinder_common::{
    BlockHash, BlockId, CallParam, CasmHash, ClassHash, ContractAddress, ContractAddressSalt,
    ContractNonce, Fee, SequencerAddress, SierraHash, StateCommitment, StorageAddress,
    StorageValue, TransactionHash, TransactionNonce, TransactionSignatureElem, TransactionVersion,
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
                BlockId::Number(_) => todo!(),
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
                parent_block_hash: block.parent_block_hash.0,
                block_number: block.block_number.get(),
                global_state_root: block.state_commitment.0,
                sequencer_address: block.sequencer_address.unwrap_or(SequencerAddress::ZERO).0,
                block_timestamp: block.timestamp.get(),

                transaction_count: block.transactions.len().try_into()?,
                transaction_commitment: block.state_commitment.0,

                // FIXME
                event_count: 0,
                event_commitment: stark_hash::Felt::ZERO,
                protocol_version: 0,
            })
            .await
    }
}
