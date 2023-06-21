//! Create fake blockchain data for test purposes
use crate::types::StateUpdate;
use crate::Storage;
use pathfinder_common::BlockHeader;
use rand::Rng;
use starknet_gateway_types::reply::transaction as gw;

pub type StorageInitializer = Vec<StorageInitializerItem>;

pub type StorageInitializerItem = (
    BlockHeader,
    Vec<(gw::Transaction, gw::Receipt)>,
    StateUpdate,
);

/// Initialize [`Storage`] with fake blocks and state updates
/// maintaining [**limited consistency guarantees**](crate::fake::init::with_n_blocks)
pub fn with_n_blocks(storage: &Storage, n: usize) -> StorageInitializer {
    let mut rng = rand::thread_rng();
    with_n_blocks_and_rng(storage, n, &mut rng)
}

/// Same as [`with_n_blocks`] except caller can specify the rng used
pub fn with_n_blocks_and_rng(
    storage: &Storage,
    n: usize,
    rng: &mut impl Rng,
) -> StorageInitializer {
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();
    let fake_data = init::with_n_blocks_and_rng(n, rng);
    fake_data
        .iter()
        .for_each(|(header, transaction_data, state_update)| {
            tx.insert_block_header(header).unwrap();
            tx.insert_transaction_data(header.hash, header.number, transaction_data)
                .unwrap();

            state_update
                .state_diff
                .declared_contracts
                .iter()
                .for_each(|cairo_class| {
                    tx.insert_cairo_class(cairo_class.class_hash, b"").unwrap()
                });

            state_update
                .state_diff
                .declared_sierra_classes
                .iter()
                .for_each(|sierra_class| {
                    tx.insert_sierra_class(
                        &sierra_class.class_hash,
                        &[],
                        &sierra_class.compiled_class_hash,
                        &[],
                        "1.0.alpha6",
                    )
                    .unwrap()
                });

            tx.insert_state_diff(header.number, &state_update.state_diff)
                .unwrap();
        });
    tx.commit().unwrap();
    fake_data
}

/// Raw _fake state initializers_
pub mod init {
    use super::StorageInitializer;
    use crate::types::{
        state_update::{Nonce, ReplacedClass, StateDiff, StorageDiff, StorageEntry},
        StateUpdate,
    };
    use fake::{Fake, Faker};
    use pathfinder_common::test_utils::fake_non_empty_with_rng;
    use pathfinder_common::{
        BlockHash, BlockHeader, BlockNumber, ContractAddress, StateCommitment, TransactionIndex,
    };
    use rand::Rng;
    use starknet_gateway_types::reply::transaction as gw;

    /// Create fake blocks and state updates with __limited consistency guarantees__:
    /// - block headers:
    ///     - consecutive numbering starting from genesis (`0`) up to `n-1`
    ///     - parent hash wrt previous block, genesis' parent hash is `0`
    ///     - state commitment is a hash of storage and class commitments
    /// - block bodies:
    ///     - transaction indices within a block
    ///     - transaction hashes in respective receipts
    ///     - at least 1 transaction with receipt per block
    /// - state updates:
    ///     - block hashes
    ///     - old roots wrt previous state update, genesis' old root is `0`
    ///     - replaced classes for block N point to some deployed contracts from block N-1
    ///     - each storage diff has its respective nonce update
    ///     - storage entries contrain at least 1 element
    ///     
    pub fn with_n_blocks(n: usize) -> StorageInitializer {
        let mut rng = rand::thread_rng();
        with_n_blocks_and_rng(n, &mut rng)
    }

    /// Same as [`with_n_blocks`] except caller can specify the rng used
    pub fn with_n_blocks_and_rng(n: usize, rng: &mut impl Rng) -> StorageInitializer {
        let mut init = Vec::with_capacity(n);

        for i in 0..n {
            let mut header: BlockHeader = Faker.fake_with_rng(rng);
            header.number =
                BlockNumber::new_or_panic(i.try_into().expect("u64 is at least as wide as usize"));
            header.state_commitment =
                StateCommitment::calculate(header.storage_commitment, header.class_commitment);

            // There must be at least 1 transaction per block
            let transactions_and_receipts = fake_non_empty_with_rng::<Vec<_>, gw::Transaction>(rng)
                .into_iter()
                .enumerate()
                .map(|(i, t)| {
                    let transaction_hash = t.hash();
                    (
                        t,
                        gw::Receipt {
                            transaction_hash,
                            transaction_index: TransactionIndex::new_or_panic(
                                i.try_into().expect("u64 is at least as wide as usize"),
                            ),
                            ..Faker.fake_with_rng(rng)
                        },
                    )
                })
                .collect::<Vec<_>>();

            let block_hash = Some(header.hash);
            let new_root = header.state_commitment;

            init.push((
                header,
                transactions_and_receipts,
                StateUpdate {
                    block_hash,
                    new_root,
                    // Will be fixed in the next loop
                    old_root: StateCommitment::ZERO,
                    state_diff: {
                        let contracts_with_storage_diffs = Faker
                            .fake_with_rng::<Vec<ContractAddress>, _>(rng)
                            .into_iter();
                        StateDiff {
                            storage_diffs: {
                                contracts_with_storage_diffs
                                    .clone()
                                    .map(|address| StorageDiff {
                                        address,
                                        // Disallow empty storage entries
                                        storage_entries: fake_non_empty_with_rng::<
                                            Vec<StorageEntry>,
                                            _,
                                        >(
                                            rng
                                        )
                                        .into_iter()
                                        .collect(),
                                    })
                                    .collect()
                            },
                            // Will be fixed in the next loop
                            replaced_classes: vec![],
                            nonces: contracts_with_storage_diffs
                                .map(|contract_address| Nonce {
                                    contract_address,
                                    nonce: Faker.fake_with_rng(rng),
                                })
                                .collect(),
                            ..Faker.fake_with_rng(rng)
                        }
                    },
                },
            ));
        }

        //
        // "Fix" block headers and state updates
        //
        if !init.is_empty() {
            let (header, _, state_update) = init.get_mut(0).unwrap();
            header.parent_hash = BlockHash::ZERO;
            state_update.old_root = StateCommitment::ZERO;

            for i in 1..n {
                let (parent_hash, old_root, deployed_in_parent) = init
                    .get(i - 1)
                    .map(|(h, _, state_update)| {
                        (
                            h.hash,
                            h.state_commitment,
                            state_update.state_diff.deployed_contracts.clone(),
                        )
                    })
                    .unwrap();
                let (header, _, state_update) = init.get_mut(i).unwrap();

                header.parent_hash = parent_hash;
                state_update.old_root = old_root;

                let num_deployed_in_parent = deployed_in_parent.len();

                if num_deployed_in_parent > 0 {
                    // Add some replaced classes
                    let num_replaced = rng.gen_range(1..=num_deployed_in_parent);
                    use rand::seq::SliceRandom;

                    state_update.state_diff.replaced_classes = deployed_in_parent
                        .choose_multiple(rng, num_replaced)
                        .map(|x| ReplacedClass {
                            address: x.address,
                            class_hash: Faker.fake_with_rng(rng),
                        })
                        .collect()
                }
            }
        }

        init
    }
}
