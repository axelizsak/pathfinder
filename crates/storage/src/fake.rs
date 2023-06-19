//! Create fake blockchain data for test purposes
use crate::types::StateUpdate;
use crate::Storage;
use pathfinder_common::BlockHeader;
use rand::Rng;
use starknet_gateway_types::reply::transaction as gateway;

pub type StorageInitializer = Vec<StorageInitializerItem>;

pub type StorageInitializerItem = (
    BlockHeader,
    Vec<(gateway::Transaction, gateway::Receipt)>,
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
            tx.insert_state_diff(header.number, &state_update.state_diff)
                .unwrap();
        });
    tx.commit().unwrap();
    fake_data
}

/// Raw _fake state initializers_
pub mod init {
    use super::StorageInitializer;
    use crate::types::StateUpdate;
    use fake::{Fake, Faker};
    use pathfinder_common::{
        BlockHash, BlockHeader, BlockNumber, StateCommitment, TransactionIndex,
    };
    use rand::Rng;
    use starknet_gateway_types::reply::transaction as gateway;

    /// Create fake blocks and state updates with __limited consistency guarantees__:
    /// - block headers:
    ///     - consecutive numbering starting from genesis (`0`) up to `n-1`
    ///     - parent hash wrt previous block, genesis' parent hash is `0`
    ///     - state commitment is a hash of storage and class commitments
    /// - block bodies:
    ///     - transaction indices within a block
    ///     - transaction hashes in respective receipts
    /// - state updates:
    ///     - block hashes
    ///     - old roots wrt previous state update, genesis' old root is `0`
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
            let transactions_and_receipts = Faker
                .fake_with_rng::<Vec<gateway::Transaction>, _>(rng)
                .into_iter()
                .enumerate()
                .map(|(i, t)| {
                    let transaction_hash = t.hash();
                    (
                        t,
                        gateway::Receipt {
                            transaction_hash,
                            transaction_index: TransactionIndex::new_or_panic(
                                i.try_into().expect("u64 is at least as wide as usize"),
                            ),
                            ..Faker.fake_with_rng(rng)
                        },
                    )
                })
                .collect::<Vec<_>>();
            init.push((
                header,
                transactions_and_receipts,
                Faker.fake_with_rng::<StateUpdate, _>(rng),
            ));
        }

        // "Fix" block headers and state updates
        let (header, _, state_update) = init.get_mut(0).unwrap();
        header.parent_hash = BlockHash::ZERO;
        header.state_commitment =
            StateCommitment::calculate(header.storage_commitment, header.class_commitment);
        state_update.block_hash = Some(header.hash);
        state_update.old_root = StateCommitment::ZERO;

        for i in 1..n {
            let (parent_hash, old_root) = init
                .get(i - 1)
                .map(|(h, _, s)| (h.hash, s.new_root))
                .unwrap();
            let (header, _, state_update) = init.get_mut(i).unwrap();
            header.parent_hash = parent_hash;
            header.state_commitment =
                StateCommitment::calculate(header.storage_commitment, header.class_commitment);
            state_update.block_hash = Some(header.hash);
            state_update.old_root = old_root;
        }

        init
    }
}