use std::collections::HashMap;

use anyhow::{anyhow, Context};
use p2p_proto as proto;
use pathfinder_common::{BlockHash, BlockNumber, TransactionNonce};
use pathfinder_storage::{StarknetBlocksBlockId, StarknetTransactionsTable, Storage};
use stark_hash::Felt;

const MAX_HEADERS_COUNT: u64 = 1000;
const MAX_BODIES_COUNT: u64 = 100;
const MAX_STATE_UPDATES_COUNT: u64 = 100;

// TODO: we currently ignore the size limit.
pub async fn get_block_headers(
    request: p2p_proto::sync::GetBlockHeaders,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::BlockHeaders> {
    let storage = storage.clone();
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;

        let headers = fetch_block_headers(tx, request)?;

        Ok(p2p_proto::sync::BlockHeaders { headers })
    })
    .await
    .context("Database read panic or shutting down")?
}

fn fetch_block_headers(
    tx: rusqlite::Transaction<'_>,
    request: p2p_proto::sync::GetBlockHeaders,
) -> anyhow::Result<Vec<p2p_proto::common::BlockHeader>> {
    use pathfinder_storage::StarknetBlocksTable;

    let mut count = std::cmp::min(request.count, MAX_HEADERS_COUNT);
    let mut headers = Vec::new();

    let mut next_block_number =
        StarknetBlocksTable::get_number(&tx, BlockHash(request.start_block))?;

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(block) = StarknetBlocksTable::get(
            &tx,
            pathfinder_storage::StarknetBlocksBlockId::Number(block_number),
        )? else {
            // no such block in our database, stop iterating
            break;
        };

        let parent_block_number = block_number.get().checked_sub(1).and_then(BlockNumber::new);
        let parent_block_hash = match parent_block_number {
            Some(number) => StarknetBlocksTable::get_hash(&tx, number.into())?,
            None => None,
        };

        let transaction_count = StarknetTransactionsTable::get_transaction_count(
            &tx,
            StarknetBlocksBlockId::Hash(block.hash),
        )?;

        headers.push(p2p_proto::common::BlockHeader {
            parent_block_hash: parent_block_hash.unwrap_or(BlockHash(Felt::ZERO)).0,
            block_number: block.number.get(),
            global_state_root: block.state_commmitment.0,
            sequencer_address: block.sequencer_address.0,
            block_timestamp: block.timestamp.get(),
            transaction_count: transaction_count
                .try_into()
                .context("Too many transactions")?,
            transaction_commitment: block
                .transaction_commitment
                .map(|tx| tx.0)
                .ok_or(anyhow!("Transaction commitment missing"))?,
            event_count: 0,
            event_commitment: block
                .event_commitment
                .map(|ev| ev.0)
                .ok_or(anyhow!("Event commitment missing"))?,
            // TODO: what's the protocol version?
            protocol_version: 0,
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(headers)
}

// TODO: we currently ignore the size limit.
pub async fn get_block_bodies(
    request: p2p_proto::sync::GetBlockBodies,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::BlockBodies> {
    let storage = storage.clone();
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;

        let block_bodies = fetch_block_bodies(tx, request)?;

        Ok(p2p_proto::sync::BlockBodies { block_bodies })
    })
    .await
    .context("Database read panic or shutting down")?
}

fn fetch_block_bodies(
    tx: rusqlite::Transaction<'_>,
    request: p2p_proto::sync::GetBlockBodies,
) -> anyhow::Result<Vec<p2p_proto::common::BlockBody>> {
    use pathfinder_storage::StarknetBlocksTable;

    let mut count = std::cmp::min(request.count, MAX_BODIES_COUNT);
    let mut bodies = Vec::new();

    let mut next_block_number =
        StarknetBlocksTable::get_number(&tx, BlockHash(request.start_block))?;

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let transactions_and_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(&tx, block_number.into())?;

        if transactions_and_receipts.is_empty() {
            // no such block in our database, stop iterating
            break;
        }

        let (transactions, receipts) = transactions_and_receipts
            .into_iter()
            .map(|tr| body::from_gw(tr))
            .unzip();

        bodies.push(p2p_proto::common::BlockBody {
            transactions,
            receipts,
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(bodies)
}

// TODO: we currently ignore the size limit.
pub async fn get_state_updates(
    request: p2p_proto::sync::GetStateDiffs,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::StateDiffs> {
    let storage = storage.clone();
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;

        let block_state_updates = fetch_block_state_updates(tx, request)?;

        Ok(p2p_proto::sync::StateDiffs {
            block_state_updates,
        })
    })
    .await
    .context("Database read panic or shutting down")?
}

fn fetch_block_state_updates(
    tx: rusqlite::Transaction<'_>,
    request: p2p_proto::sync::GetStateDiffs,
) -> anyhow::Result<Vec<p2p_proto::sync::BlockStateUpdateWithHash>> {
    use pathfinder_storage::StarknetBlocksTable;
    // use pathfinder_storage::;

    let mut count = std::cmp::min(request.count, MAX_STATE_UPDATES_COUNT);
    let mut state_updates = Vec::new();

    let mut next_block_number =
        StarknetBlocksTable::get_number(&tx, BlockHash(request.start_block))?;

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let block_hash = match StarknetBlocksTable::get_hash(&tx, block_number.into())? {
            Some(block_hash) => block_hash,
            // No such block found
            None => break,
        };

        let state_update = get_state_update_from_storage(&tx, block_number)?;
        state_updates.push(p2p_proto::sync::BlockStateUpdateWithHash {
            block_hash: block_hash.0,
            state_update,
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(state_updates)
}

// Copied from rpc/v03/get_state_update
fn get_state_update_from_storage(
    tx: &rusqlite::Transaction<'_>,
    number: BlockNumber,
) -> anyhow::Result<p2p_proto::propagation::BlockStateUpdate> {
    use p2p_proto::propagation::{
        ContractDiff, DeclaredClass as DeclaredSierraClass, DeployedContract, ReplacedClass,
        StorageDiff,
    };
    use pathfinder_common::{CasmHash, ClassHash, ContractAddress, StorageAddress, StorageValue};

    let mut stmt = tx
        .prepare_cached("SELECT contract_address, nonce FROM nonce_updates WHERE block_number = ?")
        .context("Preparing nonce update query statement")?;
    let nonces = stmt
        .query_map([number], |row| {
            let contract_address = row.get(0)?;
            let nonce = row.get(1)?;

            Ok((contract_address, nonce))
        })
        .context("Querying nonce updates")?
        .collect::<Result<HashMap<ContractAddress, TransactionNonce>, _>>()
        .context("Iterating over nonce query rows")?;

    let mut stmt = tx
        .prepare_cached(
            "SELECT contract_address, storage_address, storage_value FROM storage_updates WHERE block_number = ?"
        )
        .context("Preparing storage update query statement")?;
    let storage_tuples = stmt
        .query_map([number], |row| {
            let contract_address: ContractAddress = row.get(0)?;
            let storage_address: StorageAddress = row.get(1)?;
            let storage_value: StorageValue = row.get(2)?;

            Ok((contract_address, storage_address, storage_value))
        })
        .context("Querying storage updates")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over storage query rows")?;
    // Convert storage tuples to contract based mapping.
    let mut storage_diffs: HashMap<ContractAddress, Vec<StorageDiff>> = HashMap::new();
    for (addr, key, value) in storage_tuples {
        storage_diffs.entry(addr).or_default().push(StorageDiff {
            key: *key.get(),
            value: value.0,
        });
    }

    let mut stmt = tx
        .prepare_cached(
            r"SELECT
                class_definitions.hash AS class_hash,
                casm_definitions.compiled_class_hash AS compiled_class_hash
            FROM
                class_definitions
            LEFT OUTER JOIN
                casm_definitions ON casm_definitions.hash = class_definitions.hash
            WHERE
                class_definitions.block_number = ?",
        )
        .context("Preparing class declaration query statement")?;
    enum DeclaredClass {
        Deprecated(ClassHash),
        Sierra(DeclaredSierraClass),
    }
    let declared_classes = stmt
        .query_map([number], |row| {
            let class_hash: ClassHash = row.get(0)?;
            let compiled_class_hash: Option<CasmHash> = row.get(1)?;

            Ok(match compiled_class_hash {
                Some(compiled_class_hash) => DeclaredClass::Sierra(DeclaredSierraClass {
                    contract_class_hash: class_hash.0,
                    compiled_class_hash: compiled_class_hash.0,
                }),
                None => DeclaredClass::Deprecated(class_hash),
            })
        })
        .context("Querying class declarations")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over class declaration query rows")?;
    let (deprecated_declared_classes, declared_classes): (Vec<_>, Vec<_>) = declared_classes
        .into_iter()
        .partition(|c| matches!(c, DeclaredClass::Deprecated(_)));
    let deprecated_declared_classes = deprecated_declared_classes
        .into_iter()
        .map(|c| match c {
            DeclaredClass::Deprecated(c) => c.0,
            DeclaredClass::Sierra(_) => {
                panic!("Internal error: unexpected Sierra class declaration")
            }
        })
        .collect();
    let declared_classes = declared_classes
        .into_iter()
        .map(|c| match c {
            DeclaredClass::Deprecated(_) => {
                panic!("Internal error: unexpected deprecated class declaration")
            }
            DeclaredClass::Sierra(c) => c,
        })
        .collect();

    let mut stmt = tx
        .prepare_cached(
            r"SELECT
                cu1.contract_address AS contract_address,
                cu1.class_hash AS class_hash,
                cu2.block_number IS NOT NULL AS is_replaced
            FROM
                contract_updates cu1
            LEFT OUTER JOIN
                contract_updates cu2 ON cu1.contract_address = cu2.contract_address AND cu2.block_number < cu1.block_number
            WHERE
                cu1.block_number = ?",
        )
        .context("Preparing contract update query statement")?;
    enum DeployedOrReplacedContract {
        Deployed(DeployedContract),
        Replaced(ReplacedClass),
    }
    let deployed_and_replaced_contracts = stmt
        .query_map([number], |row| {
            let address: ContractAddress = row.get(0)?;
            let class_hash: ClassHash = row.get(1)?;
            let is_replaced: bool = row.get(2)?;

            Ok(match is_replaced {
                true => DeployedOrReplacedContract::Replaced(ReplacedClass {
                    contract_address: *address.get(),
                    contract_class_hash: class_hash.0,
                }),
                false => DeployedOrReplacedContract::Deployed(DeployedContract {
                    contract_address: *address.get(),
                    contract_class_hash: class_hash.0,
                }),
            })
        })
        .context("Querying contract deployments")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over contract deployment query rows")?;
    let (deployed_contracts, replaced_classes): (Vec<_>, Vec<_>) = deployed_and_replaced_contracts
        .into_iter()
        .partition(|c| matches!(c, DeployedOrReplacedContract::Deployed(_)));
    let deployed_contracts = deployed_contracts
        .into_iter()
        .map(|c| match c {
            DeployedOrReplacedContract::Deployed(c) => c,
            DeployedOrReplacedContract::Replaced(_) => {
                panic!("Internal error: unexpected replaced class")
            }
        })
        .collect();
    let replaced_classes = replaced_classes
        .into_iter()
        .map(|c| match c {
            DeployedOrReplacedContract::Deployed(_) => {
                panic!("Internal error: unexpected deployed contract")
            }
            DeployedOrReplacedContract::Replaced(c) => c,
        })
        .collect();

    let mut contract_diffs = nonces
        .into_iter()
        .map(|(contract_address, nonce)| {
            (
                *contract_address.get(),
                ContractDiff {
                    contract_address: *contract_address.get(),
                    nonce: nonce.0,
                    storage_diffs: storage_diffs.remove(&contract_address).unwrap_or_default(),
                },
            )
        })
        .collect::<HashMap<_, _>>();

    // TODO remove me
    debug_assert!(
        storage_diffs.is_empty(),
        "a storage update is always accompanied by a nonce update, but is it the other way round?"
    );

    storage_diffs
        .into_iter()
        .for_each(|(contract_address, storage_diffs)| {
            contract_diffs.insert(
                *contract_address.get(),
                ContractDiff {
                    contract_address: *contract_address.get(),
                    nonce: Felt::ZERO,
                    storage_diffs,
                },
            );
        });

    Ok(proto::propagation::BlockStateUpdate {
        contract_diffs: contract_diffs.into_iter().map(|(_, diff)| diff).collect(),
        deployed_contracts,
        declared_deprecated_contract_class_hashes: deprecated_declared_classes,
        declared_contract_classes: declared_classes,
        replaced_contract_classes: replaced_classes,
    })
}

mod body {
    use p2p_proto::common::{
        CommonTransactionReceiptProperties, DeclareTransaction, DeclareTransactionReceipt,
        DeployAccountTransaction, DeployAccountTransactionReceipt, DeployTransaction,
        DeployTransactionReceipt, Event, InvokeTransaction, InvokeTransactionReceipt, MessageToL1,
        Receipt, Transaction,
    };
    use pathfinder_common::{EntryPoint, Fee, TransactionNonce};
    use stark_hash::Felt;
    use starknet_gateway_types::reply::transaction as gw;

    pub(super) fn from_gw((gw_t, gw_r): (gw::Transaction, gw::Receipt)) -> (Transaction, Receipt) {
        let common = CommonTransactionReceiptProperties {
            transaction_hash: gw_t.hash().0,
            // TODO What if the fee is missing?
            actual_fee: gw_r.actual_fee.unwrap_or(Fee::ZERO).0,
            messages_sent: gw_r
                .l2_to_l1_messages
                .into_iter()
                .map(|m| MessageToL1 {
                    from_address: *m.from_address.get(),
                    payload: m.payload.into_iter().map(|x| x.0).collect(),
                    to_address: m.to_address.0,
                })
                .collect(),
            events: gw_r
                .events
                .into_iter()
                .map(|e| Event {
                    from_address: *e.from_address.get(),
                    keys: e.keys.into_iter().map(|k| k.0).collect(),
                    data: e.data.into_iter().map(|d| d.0).collect(),
                })
                .collect(),
        };

        let version =
            Felt::from_be_slice(gw_t.version().0.as_bytes()).expect("Version fits into felt");

        match gw_t {
            gw::Transaction::Declare(
                gw::DeclareTransaction::V0(t) | gw::DeclareTransaction::V1(t),
            ) => {
                let r = Receipt::Declare(DeclareTransactionReceipt { common });
                let t = Transaction::Declare(DeclareTransaction {
                    contract_class_hash: t.class_hash.0,
                    sender_address: *t.sender_address.get(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    version,
                });
                (t, r)
            }
            gw::Transaction::Declare(gw::DeclareTransaction::V2(t)) => {
                let r = Receipt::Declare(DeclareTransactionReceipt { common });
                let t = Transaction::Declare(DeclareTransaction {
                    contract_class_hash: t.class_hash.0,
                    sender_address: *t.sender_address.get(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    version,
                });
                (t, r)
            }
            gw::Transaction::Deploy(t) => {
                let r = Receipt::Deploy(DeployTransactionReceipt {
                    common,
                    contract_address: *t.contract_address.get(),
                });
                let t = Transaction::Deploy(DeployTransaction {
                    contract_class_hash: t.class_hash.0,
                    contract_address_salt: t.contract_address_salt.0,
                    constructor_calldata: t.constructor_calldata.into_iter().map(|x| x.0).collect(),
                    version,
                });
                (t, r)
            }
            gw::Transaction::DeployAccount(t) => {
                let r = Receipt::DeployAccount(DeployAccountTransactionReceipt {
                    common,
                    contract_address: *t.contract_address.get(),
                });
                let t = Transaction::DeployAccount(DeployAccountTransaction {
                    class_hash: t.class_hash.0,
                    contract_address_salt: t.contract_address_salt.0,
                    constructor_calldata: t.constructor_calldata.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    version,
                });
                (t, r)
            }
            gw::Transaction::Invoke(gw::InvokeTransaction::V0(t)) => {
                let r = Receipt::Invoke(InvokeTransactionReceipt { common });
                let t = Transaction::Invoke(InvokeTransaction {
                    contract_address: *t.sender_address.get(),
                    entry_point_selector: t.entry_point_selector.0,
                    calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    // FIXME
                    nonce: TransactionNonce::ZERO.0,
                    version,
                });
                (t, r)
            }
            gw::Transaction::Invoke(gw::InvokeTransaction::V1(t)) => {
                let r = Receipt::Invoke(InvokeTransactionReceipt { common });
                let t = Transaction::Invoke(InvokeTransaction {
                    contract_address: *t.sender_address.get(),
                    // FIXME
                    entry_point_selector: EntryPoint::ZERO.0,
                    calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                    signature: t.signature.into_iter().map(|x| x.0).collect(),
                    max_fee: t.max_fee.0,
                    nonce: t.nonce.0,
                    version,
                });
                (t, r)
            }
            gw::Transaction::L1Handler(t) => {
                let r =
                    Receipt::L1Handler(p2p_proto::common::L1HandlerTransactionReceipt { common });
                let t = Transaction::L1Handler(p2p_proto::common::L1HandlerTransaction {
                    contract_address: *t.contract_address.get(),
                    entry_point_selector: t.entry_point_selector.0,
                    calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                    nonce: t.nonce.0,
                    version,
                });
                (t, r)
            }
        }
    }
}

/// Returns next block number considering direction.
///
/// None is returned if we're out-of-bounds.
fn get_next_block_number(
    current: BlockNumber,
    direction: proto::sync::Direction,
) -> Option<BlockNumber> {
    match direction {
        proto::sync::Direction::Forward => current.get().checked_add(1).and_then(BlockNumber::new),
        proto::sync::Direction::Backward => current.get().checked_sub(1).and_then(BlockNumber::new),
    }
}

// TODO rework to iterate over all types of requests (headers, bodies, state diffs)
// unfortunately cannot cover classes (ie cairo0/sierra)
#[cfg(test)]
mod tests {
    use super::proto::sync::Direction;
    use p2p_proto::sync::GetBlockHeaders;
    use pathfinder_common::BlockNumber;

    use super::{fetch_block_headers, get_next_block_number};

    #[test]
    fn test_get_next_block_number() {
        let genesis = BlockNumber::new_or_panic(0);
        assert_eq!(get_next_block_number(genesis, Direction::Backward), None);
        assert_eq!(
            get_next_block_number(genesis, Direction::Forward),
            Some(BlockNumber::new_or_panic(1))
        );

        assert_eq!(
            get_next_block_number(BlockNumber::new_or_panic(1), Direction::Backward),
            Some(genesis)
        );
        assert_eq!(
            get_next_block_number(BlockNumber::new_or_panic(1), Direction::Forward),
            Some(BlockNumber::new_or_panic(2))
        );
    }

    #[test]
    fn test_fetch_block_headers_forward() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const COUNT: usize = 3;
        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[0].block.hash.0,
                count: COUNT as u64,
                size_limit: 100,
                direction: Direction::Forward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT)
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT)
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .skip(1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT)
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_forward_all_blocks() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[0].block.hash.0,
                count: test_data.blocks.len() as u64 + 10,
                size_limit: 100,
                direction: Direction::Forward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .skip(1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(test_data.blocks.len() - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_backward() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const COUNT: usize = 3;
        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[3].block.hash.0,
                count: COUNT as u64,
                size_limit: 100,
                direction: Direction::Backward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .take(COUNT - 1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .skip(1)
                .take(COUNT - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_backward_all_blocks() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[3].block.hash.0,
                count: test_data.blocks.len() as u64 + 10,
                size_limit: 100,
                direction: Direction::Backward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .take(test_data.blocks.len() - 1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .skip(1)
                .take(test_data.blocks.len() - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }
}
