//! Sync related data retrieval from storage as requested by other p2p clients
use anyhow::Context;
use p2p_proto as proto;
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use pathfinder_storage::{Storage, Transaction};

#[cfg(not(test))]
const MAX_HEADERS_COUNT: u64 = 1000;
#[cfg(test)]
const MAX_HEADERS_COUNT: u64 = 10;

const MAX_BODIES_COUNT: u64 = 100;
const MAX_STATE_UPDATES_COUNT: u64 = 100;

pub async fn get_block_headers(
    request: p2p_proto::sync::GetBlockHeaders,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::BlockHeaders> {
    spawn_blocking_get(request, storage, block_headers).await
}

pub async fn get_block_bodies(
    request: p2p_proto::sync::GetBlockBodies,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::BlockBodies> {
    spawn_blocking_get(request, storage, block_bodies).await
}

pub async fn get_state_diffs(
    request: p2p_proto::sync::GetStateDiffs,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::StateDiffs> {
    spawn_blocking_get(request, storage, state_diffs).await
}

pub async fn get_classes(
    request: p2p_proto::sync::GetClasses,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::Classes> {
    spawn_blocking_get(request, storage, classes).await
}

async fn spawn_blocking_get<Request, Response, Getter>(
    request: Request,
    storage: &Storage,
    getter: Getter,
) -> anyhow::Result<Response>
where
    Request: Send + 'static,
    Response: Send + 'static,
    Getter: FnOnce(Transaction<'_>, Request) -> anyhow::Result<Response> + Send + 'static,
{
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
        Ok(getter(tx, request)?)
    })
    .await
    .context("Database read panic or shutting down")?
}

fn block_headers(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetBlockHeaders,
) -> anyhow::Result<p2p_proto::sync::BlockHeaders> {
    let mut count = std::cmp::min(request.count, MAX_HEADERS_COUNT);
    let mut headers = Vec::new();

    let mut next_block_number = match BlockNumber::new(request.start_block) {
        Some(n) => Some(n),
        None => anyhow::bail!(
            "Unsupported block number value: {} > i64::MAX",
            request.start_block
        ),
    };

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(header) = tx.block_header(block_number.into())? else {
            // No such block
            break;
        };

        let transaction_count = tx
            .transaction_count(block_number.into())?
            .try_into()
            .context("Number of transactions exceeds 32 bits")?;

        headers.push(conv::header::from(header, transaction_count));

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto::sync::BlockHeaders { headers })
}

fn block_bodies(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetBlockBodies,
) -> anyhow::Result<p2p_proto::sync::BlockBodies> {
    let mut count = std::cmp::min(request.count, MAX_BODIES_COUNT);
    let mut block_bodies = Vec::new();

    let mut next_block_number = tx
        .block_id(BlockHash(request.start_block).into())?
        .map(|(n, _)| n);

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let transactions_and_receipts = match tx.transaction_data_for_block(block_number.into())? {
            Some(x) if !x.is_empty() => x,
            // No such block
            Some(_) | None => break,
        };

        let (transactions, receipts) = transactions_and_receipts
            .into_iter()
            .map(|tr| conv::body::from(tr))
            .unzip();

        block_bodies.push(p2p_proto::common::BlockBody {
            transactions,
            receipts,
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto::sync::BlockBodies { block_bodies })
}

fn state_diffs(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetStateDiffs,
) -> anyhow::Result<p2p_proto::sync::StateDiffs> {
    let mut count = std::cmp::min(request.count, MAX_STATE_UPDATES_COUNT);
    let mut block_state_updates = Vec::new();

    let mut next_block_number = tx
        .block_id(BlockHash(request.start_block).into())?
        .map(|(n, _)| n);

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(block_hash) = tx.block_id(block_number.into())?.map(|(_, h)| h) else {
            // No such block
            break;
        };

        let Some(state_diff) = tx.state_diff(block_number.into())? else {
            // No such state update, shouldn't happen with a single source of truth in L2...
            break;
        };

        block_state_updates.push(p2p_proto::sync::BlockStateUpdateWithHash {
            block_hash: block_hash.0,
            state_update: conv::state_update::from(state_diff),
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto::sync::StateDiffs {
        block_state_updates,
    })
}

fn classes(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetClasses,
) -> anyhow::Result<p2p_proto::sync::Classes> {
    let mut classes = Vec::new();
    for hash in request.class_hashes {
        let Some(class) = tx.class_definition(ClassHash(hash))? else {
            break;
        };

        classes.push(p2p_proto::common::RawClass { class });
    }

    Ok(p2p_proto::sync::Classes { classes })
}

/// Workaround for the orphan rule - implement conversion traits for types ourside our crate.
mod conv {
    pub(super) mod header {
        use pathfinder_common::BlockHeader;

        pub fn from(header: BlockHeader, transaction_count: u32) -> p2p_proto::common::BlockHeader {
            p2p_proto::common::BlockHeader {
                hash: header.hash.0,
                parent_hash: header.parent_hash.0,
                number: header.number.get(),
                state_commitment: header.state_commitment.0,
                storage_commitment: header.storage_commitment.0,
                class_commitment: header.class_commitment.0,
                sequencer_address: header.sequencer_address.0,
                timestamp: header.timestamp.get(),
                gas_price: header.gas_price.0.into(),
                transaction_count: transaction_count,
                transaction_commitment: header.transaction_commitment.0,
                // FIXME
                event_count: 0,
                event_commitment: header.event_commitment.0,
                starknet_version: header.starknet_version.take_inner(),
            }
        }
    }

    pub(super) mod body {
        use p2p_proto::common::{
            execution_resources::BuiltinInstanceCounter, invoke_transaction::EntryPoint,
            CommonTransactionReceiptProperties, DeclareTransaction, DeclareTransactionReceipt,
            DeployAccountTransaction, DeployAccountTransactionReceipt, DeployTransaction,
            DeployTransactionReceipt, Event, ExecutionResources, InvokeTransaction,
            InvokeTransactionReceipt, MessageToL1, MessageToL2, Receipt, Transaction,
        };
        use pathfinder_common::{Fee, L1ToL2MessageNonce, TransactionNonce};
        use stark_hash::Felt;
        use starknet_gateway_types::reply::transaction as gw;

        pub fn from((gw_t, gw_r): (gw::Transaction, gw::Receipt)) -> (Transaction, Receipt) {
            let common = CommonTransactionReceiptProperties {
                transaction_hash: gw_t.hash().0,
                transaction_index: gw_r
                    .transaction_index
                    .get()
                    .try_into()
                    .expect("Transaction index fits in 32 bits"),
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
                consumed_message: gw_r.l1_to_l2_consumed_message.map(|x| MessageToL2 {
                    from_address: x.from_address.0,
                    payload: x.payload.into_iter().map(|e| e.0).collect(),
                    to_address: *x.to_address.get(),
                    entry_point_selector: x.selector.0,
                    nonce: x.nonce.unwrap_or(L1ToL2MessageNonce::ZERO).0,
                }),
                execution_resources: {
                    let x = gw_r.execution_resources.unwrap_or_default();
                    let b = match x.builtin_instance_counter {
                        gw::execution_resources::BuiltinInstanceCounter::Normal(n) => n,
                        gw::execution_resources::BuiltinInstanceCounter::Empty(_) => {
                            Default::default()
                        }
                    };
                    ExecutionResources {
                        builtin_instance_counter: BuiltinInstanceCounter {
                            bitwise_builtin: b.bitwise_builtin,
                            ecdsa_builtin: b.ecdsa_builtin,
                            ec_op_builtin: b.ec_op_builtin,
                            output_builtin: b.output_builtin,
                            pedersen_builtin: b.pedersen_builtin,
                            range_check_builtin: b.range_check_builtin,
                        },
                        n_steps: x.n_steps,
                        n_memory_holes: x.n_memory_holes,
                    }
                },
            };

            let version = Felt::from_be_slice(gw_t.version().0.as_bytes())
                .expect("Transaction version fits into felt");

            match gw_t {
                gw::Transaction::Declare(
                    gw::DeclareTransaction::V0(t) | gw::DeclareTransaction::V1(t),
                ) => {
                    let r = Receipt::Declare(DeclareTransactionReceipt { common });
                    let t = Transaction::Declare(DeclareTransaction {
                        class_hash: t.class_hash.0,
                        sender_address: *t.sender_address.get(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: t.nonce.0,
                        version,
                        casm_hash: Felt::ZERO,
                    });
                    (t, r)
                }
                gw::Transaction::Declare(gw::DeclareTransaction::V2(t)) => {
                    let r = Receipt::Declare(DeclareTransactionReceipt { common });
                    let t = Transaction::Declare(DeclareTransaction {
                        class_hash: t.class_hash.0,
                        sender_address: *t.sender_address.get(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: t.nonce.0,
                        version,
                        casm_hash: t.compiled_class_hash.0,
                    });
                    (t, r)
                }
                gw::Transaction::Deploy(t) => {
                    let r = Receipt::Deploy(DeployTransactionReceipt {
                        common,
                        contract_address: *t.contract_address.get(),
                    });
                    let t = Transaction::Deploy(DeployTransaction {
                        class_hash: t.class_hash.0,
                        contract_address_salt: t.contract_address_salt.0,
                        constructor_calldata: t
                            .constructor_calldata
                            .into_iter()
                            .map(|x| x.0)
                            .collect(),
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
                        constructor_calldata: t
                            .constructor_calldata
                            .into_iter()
                            .map(|x| x.0)
                            .collect(),
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
                        sender_address: *t.sender_address.get(),
                        deprecated_entry_point_selector: match t.entry_point_type {
                            Some(gw::EntryPointType::External) => {
                                Some(EntryPoint::External(t.entry_point_selector.0))
                            }
                            Some(gw::EntryPointType::L1Handler) => {
                                Some(EntryPoint::L1Handler(t.entry_point_selector.0))
                            }
                            None => Some(EntryPoint::Unspecified(t.entry_point_selector.0)),
                        },
                        calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: TransactionNonce::ZERO.0,
                        version,
                    });
                    (t, r)
                }
                gw::Transaction::Invoke(gw::InvokeTransaction::V1(t)) => {
                    let r = Receipt::Invoke(InvokeTransactionReceipt { common });
                    let t = Transaction::Invoke(InvokeTransaction {
                        sender_address: *t.sender_address.get(),
                        deprecated_entry_point_selector: None,
                        calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: t.nonce.0,
                        version,
                    });
                    (t, r)
                }
                gw::Transaction::L1Handler(t) => {
                    let r = Receipt::L1Handler(p2p_proto::common::L1HandlerTransactionReceipt {
                        common,
                    });
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

    pub(super) mod state_update {
        use p2p_proto::propagation::{
            BlockStateUpdate, ContractDiff, DeclaredClass, DeployedContract, ReplacedClass,
            StorageDiff,
        };
        use pathfinder_storage::types::state_update::StateDiff;
        use stark_hash::Felt;
        use std::collections::HashMap;

        pub fn from(x: StateDiff) -> BlockStateUpdate {
            BlockStateUpdate {
                contract_diffs: {
                    // Create addr -> diff mapping with nonces set to 0
                    let mut lut: HashMap<Felt, ContractDiff> = x
                        .storage_diffs
                        .into_iter()
                        .map(|d| {
                            (
                                *d.address.get(),
                                ContractDiff {
                                    contract_address: *d.address.get(),
                                    nonce: Felt::ZERO,
                                    storage_diffs: d
                                        .storage_entries
                                        .into_iter()
                                        .map(|e| StorageDiff {
                                            key: *e.key.get(),
                                            value: e.value.0,
                                        })
                                        .collect(),
                                },
                            )
                        })
                        .collect();
                    // Update nonces in the mapping, create entries for missing addrs
                    x.nonces.into_iter().for_each(|n| {
                        let contract_address = *n.contract_address.get();
                        let nonce = n.nonce.0;
                        lut.entry(contract_address)
                            .and_modify(|e| e.nonce = nonce)
                            .or_insert(ContractDiff {
                                contract_address,
                                nonce,
                                storage_diffs: vec![],
                            });
                    });
                    lut.into_values().collect()
                },
                deployed_contracts: x
                    .deployed_contracts
                    .into_iter()
                    .map(|c| DeployedContract {
                        contract_address: *c.address.get(),
                        class_hash: c.class_hash.0,
                    })
                    .collect(),
                declared_cairo_classes: x
                    .declared_contracts
                    .into_iter()
                    .map(|c| c.class_hash.0)
                    .collect(),
                declared_classes: x
                    .declared_sierra_classes
                    .into_iter()
                    .map(|c| DeclaredClass {
                        sierra_hash: c.class_hash.0,
                        casm_hash: c.compiled_class_hash.0,
                    })
                    .collect(),
                replaced_classes: x
                    .replaced_classes
                    .into_iter()
                    .map(|c| ReplacedClass {
                        contract_address: *c.address.get(),
                        class_hash: c.class_hash.0,
                    })
                    .collect(),
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
    use super::super::client::conv;
    use super::*;
    use super::{block_headers, get_next_block_number};
    use ::fake::Dummy;
    use fake::{Fake, Faker};
    use http::request;
    use p2p_proto::sync::Direction;
    use p2p_proto::sync::GetBlockHeaders;
    use pathfinder_common::{BlockHeader, BlockNumber};
    use pathfinder_storage::{fake2, Storage};
    use proptest::prelude::*;
    use quickcheck::Arbitrary;
    use quickcheck_macros::quickcheck;

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

    /*
        const NUM_BLOCKS_IN_DB: u64 = super::MAX_HEADERS_COUNT * 2;

        #[derive(Clone, Debug)]
        struct ValidGetBlockHeadersFixture(p2p_proto::sync::GetBlockHeaders);

        impl Arbitrary for ValidGetBlockHeadersFixture {
            fn arbitrary(_: &mut quickcheck::Gen) -> Self {
                // Include values beyond highest block in DB
                let start_block = (0..(NUM_BLOCKS_IN_DB * 2)).fake();
                // Include values beyond the max allowed number of elements in reply
                let count = (0..NUM_BLOCKS_IN_DB).fake();

                Self(p2p_proto::sync::GetBlockHeaders {
                    start_block,
                    count,
                    size_limit: Faker.fake(), // FIXME once this field matters
                    direction: Faker.fake(),
                })
            }
        }

        #[quickcheck]
        fn requested_block_headers_match_storage(request: ValidGetBlockHeadersFixture) -> bool {
            let request = request.0;
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();

            let backward = request.direction == Direction::Backward;
            let start: usize = request.start_block.try_into().unwrap();
            let capped_len = std::cmp::min(request.count, super::MAX_HEADERS_COUNT)
                .try_into()
                .unwrap();

            let from_db = fake2::with_n_blocks(&storage, NUM_BLOCKS_IN_DB.try_into().unwrap())
                .into_iter()
                .map(|(header, _, _)| header);

            let from_proto = block_headers(tx, request)
                .unwrap()
                .headers
                .into_iter()
                .map(|header| super::super::client::conv::header::from_p2p(header));

            if backward {
                from_db
                    .skip(start.saturating_sub(capped_len))
                    .take(capped_len)
                    .eq(from_proto.rev())
            } else {
                from_db.skip(start).take(capped_len).eq(from_proto)
            }
        }
    */

    const NUM_BLOCKS: u64 = super::MAX_HEADERS_COUNT * 2;

    mod block_headers {
        use super::super::MAX_HEADERS_COUNT;
        use super::*;
        use crate::p2p_network::client::conv::header;

        proptest! {
            // FIXME pick a value that allows to run sufficient number of iterations
            // but what about test execution time?
            // run them separately?
            #![proptest_config(ProptestConfig::with_cases(50))]

            #[test]
            fn block_headers_forward(start_block in 0..(NUM_BLOCKS * 2), count in 0..(NUM_BLOCKS * 2)) {
                let storage = Storage::in_memory().unwrap();

                let from_db = fake2::with_n_blocks(&storage, NUM_BLOCKS.try_into().unwrap())
                    .into_iter()
                    .skip(start_block.try_into().unwrap())
                    .take(std::cmp::min(count, MAX_HEADERS_COUNT).try_into().unwrap())
                    .map(|(header, _, _)| header).collect::<Vec<_>>();

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let request = p2p_proto::sync::GetBlockHeaders {
                    start_block,
                    count,
                    // FIXME once size_limit is really used
                    size_limit: Faker.fake(),
                    direction: Direction::Forward
                };

                let from_p2p = block_headers(tx, request)
                    .unwrap()
                    .headers
                    .into_iter()
                    .map(|header| header::from_p2p(header)).collect::<Vec<_>>();

                prop_assert_eq!(from_p2p, from_db)
            }

            #[test]
            fn block_headers_backward(start_block in 0..(NUM_BLOCKS * 2), count in 0..(NUM_BLOCKS * 2)) {
                let storage = Storage::in_memory().unwrap();

                let from_db = fake2::with_n_blocks(&storage, NUM_BLOCKS.try_into().unwrap())
                    .into_iter()
                    .take((start_block + 1).try_into().unwrap())
                    .rev()
                    .take(std::cmp::min(count, MAX_HEADERS_COUNT).try_into().unwrap())
                    .map(|(header, _, _)| header).collect::<Vec<_>>();

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let request = p2p_proto::sync::GetBlockHeaders {
                    start_block,
                    count,
                    // FIXME once size_limit is really used
                    size_limit: Faker.fake(),
                    direction: Direction::Backward
                };

                let from_p2p = block_headers(tx, request)
                    .unwrap()
                    .headers
                    .into_iter()
                    .map(|header| header::from_p2p(header)).collect::<Vec<_>>();

                if start_block >= NUM_BLOCKS {
                    prop_assert!(from_p2p.is_empty())
                } else {
                    prop_assert_eq!(from_p2p, from_db)
                }
            }
        }

        #[test]
        fn unsupported_start_block_value() {
            let request = p2p_proto::sync::GetBlockHeaders {
                start_block: (i64::MAX as u64 + 1),
                count: Faker.fake(),
                size_limit: Faker.fake(),
                direction: Faker.fake(),
            };

            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            assert!(block_headers(tx, request).is_err());
        }
    }

    #[test]
    fn requested_block_headers_match_storage2() {
        let storage = Storage::in_memory().unwrap();
        let from_db = fake2::with_n_blocks(&storage, 3)
            .into_iter()
            .map(|(header, _, _)| header)
            .collect::<Vec<_>>();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let from_proto = block_headers(
            tx,
            p2p_proto::sync::GetBlockHeaders {
                start_block: 0,
                count: 100,
                size_limit: 1000000,
                direction: Direction::Forward,
            },
        )
        .unwrap()
        .headers
        .into_iter()
        .map(|proto_header| super::super::client::conv::header::from_p2p(proto_header))
        .collect::<Vec<_>>();
        pretty_assertions::assert_eq!(from_db, from_proto);
    }

    #[cfg(DISABLED)]
    mod disabled {

        #[test]
        fn test_fetch_block_headers_forward() {
            let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();

            const COUNT: usize = 3;
            let headers = fetch_block_headers(
                tx,
                GetBlockHeaders {
                    start_block: test_data.headers[0].number.get(),
                    count: COUNT as u64,
                    size_limit: 100,
                    direction: Direction::Forward,
                },
            )
            .unwrap();

            assert_eq!(
                headers.iter().map(|h| h.number).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .take(COUNT)
                    .map(|b| b.number.get())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .take(COUNT)
                    .map(|b| b.timestamp.get())
                    .collect::<Vec<_>>()
            );

            // check that the parent hashes are correct
            assert_eq!(
                headers
                    .iter()
                    .skip(1)
                    .map(|h| h.parent_hash)
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .take(COUNT - 1)
                    .map(|b| b.hash.0)
                    .collect::<Vec<_>>()
            );

            // check that event & transaction commitments match
            assert_eq!(
                headers
                    .iter()
                    .map(|h| (h.event_commitment, h.transaction_commitment))
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .take(COUNT)
                    .map(|b| (b.event_commitment.0, b.transaction_commitment.0))
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
                    start_block: test_data.headers[0].number.get(),
                    count: test_data.headers.len() as u64 + 10,
                    size_limit: 100,
                    direction: Direction::Forward,
                },
            )
            .unwrap();

            assert_eq!(
                headers.iter().map(|h| h.number).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .map(|b| b.number.get())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .map(|b| b.timestamp.get())
                    .collect::<Vec<_>>()
            );

            // check that the parent hashes are correct
            assert_eq!(
                headers
                    .iter()
                    .skip(1)
                    .map(|h| h.parent_hash)
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .take(test_data.headers.len() - 1)
                    .map(|b| b.hash.0)
                    .collect::<Vec<_>>()
            );

            // check that event & transaction commitments match
            assert_eq!(
                headers
                    .iter()
                    .map(|h| (h.event_commitment, h.transaction_commitment))
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .map(|b| (b.event_commitment.0, b.transaction_commitment.0))
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
                    start_block: test_data.headers[3].number.get(),
                    count: COUNT as u64,
                    size_limit: 100,
                    direction: Direction::Backward,
                },
            )
            .unwrap();

            assert_eq!(
                headers.iter().map(|h| h.number).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .take(COUNT)
                    .map(|b| b.number.get())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .take(COUNT)
                    .map(|b| b.timestamp.get())
                    .collect::<Vec<_>>()
            );

            // check that the parent hashes are correct
            assert_eq!(
                headers
                    .iter()
                    .take(COUNT - 1)
                    .map(|h| h.parent_hash)
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .skip(1)
                    .take(COUNT - 1)
                    .map(|b| b.hash.0)
                    .collect::<Vec<_>>()
            );

            // check that event & transaction commitments match
            assert_eq!(
                headers
                    .iter()
                    .map(|h| (h.event_commitment, h.transaction_commitment))
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .take(COUNT)
                    .map(|b| (b.event_commitment.0, b.transaction_commitment.0))
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
                    start_block: test_data.headers[3].number.get(),
                    count: test_data.headers.len() as u64 + 10,
                    size_limit: 100,
                    direction: Direction::Backward,
                },
            )
            .unwrap();

            assert_eq!(
                headers.iter().map(|h| h.number).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .map(|b| b.number.get())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .map(|b| b.timestamp.get())
                    .collect::<Vec<_>>()
            );

            // check that the parent hashes are correct
            assert_eq!(
                headers
                    .iter()
                    .take(test_data.headers.len() - 1)
                    .map(|h| h.parent_hash)
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .skip(1)
                    .take(test_data.headers.len() - 1)
                    .map(|b| b.hash.0)
                    .collect::<Vec<_>>()
            );

            // check that event & transaction commitments match
            assert_eq!(
                headers
                    .iter()
                    .map(|h| (h.event_commitment, h.transaction_commitment))
                    .collect::<Vec<_>>(),
                test_data
                    .headers
                    .iter()
                    .rev()
                    .map(|b| (b.event_commitment.0, b.transaction_commitment.0))
                    .collect::<Vec<_>>()
            );
        }
    }
}
