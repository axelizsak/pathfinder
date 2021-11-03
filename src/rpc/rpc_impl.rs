//! Implementation of JSON-RPC endpoints.
use crate::{
    rpc::rpc_trait::RpcApiServer,
    sequencer::{reply, request, Client},
};
use jsonrpsee::types::{
    async_trait,
    error::{CallError, Error},
};
use reqwest::Url;
use web3::types::{H256, U256};

/// Special tag values used in the RPC API.
mod tags {
    pub const LATEST: &str = "latest";
    pub const EARLIEST: &str = "earliest";
}

/// Implements JSON-RPC endpoints.
///
/// __TODO__ directly calls [sequencer::Client](crate::sequencer::Client) until storage is implemented.
pub struct RpcImpl(Client);

impl RpcImpl {
    /// Constructs a sequencer client for the __alpha2__ network.
    pub fn new() -> Self {
        let module = Client::new(Url::parse("https://alpha3.starknet.io/").expect("Valid URL."));
        Self(module)
    }
}

#[async_trait]
impl RpcApiServer for RpcImpl {
    async fn block_number(&self) -> Result<U256, Error> {
        // TODO get this from storage
        let block = self.0.latest_block().await?;
        Ok(block.block_id)
    }

    async fn get_block_by_hash(&self, block_hash: String) -> Result<reply::Block, Error> {
        // TODO get this from storage
        // TODO how do we calculate block_hash
        let block = match block_hash.as_str() {
            tags::LATEST => self.0.latest_block().await,
            tags::EARLIEST => self.0.block(U256::zero()).await,
            _ => todo!("Determine the type of hash required here."),
        }?;
        Ok(block)
    }

    async fn get_block_by_number(&self, block_number: String) -> Result<reply::Block, Error> {
        // TODO get this from storage
        // TODO earliest, latest, block_number
        let block = match block_number.as_str() {
            tags::LATEST => self.0.latest_block().await,
            tags::EARLIEST => self.0.block(U256::zero()).await,
            _ => {
                self.0
                    .block(
                        U256::from_str_radix(block_number.as_str(), 16)
                            .map_err(anyhow::Error::new)?,
                    )
                    .await
            }
        }?;
        Ok(block)
    }

    async fn get_transaction_by_hash(
        &self,
        transaction_hash: H256,
    ) -> Result<reply::Transaction, Error> {
        // TODO get this from storage
        let txn = self.0.transaction(transaction_hash).await?;
        Ok(txn)
    }

    async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: String,
        transaction_index: usize,
    ) -> Result<reply::transaction::Transaction, Error> {
        // TODO get this from storage
        // TODO how do we calculate block_hash
        let block = self.get_block_by_hash(block_hash).await?;

        if transaction_index >= block.transactions.len() {
            return Err(Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                "transaction index {} not found",
                transaction_index
            ))));
        }
        Ok(block.transactions[transaction_index].clone())
    }

    async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: String,
        transaction_index: usize,
    ) -> Result<reply::transaction::Transaction, Error> {
        // TODO get this from storage
        // TODO earliest, latest, block_number
        let block = self.get_block_by_number(block_number).await?;

        if transaction_index >= block.transactions.len() {
            return Err(Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                "transaction index {} not found",
                transaction_index
            ))));
        }
        Ok(block.transactions[transaction_index].clone())
    }

    async fn get_storage(
        &self,
        contract_address: H256,
        key: U256,
        block_id: Option<U256>,
    ) -> Result<H256, Error> {
        // TODO get this from storage
        // TODO calculate key
        let storage = self.0.storage(contract_address, key, block_id).await?;
        let x: [u8; 32] = storage.into();
        Ok(H256::from(x))
    }

    async fn get_code(
        &self,
        contract_address: H256,
        block_id: Option<U256>,
    ) -> Result<reply::Code, Error> {
        // TODO get this from storage
        let storage = self.0.code(contract_address, block_id).await?;
        Ok(storage)
    }

    async fn call(
        &self,
        contract_address: H256,
        call_data: Vec<U256>,
        entry_point: H256,
        signature: Vec<U256>,
        block_id: Option<U256>,
    ) -> Result<reply::Call, Error> {
        // TODO calculate entry point?
        let call = self
            .0
            .call(
                request::Call {
                    calldata: call_data,
                    contract_address,
                    entry_point_selector: entry_point,
                    signature,
                },
                block_id,
            )
            .await?;
        Ok(call)
    }
}
