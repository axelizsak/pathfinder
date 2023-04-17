use std::str::FromStr;

use pathfinder_common::{BlockNumber, ClassHash, ContractNonce, StorageAddress, StorageValue};
use stark_hash::Felt;
use starknet_in_rust::core::errors::state_errors::StateError;

use starknet_in_rust::services::api::contract_classes::compiled_class::CompiledClass;
use starknet_in_rust::services::api::contract_classes::deprecated_contract_class::ContractClass;
use starknet_in_rust::state::state_api::StateReader;
use starknet_in_rust::{felt::Felt252, CasmContractClass};

#[derive(Clone)]
pub struct PathfinderStateReader {
    pub storage: pathfinder_storage::Storage,
    pub block_number: Option<BlockNumber>,
}

impl PathfinderStateReader {
    fn state_block_id(&self) -> Option<pathfinder_storage::BlockId> {
        self.block_number.map(Into::into)
    }
}

impl StateReader for PathfinderStateReader {
    fn get_class_hash_at(
        &mut self,
        contract_address: &starknet_in_rust::utils::Address,
    ) -> Result<starknet_in_rust::utils::ClassHash, StateError> {
        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );

        let _span = tracing::debug_span!("get_class_hash_at", contract_address=%pathfinder_contract_address).entered();

        tracing::trace!("Getting class hash at contract");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))?;

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_anyhow_to_state_err)?;

        let class_hash = tx
            .contract_class_hash(block_id, pathfinder_contract_address)
            .map_err(|error| {
                tracing::error!(%error, "Failed to fetch contract class hash");
                StateError::CustomError(format!(
                    "Failed to fetch contract class hash for contract {}",
                    pathfinder_contract_address
                ))
            })?
            .ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))?;

        Ok(class_hash.0.to_be_bytes())
    }

    fn get_nonce_at(
        &mut self,
        contract_address: &starknet_in_rust::utils::Address,
    ) -> Result<Felt252, starknet_in_rust::core::errors::state_errors::StateError> {
        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );

        let _span =
            tracing::debug_span!("get_nonce_at", contract_address=%pathfinder_contract_address)
                .entered();

        tracing::trace!("Getting nonce for contract");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneNonce(contract_address.clone()))?;

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_anyhow_to_state_err)?;

        let nonce = tx
            .contract_nonce(pathfinder_contract_address, block_id)
            .map_err(|error| {
                tracing::error!(%error, "Failed to fetch contract nonce");
                StateError::CustomError(format!("Failed to fetch contract nonce: {}", error))
            })?
            .unwrap_or(ContractNonce(Felt::ZERO));

        Ok(nonce.0.into())
    }

    fn get_storage_at(
        &mut self,
        storage_entry: &starknet_in_rust::state::state_cache::StorageEntry,
    ) -> Result<Felt252, starknet_in_rust::core::errors::state_errors::StateError> {
        let (contract_address, storage_key) = storage_entry;
        let storage_key =
            StorageAddress::new(Felt::from_be_slice(storage_key).map_err(|_| {
                StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
            })?)
            .ok_or_else(|| {
                StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
            })?;

        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );

        let _span =
            tracing::debug_span!("get_storage_at", contract_address=%pathfinder_contract_address, %storage_key)
                .entered();

        tracing::trace!("Getting storage value");

        let Some(block_id) = self.state_block_id() else {
            return Ok(Felt::ZERO.into());
        };

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_anyhow_to_state_err)?;

        let storage_val = tx
            .storage_value(block_id, pathfinder_contract_address, storage_key)
            .map_err(|error| {
                tracing::error!(%error, %storage_key, "Failed to fetch storage value");
                StateError::CustomError(format!("Failed to fetch storage value: {}", error))
            })?
            .unwrap_or(StorageValue(Felt::ZERO));

        Ok(storage_val.0.into())
    }

    fn get_contract_class(
        &mut self,
        class_hash: &starknet_in_rust::utils::ClassHash,
    ) -> Result<CompiledClass, StateError> {
        let pathfinder_class_hash =
            ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

        let _span =
            tracing::debug_span!("get_compiled_class", class_hash=%pathfinder_class_hash).entered();

        tracing::trace!("Getting class");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneCompiledHash(*class_hash))?;

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_anyhow_to_state_err)?;

        if let Some(casm_definition) = tx
            .compiled_class_definition_at(block_id, pathfinder_class_hash)
            .map_err(map_anyhow_to_state_err)?
        {
            let casm_class: CasmContractClass =
                serde_json::from_slice(&casm_definition).map_err(|error| {
                    tracing::error!(%error, "Failed to parse CASM class definition");
                    StateError::CustomError(format!(
                        "Failed to parse CASM class definition: {}",
                        error
                    ))
                })?;
            return Ok(CompiledClass::Casm(casm_class.into()));
        }

        if let Some(definition) = tx
            .class_definition_at(block_id, pathfinder_class_hash)
            .map_err(map_anyhow_to_state_err)?
        {
            let definition = String::from_utf8(definition).map_err(|error| {
                tracing::error!(%error, "Failed to parse Cairo class definition to UTF-8 string");
                StateError::CustomError(format!(
                    "Failed to parse Cairo class definition as UTF-8: {}",
                    error
                ))
            })?;

            let contract_class = ContractClass::from_str(definition.as_str()).map_err(|error| {
                tracing::error!(%error, "Failed to parse class definition");
                StateError::CustomError(format!(
                    "Failed to parse Cairo class definition: {}",
                    error
                ))
            })?;

            return Ok(CompiledClass::Deprecated(contract_class.into()));
        }

        tracing::trace!(%pathfinder_class_hash, "Class definition not found");
        Err(StateError::NoneCompiledHash(*class_hash))
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: &starknet_in_rust::utils::ClassHash,
    ) -> Result<starknet_in_rust::utils::CompiledClassHash, StateError> {
        // should return the compiled class hash for a sierra class hash
        let pathfinder_class_hash =
            ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

        let _span =
            tracing::debug_span!("get_compiled_class_hash", %pathfinder_class_hash).entered();

        tracing::trace!("Getting compiled class hash");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneCompiledHash(*class_hash))?;

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_anyhow_to_state_err)?;

        let casm_hash = tx
            .compiled_class_hash_at(block_id, pathfinder_class_hash)
            .map_err(map_anyhow_to_state_err)?
            .ok_or(StateError::NoneCompiledHash(*class_hash))?;

        Ok(casm_hash.0.to_be_bytes())
    }
}

fn map_anyhow_to_state_err(
    error: anyhow::Error,
) -> starknet_in_rust::core::errors::state_errors::StateError {
    tracing::error!(%error, "Internal error in state reader");
    StateError::CustomError(format!("Internal error in state reader: {}", error))
}
