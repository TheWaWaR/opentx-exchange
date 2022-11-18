use anyhow::{anyhow, Result};
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{CellCollector, CellQueryOptions, DefaultCellCollector, ValueRangeOption},
    unlock::OmniLockConfig,
    Address, AddressPayload, NetworkType, ScriptId,
};
use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionView},
    packed::{CellOutput, Script},
    prelude::*,
    H160,
};

use crate::cell_dep::{CellDepName, CellDeps};

pub fn build_omni_lock_config(sighash_address: &Address) -> Result<OmniLockConfig> {
    let script = Script::from(sighash_address);
    if script.code_hash().as_slice() != SIGHASH_TYPE_HASH.as_bytes() {
        return Err(anyhow!(
            "address is not sighash address, code hash: {:?}",
            script.code_hash()
        ));
    }
    if script.hash_type() != ScriptHashType::Type.into() {
        return Err(anyhow!(
            "address is not sighash address, hash type: {:?}",
            script.hash_type()
        ));
    }
    if script.args().raw_data().len() != 20 {
        return Err(anyhow!(
            "address is not sighash address, args.length: {}",
            script.args().raw_data().len()
        ));
    }

    let arg = H160::from_slice(script.args().raw_data().as_ref()).unwrap();
    let mut config = OmniLockConfig::new_pubkey_hash(arg);
    config.set_opentx_mode();
    Ok(config)
}

pub fn build_omni_lock_address(
    sighash_address: &Address,
    cell_deps: &CellDeps,
    mainnet: bool,
) -> Result<Address> {
    let config = build_omni_lock_config(sighash_address)?;

    let omni_script_id = &cell_deps
        .get_item(&CellDepName::OmniLock)
        .expect("omni-lock cell dep")
        .script_id;
    let network = if mainnet {
        NetworkType::Mainnet
    } else {
        NetworkType::Testnet
    };
    let payload = AddressPayload::new_full(
        omni_script_id.hash_type.clone().into(),
        omni_script_id.code_hash.pack(),
        config.build_args(),
    );
    Ok(Address::new(network, payload, true))
}

pub fn query_udt_amount(
    owner: &Address,
    address: &Address,
    cell_deps: &CellDeps,
    ckb_rpc: &str,
) -> Result<Vec<u128>> {
    let xudt_dep_item = cell_deps
        .get_item(&CellDepName::Xudt)
        .expect("xudt cell dep");
    let xudt_script_id = ScriptId::from(xudt_dep_item.script_id.clone());
    let type_script = {
        let owner_lock_hash = Script::from(owner).calc_script_hash();
        xudt_script_id
            .dummy_script()
            .as_builder()
            .args(owner_lock_hash.as_bytes().pack())
            .build()
    };
    let lock_script = Script::from(address);

    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let mut query = CellQueryOptions::new_lock(lock_script);
    query.data_len_range = Some(ValueRangeOption::new_min(16));
    query.secondary_script = Some(type_script);
    let (cells, _) = cell_collector.collect_live_cells(&query, false)?;
    Ok(cells
        .into_iter()
        .map(|cell| u128::from_le_bytes(cell.output_data.as_ref()[0..16].try_into().unwrap()))
        .collect::<Vec<_>>())
}

pub fn send_tx_to_ckb(tx: TransactionView, ckb_rpc: &str) -> Result<()> {
    let json_tx = json_types::TransactionView::from(tx);
    log::debug!("> tx: {}", serde_json::to_string_pretty(&json_tx)?);
    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let tx_hash = CkbRpcClient::new(ckb_rpc)
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    log::info!(">>> tx sent to CKB node: {:#x}! <<<", tx_hash);
    Ok(())
}

pub fn explain_orders(txs: &[TransactionView], cell_deps: &CellDeps, ckb_rpc: &str) -> Result<()> {
    let omni_dep_item = cell_deps
        .get_item(&CellDepName::OmniLock)
        .expect("omni cell dep");
    let xudt_dep_item = cell_deps
        .get_item(&CellDepName::Xudt)
        .expect("xudt cell dep");
    let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());
    let xudt_script_id = ScriptId::from(xudt_dep_item.script_id.clone());
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());

    let mut ckb_client = CkbRpcClient::new(ckb_rpc);
    let network = get_network_type(&mut ckb_client)?;

    let print_cell = |label, idx, output: CellOutput, data: Bytes| {
        let address = Address::new(network, AddressPayload::from(output.lock()), true);
        let lock_script_id = ScriptId::from(&output.lock());
        let lock_category = if lock_script_id == sighash_script_id {
            "sighash"
        } else if lock_script_id == omni_script_id {
            "omni"
        } else {
            "unknown"
        };
        log::info!(
            "  {}[{}]: {} lock, address={}",
            label,
            idx,
            lock_category,
            address
        );
        if output
            .type_()
            .to_opt()
            .map(|script| ScriptId::from(&script))
            .as_ref()
            == Some(&xudt_script_id)
        {
            let amount = u128::from_le_bytes(data.as_ref()[0..16].try_into().unwrap());
            log::info!("  {}[{}]: udt-amount={}", label, idx, amount);
        };
    };

    for (tx_idx, tx) in txs.iter().enumerate() {
        log::info!("orders[{}]: tx-hash={:#x}", tx_idx, tx.hash());
        for (input_idx, input) in tx.inputs().into_iter().enumerate() {
            let out_point = input.previous_output();
            let result = ckb_client.get_live_cell(out_point.clone().into(), true)?;
            if result.status != "live" {
                log::warn!(
                    "invalid input cell status: {}, out_point: {:?}",
                    result.status,
                    out_point
                );
                break;
            }
            let cell = result.cell.unwrap();
            let output = CellOutput::from(cell.output);
            let data = cell.data.unwrap().content.into_bytes();
            print_cell("inputs", input_idx, output, data);
        }
        for (output_idx, (output, data)) in tx.outputs_with_data_iter().into_iter().enumerate() {
            print_cell("outputs", output_idx, output, data);
        }
    }
    Ok(())
}

pub fn get_network_type(rpc_client: &mut CkbRpcClient) -> Result<NetworkType> {
    log::debug!("getting network type...");
    let chain_info = rpc_client.get_blockchain_info()?;
    NetworkType::from_raw_str(chain_info.chain.as_str())
        .ok_or_else(|| anyhow!("invalid chain info: {}", chain_info.chain))
}

pub fn build_amount_range(min: Option<u128>, max: Option<u128>) -> Option<(u128, u128)> {
    match (min, max) {
        (None, None) => None,
        (Some(value_min), None) => Some((value_min, u128::max_value())),
        (None, Some(value_max)) => Some((0, value_max)),
        (Some(value_min), Some(value_max)) => Some((value_min, value_max)),
    }
}
