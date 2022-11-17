use anyhow::Result;
use ckb_sdk::{Address, ScriptId};
use ckb_types::{
    core::TransactionView,
    packed::{Script, Transaction},
    prelude::*,
};

use crate::cell_dep::{CellDepName, CellDeps};
use crate::rpc::ExchangeClient;

pub fn send_order(rpc: &str, tx: TransactionView) -> Result<()> {
    let mut client = ExchangeClient::new(rpc);
    let result = client.send_order(tx.data().into())?;
    log::info!("send order result: {}", result);
    Ok(())
}

pub fn query_by_address(rpc: &str, address: &Address) -> Result<Vec<TransactionView>> {
    let lock_script = Script::from(address);
    let mut client = ExchangeClient::new(rpc);
    let json_txs = client.query_orders_by_lock_script(lock_script.into())?;
    Ok(json_txs
        .into_iter()
        .map(|json_tx| Transaction::from(json_tx.inner).into_view())
        .collect())
}

fn query_by_order(
    rpc: &str,
    owner: &Address,
    amount_range: Option<(u128, u128)>,
    cell_deps: &CellDeps,
    is_sell: bool,
) -> Result<Vec<TransactionView>> {
    let xudt_dep_item = cell_deps
        .get_item(&CellDepName::Xudt)
        .expect("xudt cell dep");
    let xudt_script_id = ScriptId::from(xudt_dep_item.script_id.clone());
    let owner_script_hash = Script::from(owner).calc_script_hash();
    let udt_script = xudt_script_id
        .dummy_script()
        .as_builder()
        .args(owner_script_hash.as_bytes().pack())
        .build();
    let mut client = ExchangeClient::new(rpc);
    let amount_range = amount_range.map(|(min, max)| [min.into(), max.into()]);
    let json_txs = client.query_orders_by_udt_script(udt_script.into(), amount_range, is_sell)?;
    Ok(json_txs
        .into_iter()
        .map(|json_tx| Transaction::from(json_tx.inner).into_view())
        .collect())
}

pub fn query_by_sell(
    rpc: &str,
    owner: &Address,
    amount_range: Option<(u128, u128)>,
    cell_deps: &CellDeps,
) -> Result<Vec<TransactionView>> {
    query_by_order(rpc, owner, amount_range, cell_deps, true)
}

pub fn query_by_buy(
    rpc: &str,
    owner: &Address,
    amount_range: Option<(u128, u128)>,
    cell_deps: &CellDeps,
) -> Result<Vec<TransactionView>> {
    query_by_order(rpc, owner, amount_range, cell_deps, false)
}
