use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc::channel;

use anyhow::Result;
use ckb_jsonrpc_types::{Script, Transaction, TransactionView, Uint128};
use ckb_sdk::{
    traits::DefaultTransactionDependencyProvider, unlock::opentx::assembler::assemble_new_tx,
    CkbRpcClient, ScriptId,
};
use ckb_types::{packed, prelude::*, H256};
use dashmap::DashMap;
use jsonrpc_core::{Error, IoHandler, Result as RpcResult};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::ServerBuilder;
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;

use crate::cell_dep::{CellDepName, CellDeps};
use crate::util::send_tx_to_ckb;

#[rpc(server)]
pub trait ExchangeRpc {
    #[rpc(name = "send_order")]
    fn send_order(&self, tx: Transaction) -> RpcResult<String>;

    #[rpc(name = "query_orders_by_lock_script")]
    fn query_orders_by_lock_script(&self, lock_script: Script) -> RpcResult<Vec<TransactionView>>;

    #[rpc(name = "query_orders_by_udt_script")]
    fn query_orders_by_udt_script(
        &self,
        udt_script: Script,
        amount_range: Option<[Uint128; 2]>,
        is_sell: bool,
    ) -> RpcResult<Vec<TransactionView>>;
}

struct ExchangeRpcImpl {
    cell_deps: CellDeps,
    ckb_rpc: String,
    txs: DashMap<H256, TransactionView>,
    // index by inputs lock script
    txs_by_lock: DashMap<Script, HashSet<H256>>,
    // index by inputs type script
    txs_by_type: DashMap<Script, HashSet<H256>>,
    orders: DashMap<OrderKey, HashSet<H256>>,
}

impl ExchangeRpcImpl {
    fn remove_tx(&self, tx_hash: &H256) {
        self.txs.remove(tx_hash);
        self.txs_by_lock.retain(|_, hashes| {
            hashes.remove(tx_hash);
            !hashes.is_empty()
        });
        self.txs_by_type.retain(|_, hashes| {
            hashes.remove(tx_hash);
            !hashes.is_empty()
        });
        self.orders.retain(|_, hashes| {
            hashes.remove(tx_hash);
            !hashes.is_empty()
        });
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Default)]
struct OrderKey {
    sell_udt: Script,
    sell_amount: u128,
    buy_udt: Script,
    buy_amount: u128,
}

impl OrderKey {
    fn pair_order(&self) -> OrderKey {
        OrderKey {
            sell_udt: self.buy_udt.clone(),
            sell_amount: self.buy_amount,
            buy_udt: self.sell_udt.clone(),
            buy_amount: self.sell_amount,
        }
    }
}

impl ExchangeRpc for ExchangeRpcImpl {
    fn send_order(&self, tx: Transaction) -> RpcResult<String> {
        let mut ckb_client = CkbRpcClient::new(self.ckb_rpc.as_str());
        let omni_dep_item = self
            .cell_deps
            .get_item(&CellDepName::OmniLock)
            .expect("omni-lock cell dep");
        let xudt_dep_item = self
            .cell_deps
            .get_item(&CellDepName::Xudt)
            .expect("xudt cell dep");
        let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());
        let xudt_script_id = ScriptId::from(xudt_dep_item.script_id.clone());

        let mut lock_script_opt = None;
        #[allow(clippy::mutable_key_type)]
        let mut xudt_scripts = HashMap::new();
        for (input_idx, input) in tx.inputs.iter().enumerate() {
            let result = ckb_client
                .get_live_cell(input.previous_output.clone(), true)
                .map_err(|err| {
                    log::error!("get live cell error: {}", err);
                    Error::internal_error()
                })?;
            if result.status != "live" {
                return Err(Error::invalid_params("canceled transaction"));
            }
            let cell = result.cell.unwrap();
            if cell.output.lock.code_hash != omni_script_id.code_hash
                || cell.output.lock.hash_type != omni_script_id.hash_type.into()
            {
                return Err(Error::invalid_params(format!(
                    "inputs[{}] is not omni lock script",
                    input_idx,
                )));
            }
            if let Some(udt_script) = cell.output.type_.as_ref() {
                if lock_script_opt.is_none() {
                    lock_script_opt = Some(cell.output.lock);
                } else if lock_script_opt != Some(cell.output.lock) {
                    return Err(Error::invalid_params(
                        "all UDT cells must have same lock script",
                    ));
                }
                if ScriptId::from(&udt_script.clone().into()) == xudt_script_id {
                    let data = cell.data.unwrap().content.into_bytes();
                    let amount = u128::from_le_bytes(data.as_ref()[0..16].try_into().unwrap());
                    xudt_scripts.entry(udt_script.clone()).or_insert((0, 0)).0 += amount;
                }
            }
        }
        for (output_idx, output) in tx.outputs.iter().enumerate() {
            if let Some(udt_script) = output.type_.as_ref() {
                if lock_script_opt.is_none() {
                    lock_script_opt = Some(output.lock.clone());
                } else if lock_script_opt.as_ref() != Some(&output.lock) {
                    return Err(Error::invalid_params(
                        "all UDT cells must have same lock script",
                    ));
                }
                if ScriptId::from(&udt_script.clone().into()) == xudt_script_id {
                    let data = &tx.outputs_data[output_idx];
                    let amount = u128::from_le_bytes(data.as_bytes()[0..16].try_into().unwrap());
                    xudt_scripts.entry(udt_script.clone()).or_insert((0, 0)).1 += amount;
                }
            }
        }
        if xudt_scripts.len() != 2 {
            return Err(Error::invalid_params(format!(
                "The order must have exact 2 udt types, got: {}",
                xudt_scripts.len()
            )));
        }

        let mut order_key = OrderKey::default();
        for (type_script, (input_total, output_total)) in xudt_scripts.clone() {
            if input_total > output_total {
                order_key.sell_udt = type_script;
                order_key.sell_amount = input_total - output_total;
            } else {
                order_key.buy_udt = type_script;
                order_key.buy_amount = output_total - input_total;
            }
        }
        if order_key.sell_amount == 0 || order_key.buy_amount == 0 {
            return Err(Error::invalid_params(
                "This is not a exchange open transaction",
            ));
        }
        let tx_view = packed::Transaction::from(tx).into_view();
        if let Some(item) = self.orders.get(&order_key.pair_order()) {
            let omni_dep_item = self
                .cell_deps
                .get_item(&CellDepName::OmniLock)
                .expect("omni-lock cell dep");
            let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());
            if let Some(pair_tx_hash) = item.value().iter().next() {
                log::info!("matched tx: {:#x}", pair_tx_hash);
                let pair_tx = self.txs.get(pair_tx_hash).unwrap().value().clone();
                let pair_tx_view = packed::Transaction::from(pair_tx.inner).into_view();
                let tx_dep_provider =
                    DefaultTransactionDependencyProvider::new(self.ckb_rpc.as_str(), 0);
                let assembled_tx = assemble_new_tx(
                    vec![tx_view, pair_tx_view],
                    &tx_dep_provider,
                    omni_script_id.code_hash.pack(),
                )
                .map_err(|err| {
                    Error::invalid_params(format!(
                        "order matched, assemble tx with {:#x} failed, error: {}",
                        pair_tx_hash, err,
                    ))
                })?;
                let assembled_tx_hash: H256 = assembled_tx.hash().unpack();
                send_tx_to_ckb(assembled_tx, self.ckb_rpc.as_str()).map_err(|err| {
                    Error::invalid_params(format!("send assembled tx to ckb error: {}", err))
                })?;
                log::info!("remove matched tx: {:#x}", pair_tx_hash);
                self.remove_tx(pair_tx_hash);

                return Ok(format!(
                    "order pair success! matched tx: {:#x}, assembled tx: {:#x}",
                    pair_tx_hash, assembled_tx_hash
                ));
            }
        }

        let lock_script = lock_script_opt.unwrap();
        let tx_hash: H256 = tx_view.hash().unpack();
        self.txs
            .insert(tx_hash.clone(), TransactionView::from(tx_view));
        self.txs_by_lock
            .entry(lock_script)
            .or_insert_with(HashSet::new)
            .insert(tx_hash.clone());
        for (type_script, _) in xudt_scripts {
            self.txs_by_type
                .entry(type_script)
                .or_insert_with(HashSet::new)
                .insert(tx_hash.clone());
        }
        self.orders
            .entry(order_key)
            .or_insert_with(HashSet::new)
            .insert(tx_hash);
        Ok("order added".to_string())
    }

    fn query_orders_by_lock_script(&self, lock_script: Script) -> RpcResult<Vec<TransactionView>> {
        let txs: Vec<_> = self
            .txs_by_lock
            .get(&lock_script)
            .map(|tx_hashes| {
                tx_hashes
                    .iter()
                    .map(|tx_hash| self.txs.get(tx_hash).unwrap().clone())
                    .collect()
            })
            .unwrap_or_default();
        Ok(txs)
    }

    fn query_orders_by_udt_script(
        &self,
        udt_script: Script,
        amount_range: Option<[Uint128; 2]>,
        is_sell: bool,
    ) -> RpcResult<Vec<TransactionView>> {
        let tx_hashes: HashSet<_> = if let Some(hashes) = self.txs_by_type.get(&udt_script) {
            hashes.clone()
        } else {
            return Ok(Vec::new());
        };

        let mut ckb_client = CkbRpcClient::new(self.ckb_rpc.as_str());
        let mut canceled_txs = HashSet::new();
        let mut txs = Vec::new();
        for tx_hash in tx_hashes {
            let tx = self.txs.get(&tx_hash).unwrap();
            let mut input_total: u128 = 0;
            let mut output_total: u128 = 0;
            for input in &tx.inner.inputs {
                let result = ckb_client
                    .get_live_cell(input.previous_output.clone(), true)
                    .map_err(|err| {
                        log::error!("get live cell error: {}", err);
                        Error::internal_error()
                    })?;
                if result.status != "live" {
                    canceled_txs.insert(tx_hash.clone());
                    break;
                }
                let cell = result.cell.unwrap();
                if cell.output.type_.as_ref() == Some(&udt_script) {
                    let data = cell.data.unwrap().content.into_bytes();
                    let amount = u128::from_le_bytes(data.as_ref()[0..16].try_into().unwrap());
                    input_total += amount;
                }
            }
            if canceled_txs.contains(&tx_hash) {
                continue;
            }
            for (output_idx, output) in tx.inner.outputs.iter().enumerate() {
                if output.type_.as_ref() == Some(&udt_script) {
                    let data = &tx.inner.outputs_data[output_idx];
                    let amount = u128::from_le_bytes(data.as_bytes()[0..16].try_into().unwrap());
                    output_total += amount;
                }
            }
            if (is_sell && output_total >= input_total) || (!is_sell && input_total >= output_total)
            {
                continue;
            }
            if let Some([min, max]) = amount_range {
                let delta = if is_sell {
                    input_total - output_total
                } else {
                    output_total - input_total
                };
                if delta < min.value() || delta >= max.value() {
                    continue;
                }
            }
            txs.push(tx.clone());
        }

        // clean up canceled transactions
        for tx_hash in canceled_txs {
            log::info!("remove canceled tx: {:#x}", tx_hash);
            self.remove_tx(&tx_hash);
        }
        Ok(txs)
    }
}

pub fn start(bind: &str, cell_deps: &Path, ckb_rpc: &str) -> Result<()> {
    let content = fs::read_to_string(cell_deps)?;
    let cell_deps: CellDeps = serde_json::from_str(&content)?;
    let rpc_impl = ExchangeRpcImpl {
        cell_deps,
        ckb_rpc: ckb_rpc.to_string(),
        txs: DashMap::new(),
        txs_by_lock: DashMap::new(),
        txs_by_type: DashMap::new(),
        orders: DashMap::new(),
    };

    let bind_addr: SocketAddr = bind.parse()?;
    let mut io_handler = IoHandler::new();
    io_handler.extend_with(rpc_impl.to_delegate());
    let server = ServerBuilder::new(io_handler)
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Null,
            AccessControlAllowOrigin::Any,
        ]))
        .health_api(("/ping", "ping"))
        .start_http(&bind_addr)
        .expect("Start Jsonrpc HTTP service");
    log::info!("jsonrpc server started: {}", bind);
    let (tx, rx) = channel();
    ctrlc::set_handler(move || tx.send(()).unwrap()).unwrap();
    log::info!("Waiting for Ctrl-C...");
    rx.recv().expect("Could not receive from channel.");
    server.close();
    Ok(())
}
