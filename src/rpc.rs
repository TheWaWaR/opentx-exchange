// TODO: should fix this in ckb-sdk
pub use ckb_sdk::rpc::RpcError;

use ckb_jsonrpc_types::{Script, Transaction, TransactionView, Uint128};

ckb_sdk::jsonrpc!(pub struct ExchangeClient {
    pub fn send_order(&mut self, tx: Transaction) -> String;
    pub fn query_orders_by_lock_script(&mut self, lock_script: Script) -> Vec<TransactionView>;
    pub fn query_orders_by_udt_script(&mut self, udt_script: Script, amount_range: Option<[Uint128; 2]>, is_sell: bool) -> Vec<TransactionView>;
});
