use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        CellCollector, CellQueryOptions, DefaultCellCollector, DefaultCellDepResolver,
        DefaultHeaderDepResolver, DefaultTransactionDependencyProvider, LiveCell,
        SecpCkbRawKeySigner, ValueRangeOption,
    },
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses,
        omni_lock::OmniLockTransferBuilder,
        udt::{UdtIssueBuilder, UdtTargetReceiver, UdtType},
        unlock_tx, CapacityBalancer, TransferAction, TxBuilder,
    },
    unlock::{
        opentx::{assembler::assemble_new_tx, OpentxWitness},
        OmniLockConfig, OmniLockScriptSigner, SecpSighashUnlocker,
    },
    unlock::{OmniLockUnlocker, OmniUnlockMode, ScriptUnlocker},
    Address, AddressPayload, HumanCapacity, NetworkType, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellDep, CellInput, CellOutput, Script, Transaction, WitnessArgs},
    prelude::*,
    H160, H256,
};
use clap::Args;
use secp256k1::{PublicKey, SecretKey};

use crate::cell_dep::{CellDepName, CellDeps};

#[derive(Args, Debug)]
pub struct GenOrderArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The owner address of the xUDT to sell
    #[clap(long, value_name = "ADDRESS")]
    owner_sell: Address,

    /// The owner address of the xUDT to buy
    #[clap(long, value_name = "ADDRESS")]
    owner_buy: Address,

    /// The amount of xUDT to sell
    #[clap(long, value_name = "NUMBER")]
    amount_sell: u128,

    /// The amount of xUDT to buy
    #[clap(long, value_name = "NUMBER")]
    amount_buy: u128,

    /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
    #[clap(long, env = "CELL_DEPS", value_name = "PATH")]
    cell_deps: PathBuf,

    /// The transaction fee of this order transaction
    #[clap(long, value_name = "CAPACITY", default_value = "0.001")]
    tx_fee: HumanCapacity,

    /// The output order transaction file (.json)
    #[clap(long, value_name = "PATH")]
    pub tx_file: PathBuf,

    /// CKB rpc url
    #[clap(
        long,
        value_name = "URL",
        env = "CKB_RPC",
        default_value = "http://127.0.0.1:8114"
    )]
    pub ckb_rpc: String,
}

#[derive(Args, Debug)]
pub struct MergeOrdersArgs {
    /// The order transactions to be merged
    #[clap(long, value_name = "PATH")]
    order_tx: Vec<PathBuf>,

    /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
    #[clap(long, env = "CELL_DEPS", value_name = "PATH")]
    cell_deps: PathBuf,

    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    pub tx_file: PathBuf,

    /// CKB rpc url
    #[clap(
        long,
        value_name = "URL",
        env = "CKB_RPC",
        default_value = "http://127.0.0.1:8114"
    )]
    pub ckb_rpc: String,
}

#[derive(Args, Debug)]
pub struct IssueUdtArgs {
    /// The owner private key (hex string)
    #[clap(long, value_name = "KEY")]
    owner_key: H256,

    /// The target omni-lock address
    #[clap(long, value_name = "ADDRESS")]
    to: Address,

    /// The amount of xUDT to issue
    #[clap(long, value_name = "NUMBER")]
    amount: u128,

    /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
    #[clap(long, env = "CELL_DEPS", value_name = "PATH")]
    cell_deps: PathBuf,

    /// The fee rate of this transaction
    #[clap(long, value_name = "NUMBER", default_value = "1000")]
    fee_rate: u64,

    /// CKB rpc url
    #[clap(
        long,
        value_name = "URL",
        env = "CKB_RPC",
        default_value = "http://127.0.0.1:8114"
    )]
    pub ckb_rpc: String,
}

#[derive(Args, Debug)]
pub struct NewEmptyUdtCellArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The owner address of the xUDT cell (the admin address, only sighash address is supported)
    #[clap(long, value_name = "ADDRESS")]
    owner: Address,

    /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
    #[clap(long, env = "CELL_DEPS", value_name = "PATH")]
    cell_deps: PathBuf,

    /// The fee rate of this transaction
    #[clap(long, value_name = "NUMBER", default_value = "1000")]
    fee_rate: u64,

    /// CKB rpc url
    #[clap(
        long,
        value_name = "URL",
        env = "CKB_RPC",
        default_value = "http://127.0.0.1:8114"
    )]
    pub ckb_rpc: String,
}

#[derive(Args, Debug)]
pub struct CancelOrderArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The order transaction file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
    #[clap(long, env = "CELL_DEPS", value_name = "PATH")]
    cell_deps: PathBuf,

    /// The fee rate of this transaction
    #[clap(long, value_name = "NUMBER", default_value = "1000")]
    fee_rate: u64,

    /// CKB rpc url
    #[clap(
        long,
        value_name = "URL",
        env = "CKB_RPC",
        default_value = "http://127.0.0.1:8114"
    )]
    pub ckb_rpc: String,
}

pub fn build_order_tx(args: &GenOrderArgs) -> Result<TransactionView> {
    let content = fs::read_to_string(&args.cell_deps)?;
    let cell_deps: CellDeps = serde_json::from_str(&content)?;
    let omni_dep_item = cell_deps
        .get_item(&CellDepName::OmniLock)
        .expect("omni-lock cell dep");
    let xudt_dep_item = cell_deps
        .get_item(&CellDepName::Xudt)
        .expect("xudt cell dep");
    let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());
    let xudt_script_id = ScriptId::from(xudt_dep_item.script_id.clone());

    let sender_privkey = SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| anyhow!("invalid sender secret key: {}", err))?;
    let (mut omni_lock_config, omni_lock_script) = {
        let sender_pubkey = PublicKey::from_secret_key(&SECP256K1, &sender_privkey);
        let sender_pubkey_hash =
            H160::from_slice(&blake2b_256(&sender_pubkey.serialize()[..])[0..20]).unwrap();
        let mut config = OmniLockConfig::new_pubkey_hash(sender_pubkey_hash);
        config.set_opentx_mode();
        let omni_script = omni_script_id
            .dummy_script()
            .as_builder()
            .args(config.build_args().pack())
            .build();
        (config, omni_script)
    };

    let mut cell_collector = DefaultCellCollector::new(args.ckb_rpc.as_str());
    let sell_input_cell = query_xudt_cell(
        &args.owner_sell,
        omni_lock_script.clone(),
        &xudt_script_id,
        &mut cell_collector,
    )?;
    let sell_input_amount = u128::from_le_bytes(
        sell_input_cell.output_data.as_ref()[0..16]
            .try_into()
            .unwrap(),
    );
    if sell_input_amount < args.amount_sell {
        return Err(anyhow!(
            "not enough xudt to sell, expect >= {}, got: {}",
            args.amount_sell,
            sell_input_amount
        ));
    }
    let buy_input_cell = query_xudt_cell(
        &args.owner_buy,
        omni_lock_script.clone(),
        &xudt_script_id,
        &mut cell_collector,
    )?;
    let buy_input_amount = u128::from_le_bytes(
        buy_input_cell.output_data.as_ref()[0..16]
            .try_into()
            .unwrap(),
    );

    let sell_output_data = {
        let mut data = sell_input_cell.output_data.as_ref().to_vec();
        let sell_output_amount = sell_input_amount - args.amount_sell;
        data[0..16].copy_from_slice(&sell_output_amount.to_le_bytes()[..]);
        Bytes::from(data)
    };
    let buy_output_data = {
        let mut data = buy_input_cell.output_data.as_ref().to_vec();
        let buy_output_amount = buy_input_amount + args.amount_buy;
        data[0..16].copy_from_slice(&buy_output_amount.to_le_bytes()[..]);
        Bytes::from(data)
    };

    let fee_input_cell = query_cell_by_lock(omni_lock_script.clone(), &mut cell_collector)?;
    let fee_output = {
        let input_capacity: u64 = fee_input_cell.output.capacity().unpack();
        let output_capacity = input_capacity - args.tx_fee.0;
        fee_input_cell
            .output
            .as_builder()
            .capacity(output_capacity.pack())
            .build()
    };

    let cell_dep_resolver = {
        let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
        let genesis_block: BlockView = ckb_client.get_block_by_number(0.into())?.unwrap().into();
        let mut resolver = DefaultCellDepResolver::from_genesis(&genesis_block)?;
        cell_deps.apply_to_resolver(&mut resolver)?;
        resolver
    };

    let tx_cell_deps: Vec<CellDep> = vec![
        cell_dep_resolver.sighash_dep().unwrap().0.clone(),
        omni_dep_item.cell_dep.clone().into(),
        xudt_dep_item.cell_dep.clone().into(),
    ];
    let tx_inputs = vec![
        CellInput::new(fee_input_cell.out_point, 0),
        CellInput::new(sell_input_cell.out_point, 0),
        CellInput::new(buy_input_cell.out_point, 0),
    ];
    let tx_outputs = vec![fee_output, sell_input_cell.output, buy_input_cell.output];
    let tx_outputs_data = vec![
        Bytes::new().pack(),
        sell_output_data.pack(),
        buy_output_data.pack(),
    ];
    let base_tx = TransactionBuilder::default()
        .cell_deps(tx_cell_deps.pack())
        .inputs(tx_inputs.pack())
        .outputs(tx_outputs)
        .outputs_data(tx_outputs_data)
        .build();

    let unlockers = build_omnilock_unlockers(
        vec![sender_privkey],
        omni_lock_config.clone(),
        omni_script_id,
    );

    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);
    let (tx, _) = fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;
    let wit = OpentxWitness::new_sig_all_relative(&tx, Some(0xdeadbeef)).unwrap();
    omni_lock_config.set_opentx_input(wit);
    let tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &omni_lock_config,
        OmniUnlockMode::Normal,
        &tx_dep_provider,
        &omni_lock_script,
    )?;

    // NOTE: the transaction already capacity balanced

    let (tx, still_locked_groups) = unlock_tx(tx, &tx_dep_provider, &unlockers)?;
    log::debug!("still locked groups: {:?}", still_locked_groups);
    assert!(still_locked_groups.is_empty());

    Ok(tx)
}

pub fn build_merge_orders_tx(args: &MergeOrdersArgs) -> Result<TransactionView> {
    let mut txs = Vec::new();
    for path in &args.order_tx {
        let content = fs::read_to_string(path)?;
        let json_tx: json_types::TransactionView = serde_json::from_str(&content)?;
        txs.push(Transaction::from(json_tx.inner).into_view());
    }

    let content = fs::read_to_string(&args.cell_deps)?;
    let cell_deps: CellDeps = serde_json::from_str(&content)?;
    let omni_dep_item = cell_deps
        .get_item(&CellDepName::OmniLock)
        .expect("omni-lock cell dep");
    let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);
    let assembled_tx = assemble_new_tx(txs, &tx_dep_provider, omni_script_id.code_hash.pack())?;
    Ok(assembled_tx)
}

pub fn build_issue_udt_tx(args: &IssueUdtArgs) -> Result<TransactionView> {
    let content = fs::read_to_string(&args.cell_deps)?;
    let cell_deps: CellDeps = serde_json::from_str(&content)?;
    let omni_dep_item = cell_deps
        .get_item(&CellDepName::OmniLock)
        .expect("omni cell dep");
    let xudt_dep_item = cell_deps
        .get_item(&CellDepName::Xudt)
        .expect("xudt cell dep");
    let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());
    let xudt_script_id = ScriptId::from(xudt_dep_item.script_id.clone());

    let to_script = Script::from(&args.to);
    if to_script.code_hash().as_slice() != omni_script_id.code_hash.as_bytes() {
        return Err(anyhow!(
            "to address is not omni-lock address, code hash: {:?}",
            to_script.code_hash()
        ));
    }
    if to_script.hash_type() != omni_script_id.hash_type.into() {
        return Err(anyhow!(
            "to address is not omni-lock address, hash type: {:?}",
            to_script.hash_type()
        ));
    }

    let owner_privkey = SecretKey::from_slice(args.owner_key.as_bytes())
        .map_err(|err| anyhow!("invalid owner secret key: {}", err))?;
    let owner = {
        let owner_pubkey = PublicKey::from_secret_key(&SECP256K1, &owner_privkey);
        let owner_pubkey_hash =
            H160::from_slice(&blake2b_256(&owner_pubkey.serialize()[..])[0..20]).unwrap();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(owner_pubkey_hash.as_bytes().to_vec()).pack())
            .build()
    };
    let receiver = UdtTargetReceiver {
        action: TransferAction::Create,
        lock_script: Script::from(&args.to),
        capacity: None,
        amount: args.amount,
        extra_data: None,
    };

    let builder = UdtIssueBuilder {
        udt_type: UdtType::Xudt(Bytes::new()),
        script_id: xudt_script_id,
        owner: owner.clone(),
        receivers: vec![receiver],
    };

    let mut unlockers: HashMap<_, Box<dyn ScriptUnlocker>> = HashMap::new();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![owner_privkey]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(owner, placeholder_witness, args.fee_rate);
    let cell_dep_resolver = {
        let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
        let genesis_block: BlockView = ckb_client.get_block_by_number(0.into())?.unwrap().into();
        let mut resolver = DefaultCellDepResolver::from_genesis(&genesis_block)?;
        cell_deps.apply_to_resolver(&mut resolver)?;
        resolver
    };

    let mut cell_collector = DefaultCellCollector::new(args.ckb_rpc.as_str());
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);
    let (tx, still_locked_groups) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    log::debug!("still locked groups: {:?}", still_locked_groups);
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

pub fn build_new_empty_udt_cell_tx(args: &NewEmptyUdtCellArgs) -> Result<TransactionView> {
    let content = fs::read_to_string(&args.cell_deps)?;
    let cell_deps: CellDeps = serde_json::from_str(&content)?;
    let omni_dep_item = cell_deps
        .get_item(&CellDepName::OmniLock)
        .expect("omni cell dep");
    let xudt_dep_item = cell_deps
        .get_item(&CellDepName::Xudt)
        .expect("xudt cell dep");
    let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());
    let xudt_script_id = ScriptId::from(xudt_dep_item.script_id.clone());

    let type_script = {
        let owner_lock_hash = Script::from(&args.owner).calc_script_hash();
        xudt_script_id
            .dummy_script()
            .as_builder()
            .args(owner_lock_hash.as_bytes().pack())
            .build()
    };

    let sender_privkey = SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| anyhow!("invalid sender secret key: {}", err))?;
    let (omni_lock_script, sighash_lock_script) = {
        let sender_pubkey = PublicKey::from_secret_key(&SECP256K1, &sender_privkey);
        let sender_pubkey_hash =
            H160::from_slice(&blake2b_256(&sender_pubkey.serialize()[..])[0..20]).unwrap();
        let sighash_script = Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(sender_pubkey_hash.as_bytes().to_vec()).pack())
            .build();

        let mut config = OmniLockConfig::new_pubkey_hash(sender_pubkey_hash);
        config.set_opentx_mode();
        let omni_script = omni_script_id
            .dummy_script()
            .as_builder()
            .args(config.build_args().pack())
            .build();
        (omni_script, sighash_script)
    };
    let amount: u128 = 0;
    let (output, output_data) = {
        let base_output = CellOutput::new_builder()
            .type_(Some(type_script).pack())
            .lock(omni_lock_script)
            .build();
        let data = Bytes::from(amount.to_le_bytes().to_vec());
        let occupied_capacity = base_output
            .occupied_capacity(Capacity::bytes(data.len()).unwrap())
            .unwrap()
            .as_u64();
        let output = base_output
            .as_builder()
            .capacity(occupied_capacity.pack())
            .build();
        (output, data)
    };
    let cell_dep_resolver = {
        let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
        let genesis_block: BlockView = ckb_client.get_block_by_number(0.into())?.unwrap().into();
        let mut resolver = DefaultCellDepResolver::from_genesis(&genesis_block)?;
        cell_deps.apply_to_resolver(&mut resolver)?;
        resolver
    };
    let tx_cell_deps: Vec<CellDep> = vec![
        cell_dep_resolver.sighash_dep().unwrap().0.clone(),
        xudt_dep_item.cell_dep.clone().into(),
    ];
    let base_tx = TransactionBuilder::default()
        .cell_deps(tx_cell_deps.pack())
        .outputs(vec![output].pack())
        .outputs_data(vec![output_data.pack()].pack())
        .build();

    let mut unlockers: HashMap<_, Box<dyn ScriptUnlocker>> = HashMap::new();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_privkey]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sighash_lock_script, placeholder_witness, args.fee_rate);
    let mut cell_collector = DefaultCellCollector::new(args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 0);
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());

    let (tx, _) = fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;
    let tx = balance_tx_capacity(
        &tx,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )?;
    let (tx, still_locked_groups) = unlock_tx(tx, &tx_dep_provider, &unlockers)?;
    log::debug!("still locked groups: {:?}", still_locked_groups);
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

pub fn build_cancel_order_tx(args: &CancelOrderArgs) -> Result<TransactionView> {
    let content = fs::read_to_string(&args.tx_file)?;
    let json_tx: json_types::TransactionView = serde_json::from_str(&content)?;

    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    for input in &json_tx.inner.inputs {
        let status = ckb_client
            .get_live_cell(input.previous_output.clone(), false)?
            .status;
        log::debug!(
            "input.out_point: {:?}, status: {}",
            input.previous_output,
            status
        );
        if status != "live" {
            return Err(anyhow!("The transaction already canceled"));
        }
    }

    let content = fs::read_to_string(&args.cell_deps)?;
    let cell_deps: CellDeps = serde_json::from_str(&content)?;
    let omni_dep_item = cell_deps
        .get_item(&CellDepName::OmniLock)
        .expect("omni-lock cell dep");
    let xudt_dep_item = cell_deps
        .get_item(&CellDepName::Xudt)
        .expect("xudt cell dep");
    let omni_script_id = ScriptId::from(omni_dep_item.script_id.clone());

    let sender_privkey = SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| anyhow!("invalid sender secret key: {}", err))?;
    let (omni_lock_config, omni_lock_script, sighash_lock_script) = {
        let sender_pubkey = PublicKey::from_secret_key(&SECP256K1, &sender_privkey);
        let sender_pubkey_hash =
            H160::from_slice(&blake2b_256(&sender_pubkey.serialize()[..])[0..20]).unwrap();
        let sighash_script = Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(sender_pubkey_hash.as_bytes().to_vec()).pack())
            .build();

        let mut config = OmniLockConfig::new_pubkey_hash(sender_pubkey_hash);
        config.set_opentx_mode();
        let omni_script = omni_script_id
            .dummy_script()
            .as_builder()
            .args(config.build_args().pack())
            .build();
        (config, omni_script, sighash_script)
    };

    let cell_dep_resolver = {
        let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
        let genesis_block: BlockView = ckb_client.get_block_by_number(0.into())?.unwrap().into();
        let mut resolver = DefaultCellDepResolver::from_genesis(&genesis_block)?;
        cell_deps.apply_to_resolver(&mut resolver)?;
        resolver
    };

    let cell = ckb_client
        .get_live_cell(json_tx.inner.inputs[0].previous_output.clone(), true)?
        .cell
        .unwrap();
    let output = CellOutput::from(cell.output);
    let output_data = cell.data.unwrap().content.into_bytes();

    let mut tx_cell_deps: Vec<CellDep> = vec![cell_dep_resolver.sighash_dep().unwrap().0.clone()];
    if output.lock() == omni_lock_script {
        tx_cell_deps.push(omni_dep_item.cell_dep.clone().into());
    }
    if output.type_().to_opt().is_some() {
        tx_cell_deps.push(xudt_dep_item.cell_dep.clone().into());
    }
    let tx_inputs = vec![CellInput::from(json_tx.inner.inputs[0].clone())];

    let mut unlockers = if output.lock() == omni_lock_script {
        build_omnilock_unlockers(vec![sender_privkey], omni_lock_config, omni_script_id)
    } else {
        HashMap::new()
    };
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_privkey]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sighash_lock_script, placeholder_witness, args.fee_rate);
    let mut cell_collector = DefaultCellCollector::new(args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 0);
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());

    let base_tx = TransactionBuilder::default()
        .cell_deps(tx_cell_deps.pack())
        .inputs(tx_inputs.pack())
        .outputs(vec![output].pack())
        .outputs_data(vec![output_data.pack()].pack())
        .build();
    let (tx, _) = fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;
    let tx = balance_tx_capacity(
        &tx,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )?;
    let (tx, still_locked_groups) = unlock_tx(tx, &tx_dep_provider, &unlockers)?;
    log::debug!("still locked groups: {:?}", still_locked_groups);
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

fn query_cell_by_lock(
    lock_script: Script,
    cell_collector: &mut dyn CellCollector,
) -> Result<LiveCell> {
    let mut query = CellQueryOptions::new_lock(lock_script.clone());
    query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
    query.data_len_range = Some(ValueRangeOption::new_exact(0));
    let (cells, _) = cell_collector.collect_live_cells(&query, true)?;
    if cells.is_empty() {
        let address = Address::new(
            NetworkType::Testnet,
            AddressPayload::from(lock_script),
            true,
        );
        return Err(anyhow!(
            "cell not found for address: {}, you may transfer some capacity to this address",
            address
        ));
    }
    Ok(cells[0].clone())
}

fn query_xudt_cell(
    owner: &Address,
    lock_script: Script,
    xudt_script_id: &ScriptId,
    cell_collector: &mut dyn CellCollector,
) -> Result<LiveCell> {
    let owner_lock_hash = Script::from(owner).calc_script_hash();
    let xudt_script = xudt_script_id
        .dummy_script()
        .as_builder()
        .args(owner_lock_hash.as_bytes().pack())
        .build();
    let mut query = CellQueryOptions::new_lock(lock_script);
    query.data_len_range = Some(ValueRangeOption::new_min(16));
    query.secondary_script = Some(xudt_script);

    let (cells, _) = cell_collector.collect_live_cells(&query, true)?;
    if cells.is_empty() {
        return Err(anyhow!(
            "xudt cell not found for owner: {}, you may use `new-empty-udt-cell` subcommand to create an empty xudt cell first",
            owner
        ));
    }
    Ok(cells[0].clone())
}

fn build_omnilock_unlockers(
    keys: Vec<SecretKey>,
    config: OmniLockConfig,
    omnilock_script_id: ScriptId,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(keys);
    let omnilock_signer =
        OmniLockScriptSigner::new(Box::new(signer), config.clone(), OmniUnlockMode::Normal);
    let omnilock_unlocker = OmniLockUnlocker::new(omnilock_signer, config);
    HashMap::from([(
        omnilock_script_id,
        Box::new(omnilock_unlocker) as Box<dyn ScriptUnlocker>,
    )])
}
