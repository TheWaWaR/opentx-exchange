mod cell_dep;
mod exchange_client;
mod exchange_server;
mod rpc;
mod tx_builder;
mod util;

use std::{error::Error as StdErr, fs, path::PathBuf};

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{serialize_parameters, Address};
use ckb_types::packed::Transaction;
use clap::{Args, Parser, Subcommand};
use serde_json::to_string_pretty;

use cell_dep::CellDeps;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate and sign an order transaction (partial open transaction)
    GenOrder(tx_builder::GenOrderArgs),
    MergeOrders(tx_builder::MergeOrdersArgs),
    /// Issue some xUDT amount to address
    IssueUdt(tx_builder::IssueUdtArgs),
    /// Create new empty xUDT cell
    NewEmptyUdtCell(tx_builder::NewEmptyUdtCellArgs),
    /// Cancel an order transaction by use one of the input cell in it
    CancelOrder(tx_builder::CancelOrderArgs),

    /// Build open transaction compatible omni-lock address
    BuildOmniLockAddress {
        /// The sighash address used to build the omni-lock address
        #[clap(long, value_name = "ADDRESS")]
        sighash_address: Address,

        /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
        #[clap(long, value_name = "PATH")]
        cell_deps: PathBuf,

        /// Build mainnet address
        #[arg(long)]
        mainnet: bool,
    },

    /// Send the order transaction to exchange
    SendToExchange {
        /// The order transaction file (.json)
        #[clap(long, value_name = "PATH")]
        tx_file: PathBuf,

        /// Exchange rpc url
        #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:9933")]
        exchange_rpc: String,
    },

    /// Query orders by the omni-lock address
    QueryOrderByAddress {
        /// The omni-lock address
        #[clap(long, value_name = "ADDRESS")]
        address: Address,

        #[clap(flatten)]
        query_args: QueryArgs,
    },
    /// Query orders by the sell information
    QueryOrderBySell {
        /// The owner address of the xUDT ready to sell
        #[clap(long, value_name = "ADDRESS")]
        owner_sell: Address,

        /// The min amount of xUDT ready to sell (inclusive)
        #[clap(long, value_name = "NUMBER")]
        amount_sell_min: Option<u128>,
        /// The max amount of xUDT ready to sell (exclusive)
        #[clap(long, value_name = "NUMBER")]
        amount_sell_max: Option<u128>,

        #[clap(flatten)]
        query_args: QueryArgs,
    },
    /// Query orders by the buy information
    QueryOrderByBuy {
        /// The owner address of the xUDT ready to sell
        #[clap(long, value_name = "ADDRESS")]
        owner_buy: Address,

        /// The min amount of xUDT ready to buy (inclusive)
        #[clap(long, value_name = "NUMBER")]
        amount_buy_min: Option<u128>,
        /// The max amount of xUDT ready to buy (exclusive)
        #[clap(long, value_name = "NUMBER")]
        amount_buy_max: Option<u128>,

        #[clap(flatten)]
        query_args: QueryArgs,
    },

    /// Generate example cell_deps.json
    GenExampleCellDeps {
        /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
        #[clap(long, value_name = "PATH")]
        cell_deps: PathBuf,
    },

    /// Start exchange jsonrpc server
    StartExchange {
        /// The ip:port to bind
        #[clap(long, value_name = "IP:PORT", default_value = "0.0.0.0:9933")]
        bind: String,

        /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
        #[clap(long, value_name = "PATH")]
        cell_deps: PathBuf,

        /// CKB rpc url
        #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
        ckb_rpc: String,
    },
}

#[derive(Args, Debug)]
struct QueryArgs {
    /// The cell deps information (for resolve cell_dep by script id or build lock/type script, json format)
    #[clap(long, value_name = "PATH")]
    cell_deps: PathBuf,

    /// Exchange rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:9933")]
    exchange_rpc: String,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}

fn main() -> Result<(), Box<dyn StdErr>> {
    if std::env::var("RUST_LOG").is_err() {
        // should recognize RUST_LOG_STYLE environment variable
        env_logger::Builder::from_default_env()
            .filter(None, log::LevelFilter::Info)
            .init();
    } else {
        env_logger::init();
    }

    let cli = Cli::parse();
    log::debug!("cli args: {:#?}", cli);

    match cli.command {
        Commands::GenOrder(args) => {
            let tx = tx_builder::build_order_tx(&args)?;
            let json_tx = json_types::TransactionView::from(tx);
            fs::write(&args.tx_file, to_string_pretty(&json_tx).unwrap())?;
            log::info!("success");
        }
        Commands::MergeOrders(args) => {
            let tx = tx_builder::build_merge_orders_tx(&args)?;
            let json_tx = json_types::TransactionView::from(tx);
            fs::write(&args.tx_file, to_string_pretty(&json_tx).unwrap())?;
            log::info!("build merge orders success");
        }
        Commands::IssueUdt(args) => {
            let tx = tx_builder::build_issue_udt_tx(&args)?;
            util::send_tx_to_ckb(tx, args.ckb_rpc.as_str())?;
        }
        Commands::NewEmptyUdtCell(args) => {
            let tx = tx_builder::build_new_empty_udt_cell_tx(&args)?;
            util::send_tx_to_ckb(tx, args.ckb_rpc.as_str())?;
        }
        Commands::CancelOrder(args) => {
            let tx = tx_builder::build_cancel_order_tx(&args)?;
            util::send_tx_to_ckb(tx, args.ckb_rpc.as_str())?;
        }
        Commands::BuildOmniLockAddress {
            sighash_address,
            cell_deps,
            mainnet,
        } => {
            let content = fs::read_to_string(cell_deps)?;
            let cell_deps: CellDeps = serde_json::from_str(&content)?;
            let address = util::build_omni_lock_address(&sighash_address, &cell_deps, mainnet)?;
            log::info!("omni-lock address: {}", address);
        }
        Commands::SendToExchange {
            tx_file,
            exchange_rpc,
        } => {
            let content = fs::read_to_string(tx_file)?;
            let tx_view: json_types::TransactionView = serde_json::from_str(&content)?;
            let tx = Transaction::from(tx_view.inner);
            exchange_client::send_order(exchange_rpc.as_str(), tx.into_view())?;
        }
        Commands::QueryOrderByAddress {
            address,
            query_args,
        } => {
            let content = fs::read_to_string(query_args.cell_deps)?;
            let cell_deps: CellDeps = serde_json::from_str(&content)?;
            let txs =
                exchange_client::query_by_address(query_args.exchange_rpc.as_str(), &address)?;
            util::explain_orders(&txs, &cell_deps, query_args.ckb_rpc.as_str())?;
        }
        Commands::QueryOrderBySell {
            owner_sell,
            amount_sell_min,
            amount_sell_max,
            query_args,
        } => {
            let content = fs::read_to_string(query_args.cell_deps)?;
            let cell_deps: CellDeps = serde_json::from_str(&content)?;
            let amount_range = util::build_amount_range(amount_sell_min, amount_sell_max);
            let txs = exchange_client::query_by_sell(
                query_args.exchange_rpc.as_str(),
                &owner_sell,
                amount_range,
                &cell_deps,
            )?;
            util::explain_orders(&txs, &cell_deps, query_args.ckb_rpc.as_str())?;
        }
        Commands::QueryOrderByBuy {
            owner_buy,
            amount_buy_min,
            amount_buy_max,
            query_args,
        } => {
            let content = fs::read_to_string(query_args.cell_deps)?;
            let cell_deps: CellDeps = serde_json::from_str(&content)?;
            let amount_range = util::build_amount_range(amount_buy_min, amount_buy_max);
            let txs = exchange_client::query_by_buy(
                query_args.exchange_rpc.as_str(),
                &owner_buy,
                amount_range,
                &cell_deps,
            )?;
            util::explain_orders(&txs, &cell_deps, query_args.ckb_rpc.as_str())?;
        }
        Commands::StartExchange {
            bind,
            cell_deps,
            ckb_rpc,
        } => {
            exchange_server::start(bind.as_str(), &cell_deps, ckb_rpc.as_str())?;
        }
        Commands::GenExampleCellDeps { cell_deps } => {
            let example = CellDeps::gen_example();
            fs::write(&cell_deps, to_string_pretty(&example).unwrap())?;
        }
    }
    Ok(())
}
