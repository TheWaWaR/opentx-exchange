use std::collections::{HashMap, HashSet};
use std::fmt;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use ckb_jsonrpc_types as rpc_types;
use ckb_sdk::traits::DefaultCellDepResolver;
use ckb_types::H256;

#[derive(Clone, Hash, Eq, PartialEq, Debug, Serialize, Deserialize, Default)]
pub struct ScriptId {
    pub code_hash: H256,
    pub hash_type: rpc_types::ScriptHashType,
}

impl From<ScriptId> for ckb_sdk::types::ScriptId {
    fn from(json: ScriptId) -> ckb_sdk::types::ScriptId {
        ckb_sdk::types::ScriptId::new(json.code_hash, json.hash_type.into())
    }
}

#[derive(Clone, Copy, Hash, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CellDepName {
    /// Extensible UDT
    Xudt,
    /// Omni-lock
    OmniLock,
}
impl fmt::Display for CellDepName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = match self {
            CellDepName::Xudt => "xudt",
            CellDepName::OmniLock => "omni-lock",
        };
        write!(f, "{}", output)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CellDepItem {
    pub script_id: ScriptId,
    pub cell_dep: rpc_types::CellDep,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellDeps {
    pub items: HashMap<CellDepName, CellDepItem>,
}

impl CellDeps {
    pub fn get_item(&self, name: &CellDepName) -> Option<&CellDepItem> {
        self.items.get(name)
    }
    pub fn apply_to_resolver(&self, resolver: &mut DefaultCellDepResolver) -> Result<()> {
        let mut names = HashSet::new();
        for (name, item) in self.items.clone() {
            if !names.insert(name) {
                return Err(anyhow!("duplicated cell_dep item name: {}", name));
            }
            resolver.insert(
                item.script_id.into(),
                item.cell_dep.into(),
                name.to_string(),
            );
        }
        Ok(())
    }
    pub fn gen_example() -> CellDeps {
        let mut items = HashMap::new();
        items.insert(CellDepName::Xudt, CellDepItem::default());
        items.insert(CellDepName::OmniLock, CellDepItem::default());
        CellDeps { items }
    }
}
