use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::Manifest;

pub const INDEX_FILE: &str = "index.json";

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Index {
    pub version: u32,
    pub secrets: BTreeMap<String, IndexSecret>,
    pub groups: BTreeMap<String, IndexGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IndexSecret {
    pub group: String,
    pub master_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexGroup {
    pub hosts: BTreeMap<String, String>,
    pub recipients: Vec<String>,
}

impl Index {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(d) => {
                serde_json::from_slice(&d).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index {
                version: 1,
                ..Default::default()
            }),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = serde_json::to_vec_pretty(self).expect("index serializes");
        out.push(b'\n');
        out
    }

    pub fn group_secrets(&self, group: &str) -> BTreeSet<&str> {
        self.secrets
            .iter()
            .filter(|(_, s)| s.group == group)
            .map(|(id, _)| id.as_str())
            .collect()
    }
}

pub fn group_name(hosts: &BTreeSet<String>) -> String {
    let joined = hosts.iter().cloned().collect::<Vec<_>>().join("+");
    if joined.len() <= 200 {
        joined
    } else {
        let digest = Sha256::digest(joined.as_bytes());
        format!("group-{}", &hex(&digest)[..16])
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Default)]
pub struct Desired {
    pub groups: BTreeMap<String, BTreeMap<String, String>>,
    pub secret_group: BTreeMap<String, String>,
    pub hosts_without_pubkey: Vec<String>,
}

impl Desired {
    pub fn compute(m: &Manifest) -> Self {
        let mut d = Desired::default();
        let mut users: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for (host, h) in &m.hosts {
            if h.secrets.is_empty() {
                continue;
            }
            if h.pubkey.is_none() {
                d.hosts_without_pubkey.push(host.clone());
                continue;
            }
            for id in h.secrets.values() {
                users.entry(id).or_default().insert(host.clone());
            }
        }
        for (id, hosts) in users {
            let name = group_name(&hosts);
            d.groups.entry(name.clone()).or_insert_with(|| {
                hosts
                    .iter()
                    .map(|h| (h.clone(), m.hosts[h].pubkey.clone().unwrap()))
                    .collect()
            });
            d.secret_group.insert(id.to_string(), name);
        }
        d
    }

    pub fn group_secrets(&self, group: &str) -> BTreeSet<&str> {
        self.secret_group
            .iter()
            .filter(|(_, g)| g.as_str() == group)
            .map(|(id, _)| id.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_names() {
        let hosts: BTreeSet<String> = ["web", "db"].iter().map(|s| s.to_string()).collect();
        assert_eq!(group_name(&hosts), "db+web");
        let many: BTreeSet<String> = (0..50).map(|i| format!("host-number-{i}")).collect();
        let name = group_name(&many);
        assert!(name.starts_with("group-") && name.len() == 22, "{name}");
    }

    #[test]
    fn desired_groups_by_recipient_set() {
        let m: Manifest = serde_json::from_value(serde_json::json!({
            "version": 1,
            "hosts": {
                "h1": { "pubkey": "age1a", "storageDir": "r", "secrets": { "a": "A", "b": "B", "c": "C" } },
                "h2": { "pubkey": "age1b", "storageDir": "r", "secrets": { "x": "A", "c": "C" } },
                "h3": { "pubkey": null, "storageDir": "r", "secrets": { "c": "C" } }
            },
            "secrets": {
                "A": { "file": "s.yaml", "key": "a", "pubFile": "p" },
                "B": { "file": "s.yaml", "key": "b", "pubFile": "p" },
                "C": { "file": "s.yaml", "key": "c", "pubFile": "p" }
            }
        }))
        .unwrap();
        let d = Desired::compute(&m);
        assert_eq!(d.secret_group["A"], "h1+h2");
        assert_eq!(d.secret_group["B"], "h1");
        assert_eq!(d.secret_group["C"], "h1+h2");
        assert_eq!(d.group_secrets("h1+h2"), ["A", "C"].into_iter().collect());
        assert_eq!(d.hosts_without_pubkey, vec!["h3"]);
    }
}
