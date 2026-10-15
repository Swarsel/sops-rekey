use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub version: u32,
    #[serde(default)]
    pub master_recipients: MasterRecipients,
    #[serde(default)]
    pub master_identities: Vec<String>,
    pub hosts: BTreeMap<String, Host>,
    pub secrets: BTreeMap<String, Secret>,
}

#[derive(Debug, Default, Deserialize)]
pub struct MasterRecipients {
    #[serde(default)]
    pub pgp: Vec<String>,
    #[serde(default)]
    pub age: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub pubkey: Option<String>,
    pub storage_dir: Option<String>,
    pub secrets: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    pub file: String,
    pub key: Option<String>,
    pub pub_file: String,
    #[serde(default)]
    pub generators: Vec<Generator>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Generator {
    pub host: String,
    pub secret: String,
    pub script: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let data =
            std::fs::read(path).with_context(|| format!("reading manifest {}", path.display()))?;
        let manifest: Manifest = serde_json::from_slice(&data).context("parsing manifest")?;
        if manifest.version != 1 {
            bail!("unsupported manifest version {}", manifest.version);
        }
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        for (host, h) in &self.hosts {
            for (name, id) in &h.secrets {
                if !self.secrets.contains_key(id) {
                    bail!("manifest: secret {name} of host {host} refers to unknown id {id}");
                }
            }
        }
        for (id, s) in &self.secrets {
            if let Some(first) = s.generators.first() {
                for g in &s.generators[1..] {
                    if g.script != first.script
                        || g.dependencies != first.dependencies
                        || g.tags != first.tags
                    {
                        bail!(
                            "conflicting generators for {id}: declared differently by {}.{} and {}.{}",
                            first.host, first.secret, g.host, g.secret
                        );
                    }
                }
                for dep in &first.dependencies {
                    if !self.secrets.contains_key(dep) {
                        bail!("generator for {id} depends on {dep}, which is not a rekeyed secret");
                    }
                }
            }
        }
        crate::graph::check_acyclic(self)?;
        Ok(())
    }

    pub fn storage_dir(&self) -> Result<Option<&str>> {
        let dirs: BTreeSet<Option<&str>> = self
            .hosts
            .values()
            .filter(|h| !h.secrets.is_empty())
            .map(|h| h.storage_dir.as_deref())
            .collect();
        match dirs.len() {
            0 => Ok(None),
            1 => match dirs.into_iter().next().unwrap() {
                Some(d) => Ok(Some(d)),
                None => bail!("hosts with rekeyed secrets must set sops.rekey.storageDir"),
            },
            _ => {
                let all: Vec<String> = self
                    .hosts
                    .iter()
                    .filter(|(_, h)| !h.secrets.is_empty())
                    .map(|(n, h)| format!("{n}={}", h.storage_dir.as_deref().unwrap_or("<unset>")))
                    .collect();
                bail!(
                    "all hosts must use the same sops.rekey.storageDir, found: {}",
                    all.join(", ")
                )
            }
        }
    }

    pub fn generator(&self, id: &str) -> Option<&Generator> {
        self.secrets.get(id).and_then(|s| s.generators.first())
    }

    pub fn resolve(&self, query: &str) -> Result<Vec<String>> {
        if self.secrets.contains_key(query) {
            return Ok(vec![query.to_string()]);
        }
        let (host_filter, name) = match query.split_once(':') {
            Some((h, n)) => (Some(h), n),
            None => (None, query),
        };
        let ids: BTreeSet<String> = self
            .hosts
            .iter()
            .filter(|(h, _)| host_filter.is_none_or(|f| f == h.as_str()))
            .filter_map(|(_, h)| h.secrets.get(name).cloned())
            .collect();
        match ids.len() {
            0 => bail!("no secret matches {query:?}"),
            1 => Ok(ids.into_iter().collect()),
            _ => bail!(
                "{query:?} is ambiguous, it refers to: {} (use the id or host:name)",
                ids.into_iter().collect::<Vec<_>>().join(", ")
            ),
        }
    }
}
