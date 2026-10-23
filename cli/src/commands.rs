use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

use crate::graph;
use crate::identities;
use crate::index::{Desired, Index, IndexGroup, IndexSecret, INDEX_FILE};
use crate::manifest::Manifest;
use crate::sops::{self, EncryptOpts, Format, Recipients, Sops};
use crate::tree;
use crate::util::{self, Touched};

pub struct Repo {
    pub root: PathBuf,
    pub m: Manifest,
    pub touched: Touched,
}

#[derive(Default)]
struct Plain {
    trees: BTreeMap<String, Value>,
    dirty: BTreeSet<String>,
}

impl Plain {
    fn leaf(&self, m: &Manifest, id: &str) -> Result<String> {
        let s = &m.secrets[id];
        let t = self
            .trees
            .get(&s.file)
            .ok_or_else(|| anyhow!("internal error: {} was not decrypted", s.file))?;
        tree::get_leaf(t, s.key.as_deref()).with_context(|| format!("reading {id} from {}", s.file))
    }
}

impl Repo {
    pub fn new(root: PathBuf, m: Manifest) -> Self {
        Repo {
            root,
            m,
            touched: Touched::default(),
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn master_recipients(&self) -> Result<Recipients> {
        let r = Recipients {
            pgp: self.m.master_recipients.pgp.clone(),
            age: self.m.master_recipients.age.clone(),
        };
        if r.is_empty() {
            bail!("masterRecipients is empty; configure at least one pgp or age master recipient");
        }
        Ok(r)
    }

    fn missing(&self) -> Result<BTreeSet<String>> {
        let mut structures: BTreeMap<&str, Option<Value>> = BTreeMap::new();
        let mut missing = BTreeSet::new();
        for (id, s) in &self.m.secrets {
            if !structures.contains_key(s.file.as_str()) {
                let st = sops::read_structure(&self.path(&s.file), Format::from_path(&s.file))?;
                structures.insert(&s.file, st);
            }
            let present = match &structures[s.file.as_str()] {
                None => false,
                Some(st) => tree::has_key(st, s.key.as_deref()),
            };
            if !present {
                missing.insert(id.clone());
            }
        }
        Ok(missing)
    }

    fn plan_generation(
        &self,
        selected: &BTreeSet<String>,
        force: bool,
        missing: &BTreeSet<String>,
    ) -> Result<Vec<String>> {
        let mut set: BTreeSet<String> = if force {
            graph::with_dependents(&self.m, selected)
        } else {
            selected.intersection(missing).cloned().collect()
        };
        loop {
            let mut added = false;
            for id in set.clone() {
                for dep in self
                    .m
                    .generator(&id)
                    .map(|g| g.dependencies.as_slice())
                    .unwrap_or(&[])
                {
                    if missing.contains(dep) && !set.contains(dep) {
                        if self.m.generator(dep).is_none() {
                            bail!(
                                "{id} depends on {dep}, which does not exist and has no generator"
                            );
                        }
                        set.insert(dep.clone());
                        added = true;
                    }
                }
            }
            if !added {
                break;
            }
        }
        if let Some(id) = set.iter().find(|id| self.m.generator(id).is_none()) {
            bail!("{id} has no generator");
        }
        Ok(graph::topo_order(&self.m, &set))
    }

    fn generation_inputs(&self, order: &[String]) -> BTreeSet<String> {
        let generating: BTreeSet<&String> = order.iter().collect();
        let mut files = BTreeSet::new();
        for id in order {
            files.insert(self.m.secrets[id].file.clone());
            for dep in &self.m.generator(id).unwrap().dependencies {
                if !generating.contains(dep) {
                    files.insert(self.m.secrets[dep].file.clone());
                }
            }
        }
        files
    }

    fn decrypt_all(&self, files: &BTreeSet<String>) -> Result<Plain> {
        let existing: Vec<&String> = files.iter().filter(|f| self.path(f).exists()).collect();
        let mut plain = Plain::default();
        if existing.is_empty() {
            return Ok(plain);
        }
        let sops = Sops::new(identities::load(&self.m.master_identities)?);
        eprintln!(
            "Decrypting {} master file(s). Confirm on your security key when asked; nothing afterwards needs it.",
            existing.len()
        );
        for f in existing {
            eprintln!("  decrypting {f}");
            plain.trees.insert(f.clone(), sops.decrypt(&self.path(f))?);
        }
        eprintln!("Done decrypting.");
        Ok(plain)
    }

    fn run_generators(&self, order: &[String], plain: &mut Plain) -> Result<()> {
        for id in order {
            let s = &self.m.secrets[id];
            let g = self.m.generator(id).unwrap();
            let mut deps = serde_json::Map::new();
            for dep in &g.dependencies {
                deps.insert(dep.clone(), Value::String(plain.leaf(&self.m, dep)?));
            }
            if let Some(parent) = self.path(&s.pub_file).parent() {
                std::fs::create_dir_all(parent)?;
            }
            eprintln!("Generating {id}");
            let out = Command::new(&g.script)
                .current_dir(&self.root)
                .env("SOPS_REKEY_DEPS", Value::Object(deps).to_string())
                .stdin(Stdio::null())
                .stderr(Stdio::inherit())
                .output()
                .with_context(|| format!("running generator for {id}"))?;
            if !out.status.success() {
                bail!("generator for {id} failed ({})", out.status);
            }
            let value = String::from_utf8(out.stdout)
                .with_context(|| format!("generator for {id} printed non-UTF-8"))?;
            if value.is_empty() {
                bail!("generator for {id} printed nothing");
            }
            let t = plain.trees.entry(s.file.clone()).or_insert(Value::Null);
            tree::set_leaf(t, s.key.as_deref(), value)?;
            plain.dirty.insert(s.file.clone());
        }
        Ok(())
    }

    fn write_masters(&mut self, plain: &Plain) -> Result<()> {
        if plain.dirty.is_empty() {
            return Ok(());
        }
        let recipients = self.master_recipients()?;
        let sops = Sops::new(None);
        for file in &plain.dirty {
            let fmt = Format::from_path(file);
            if matches!(fmt, Format::Dotenv | Format::Ini) {
                bail!(
                    "cannot write generated secrets into {file}: {} master files are not supported",
                    fmt.as_str()
                );
            }
            let path = self.path(file);
            let opts = if path.exists() {
                let md = sops::metadata(&path, fmt)?;
                if !md.foreign_keys.is_empty() || md.key_groups || md.mac_only_encrypted {
                    bail!(
                        "cannot rewrite {file}: it uses key groups, mac_only_encrypted or {:?}; \
                         generators can only write to files encrypted to plain pgp/age recipients",
                        md.foreign_keys
                    );
                }
                md.opts
            } else {
                EncryptOpts::default()
            };
            let t = &plain.trees[file];
            let (input, data) = match fmt {
                Format::Binary => (Format::Binary, tree::get_leaf(t, None)?.into_bytes()),
                _ => (Format::Json, serde_json::to_vec(t)?),
            };
            let name = Path::new(file).file_name().unwrap().to_string_lossy();
            let out = sops.encrypt(&data, input, fmt, &name, &recipients, &opts)?;
            util::write_atomic(&path, &out)?;
            eprintln!("Wrote {file}");
            self.touched.written.push(path);
        }
        for s in self.m.secrets.values() {
            let p = self.path(&s.pub_file);
            if plain.dirty.contains(&s.file) && p.exists() {
                self.touched.written.push(p);
            }
        }
        Ok(())
    }

    fn generators_selection(
        &self,
        queries: &[String],
        tags: &[String],
    ) -> Result<BTreeSet<String>> {
        let mut ids: BTreeSet<String> = if queries.is_empty() {
            self.m
                .secrets
                .keys()
                .filter(|id| self.m.generator(id).is_some())
                .cloned()
                .collect()
        } else {
            let mut out = BTreeSet::new();
            for q in queries {
                out.extend(self.m.resolve(q)?);
            }
            out
        };
        if !tags.is_empty() {
            ids.retain(|id| {
                self.m
                    .generator(id)
                    .is_some_and(|g| g.tags.iter().any(|t| tags.contains(t)))
            });
        }
        Ok(ids)
    }

    pub fn generate(&mut self, queries: &[String], tags: &[String], force: bool) -> Result<()> {
        let selected = self.generators_selection(queries, tags)?;
        let missing = self.missing()?;
        let order = self.plan_generation(&selected, force, &missing)?;
        if order.is_empty() {
            eprintln!("Nothing to generate.");
            return Ok(());
        }
        let mut plain = self.decrypt_all(&self.generation_inputs(&order))?;
        self.run_generators(&order, &mut plain)?;
        self.write_masters(&plain)?;
        eprintln!(
            "Generated {} secret(s). Run `sops-rekey rekey` to distribute them.",
            order.len()
        );
        Ok(())
    }

    fn storage_dir(&self) -> Result<Option<String>> {
        Ok(self.m.storage_dir()?.map(str::to_string))
    }

    fn group_recipients(&self, desired: &Desired) -> Result<BTreeMap<String, Vec<String>>> {
        let mut cache: BTreeMap<&str, String> = BTreeMap::new();
        let mut out = BTreeMap::new();
        for (g, hosts) in &desired.groups {
            let mut recipients = Vec::new();
            for (host, pk) in hosts {
                if !cache.contains_key(pk.as_str()) {
                    let r = util::to_age_recipient(pk)
                        .with_context(|| format!("pubkey of host {host}"))?;
                    cache.insert(pk, r);
                }
                recipients.push(cache[pk.as_str()].clone());
            }
            out.insert(g.clone(), recipients);
        }
        Ok(out)
    }

    fn group_staleness(
        &self,
        g: &str,
        desired: &Desired,
        index: &Index,
        storage: &str,
        hashes: &BTreeMap<String, Option<String>>,
        rewritten_files: &BTreeSet<String>,
    ) -> Option<String> {
        let Some(ig) = index.groups.get(g) else {
            return Some("new group".into());
        };
        if ig.hosts != desired.groups[g] {
            return Some("hosts or host keys changed".into());
        }
        let want = desired.group_secrets(g);
        if index.group_secrets(g) != want {
            return Some("set of secrets changed".into());
        }
        for id in want {
            let file = &self.m.secrets[id].file;
            if rewritten_files.contains(file) {
                return Some(format!("{file} is being regenerated"));
            }
            if index.secrets.get(id).map(|s| Some(&s.master_hash)) != Some(hashes[file].as_ref()) {
                return Some(format!("{file} changed"));
            }
        }
        if !self.path(storage).join(format!("{g}.yaml")).exists() {
            return Some("file missing".into());
        }
        None
    }

    fn hashes(&self) -> Result<BTreeMap<String, Option<String>>> {
        let mut out = BTreeMap::new();
        for s in self.m.secrets.values() {
            if !out.contains_key(&s.file) {
                out.insert(s.file.clone(), util::hash_file(&self.path(&s.file))?);
            }
        }
        Ok(out)
    }

    fn build_index(
        &self,
        desired: &Desired,
        recipients: &BTreeMap<String, Vec<String>>,
        hashes: &BTreeMap<String, Option<String>>,
    ) -> Index {
        Index {
            version: 1,
            secrets: desired
                .secret_group
                .iter()
                .map(|(id, g)| {
                    let file = &self.m.secrets[id].file;
                    (
                        id.clone(),
                        IndexSecret {
                            group: g.clone(),
                            master_hash: hashes[file].clone().unwrap_or_default(),
                        },
                    )
                })
                .collect(),
            groups: desired
                .groups
                .iter()
                .map(|(g, hosts)| {
                    (
                        g.clone(),
                        IndexGroup {
                            hosts: hosts.clone(),
                            recipients: recipients[g].clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn warn_missing_pubkeys(desired: &Desired) {
        for h in &desired.hosts_without_pubkey {
            eprintln!("warning: host {h} has no sops.rekey.hostPubkey and gets no secrets");
        }
    }

    pub fn rekey(&mut self, force: bool) -> Result<()> {
        let Some(storage) = self.storage_dir()? else {
            eprintln!("No host uses rekeyed secrets.");
            return Ok(());
        };
        let missing = self.missing()?;
        let no_generator: Vec<&String> = missing
            .iter()
            .filter(|id| self.m.generator(id).is_none())
            .collect();
        if !no_generator.is_empty() {
            let list: Vec<String> = no_generator
                .iter()
                .map(|id| format!("  {id} (in {})", self.m.secrets[*id].file))
                .collect();
            bail!("these secrets don't exist and have no generator; add them with `sops-rekey edit`:\n{}", list.join("\n"));
        }
        let gen_order = self.plan_generation(&missing, false, &missing)?;
        let rewritten_files: BTreeSet<String> = gen_order
            .iter()
            .map(|id| self.m.secrets[id].file.clone())
            .collect();

        let desired = Desired::compute(&self.m);
        Self::warn_missing_pubkeys(&desired);
        let recipients = self.group_recipients(&desired)?;
        let index_path = self.path(&storage).join(INDEX_FILE);
        let index = Index::load(&index_path)?;
        let hashes = self.hashes()?;

        let mut to_write = BTreeMap::new();
        for g in desired.groups.keys() {
            let reason = if force {
                Some("forced".to_string())
            } else {
                self.group_staleness(g, &desired, &index, &storage, &hashes, &rewritten_files)
            };
            if let Some(r) = reason {
                to_write.insert(g.clone(), r);
            }
        }
        let obsolete: Vec<&String> = index
            .groups
            .keys()
            .filter(|g| !desired.groups.contains_key(*g))
            .collect();

        let mut needed = self.generation_inputs(&gen_order);
        for g in to_write.keys() {
            for id in desired.group_secrets(g) {
                needed.insert(self.m.secrets[id].file.clone());
            }
        }
        let mut plain = self.decrypt_all(&needed)?;

        self.run_generators(&gen_order, &mut plain)?;
        self.write_masters(&plain)?;
        let hashes = self.hashes()?;

        let sops = Sops::new(None);
        for (g, reason) in &to_write {
            let mut doc = Value::Null;
            for id in desired.group_secrets(g) {
                let path: Vec<&str> = id.split('/').collect();
                tree::insert(
                    &mut doc,
                    &path,
                    Value::String(plain.leaf(&self.m, id)?),
                    false,
                )
                .with_context(|| format!("building group {g}"))?;
            }
            let file = format!("{g}.yaml");
            let data = serde_json::to_vec(&doc)?;
            let r = Recipients {
                pgp: vec![],
                age: recipients[g].clone(),
            };
            let out = sops.encrypt(
                &data,
                Format::Json,
                Format::Yaml,
                &file,
                &r,
                &EncryptOpts::default(),
            )?;
            let path = self.path(&storage).join(&file);
            util::write_atomic(&path, &out)?;
            eprintln!("Rekeyed {storage}/{file} ({reason})");
            self.touched.written.push(path);
        }
        for g in obsolete {
            let path = self.path(&storage).join(format!("{g}.yaml"));
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            eprintln!("Removed obsolete {storage}/{g}.yaml");
            self.touched.deleted.push(path);
        }
        let new_index = self.build_index(&desired, &recipients, &hashes);
        if new_index != index || !index_path.exists() {
            util::write_atomic(&index_path, &new_index.to_bytes())?;
            self.touched.written.push(index_path);
        }
        if to_write.is_empty() && gen_order.is_empty() && self.touched.deleted.is_empty() {
            eprintln!("Everything is up to date.");
        }
        Ok(())
    }
}
