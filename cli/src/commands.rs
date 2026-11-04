use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

use crate::graph;
use crate::identities;
use crate::index::{Desired, Index, IndexGroup, IndexSecret, INDEX_FILE, INDEX_VERSION};
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

#[derive(Default)]
struct Hashes {
    files: BTreeMap<String, Option<String>>,
    leaves: BTreeMap<String, Option<String>>,
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
        let sops = Sops::new(identities::load(&self.m.master_identities)?);
        for file in &plain.dirty {
            let fmt = Format::from_path(file);
            if matches!(fmt, Format::Dotenv | Format::Ini) {
                bail!(
                    "cannot write generated secrets into {file}: {} master files are not supported",
                    fmt.as_str()
                );
            }
            let path = self.path(file);
            let t = &plain.trees[file];
            if path.exists() && fmt != Format::Binary {
                let buffer = match fmt {
                    Format::Json => serde_json::to_vec_pretty(t)?,
                    _ => serde_yaml_ng::to_string(t)?.into_bytes(),
                };
                sops.edit_scripted(&path, &buffer)
                    .with_context(|| format!("updating {file}"))?;
                eprintln!("Updated {file}");
            } else {
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
                let (input, data) = match fmt {
                    Format::Binary => (Format::Binary, tree::get_leaf(t, None)?.into_bytes()),
                    _ => (Format::Json, serde_json::to_vec(t)?),
                };
                let name = Path::new(file).file_name().unwrap().to_string_lossy();
                let out = sops.encrypt(&data, input, fmt, &name, &recipients, &opts)?;
                util::write_atomic(&path, &out)?;
                eprintln!("Wrote {file}");
            }
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
        hashes: &Hashes,
        generated: &BTreeSet<String>,
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
            if generated.contains(id) {
                return Some(format!("{id} is being generated"));
            }
            if index.secrets.get(id).map(|s| Some(&s.leaf_hash)) != Some(hashes.leaves[id].as_ref())
            {
                return Some(format!("{id} changed"));
            }
        }
        if !self.path(storage).join(format!("{g}.yaml")).exists() {
            return Some("file missing".into());
        }
        None
    }

    fn hashes(&self) -> Result<Hashes> {
        let mut h = Hashes::default();
        let mut structures: BTreeMap<&str, Option<Value>> = BTreeMap::new();
        for (id, s) in &self.m.secrets {
            if !structures.contains_key(s.file.as_str()) {
                let path = self.path(&s.file);
                h.files.insert(s.file.clone(), util::hash_file(&path)?);
                let st = sops::read_structure(&path, Format::from_path(&s.file))?;
                structures.insert(&s.file, st);
            }
            let leaf = structures[s.file.as_str()]
                .as_ref()
                .and_then(|st| tree::get_leaf(st, s.key.as_deref()).ok())
                .map(|ciphertext| util::hash_bytes(ciphertext.as_bytes()));
            h.leaves.insert(id.clone(), leaf);
        }
        Ok(h)
    }

    fn build_index(
        &self,
        desired: &Desired,
        recipients: &BTreeMap<String, Vec<String>>,
        hashes: &Hashes,
    ) -> Index {
        Index {
            version: INDEX_VERSION,
            files: hashes
                .files
                .iter()
                .filter_map(|(f, h)| h.clone().map(|h| (f.clone(), h)))
                .collect(),
            secrets: desired
                .secret_group
                .iter()
                .map(|(id, g)| {
                    (
                        id.clone(),
                        IndexSecret {
                            group: g.clone(),
                            leaf_hash: hashes.leaves[id].clone().unwrap_or_default(),
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
        let generated: BTreeSet<String> = gen_order.iter().cloned().collect();

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
                self.group_staleness(g, &desired, &index, &storage, &hashes, &generated)
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

    pub fn check(&self) -> Result<bool> {
        let mut ok = true;
        let missing = self.missing()?;
        for id in &missing {
            let hint = if self.m.generator(id).is_some() {
                "run `sops-rekey generate`"
            } else {
                "add it with `sops-rekey edit`"
            };
            println!("missing: {id} in {} ({hint})", self.m.secrets[id].file);
            ok = false;
        }
        let Some(storage) = self.storage_dir()? else {
            return Ok(ok);
        };
        let desired = Desired::compute(&self.m);
        Self::warn_missing_pubkeys(&desired);
        let index = Index::load(&self.path(&storage).join(INDEX_FILE))?;
        let hashes = self.hashes()?;
        for g in desired.groups.keys() {
            if let Some(reason) =
                self.group_staleness(g, &desired, &index, &storage, &hashes, &BTreeSet::new())
            {
                println!("stale: {storage}/{g}.yaml ({reason})");
                ok = false;
            }
        }
        for g in index
            .groups
            .keys()
            .filter(|g| !desired.groups.contains_key(*g))
        {
            println!("obsolete: {storage}/{g}.yaml");
            ok = false;
        }
        if ok {
            let recipients = self.group_recipients(&desired)?;
            if self.build_index(&desired, &recipients, &hashes) != index {
                println!("stale: {storage}/{INDEX_FILE}");
                ok = false;
            }
        }
        if ok {
            println!("Everything is up to date.");
        } else {
            println!("Run `sops-rekey rekey` to fix.");
        }
        Ok(ok)
    }

    pub fn edit(&mut self, file: &Path) -> Result<()> {
        let path = std::env::current_dir()?.join(file);
        let recipients = self.master_recipients()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let sops = Sops::new(identities::load(&self.m.master_identities)?);
        let before = util::hash_file(&path)?;
        sops.edit(&path, &recipients)?;
        if util::hash_file(&path)? != before {
            self.touched.written.push(path);
            eprintln!("Run `sops-rekey rekey` to distribute the changes.");
        }
        Ok(())
    }

    pub fn update_keys(&mut self) -> Result<()> {
        let want = self.master_recipients()?;
        let want_pgp: BTreeSet<String> = want.pgp.iter().map(|f| sops::normalize_fp(f)).collect();
        let want_age: BTreeSet<&str> = want.age.iter().map(String::as_str).collect();
        let files: BTreeSet<&String> = self.m.secrets.values().map(|s| &s.file).collect();
        let mut plan = Vec::new();
        for file in files {
            let path = self.path(file);
            if !path.exists() {
                continue;
            }
            let fmt = Format::from_path(file);
            if matches!(fmt, Format::Dotenv | Format::Ini) {
                eprintln!(
                    "warning: skipping {file}: update-keys does not support {} files",
                    fmt.as_str()
                );
                continue;
            }
            let md = sops::metadata(&path, fmt)?;
            let have_pgp: BTreeMap<String, &String> =
                md.pgp.iter().map(|f| (sops::normalize_fp(f), f)).collect();
            let add = Recipients {
                pgp: want
                    .pgp
                    .iter()
                    .filter(|f| !have_pgp.contains_key(&sops::normalize_fp(f)))
                    .cloned()
                    .collect(),
                age: want
                    .age
                    .iter()
                    .filter(|r| !md.age.contains(r))
                    .cloned()
                    .collect(),
            };
            let rm = Recipients {
                pgp: have_pgp
                    .iter()
                    .filter(|(n, _)| !want_pgp.contains(*n))
                    .map(|(_, f)| (*f).clone())
                    .collect(),
                age: md
                    .age
                    .iter()
                    .filter(|r| !want_age.contains(r.as_str()))
                    .cloned()
                    .collect(),
            };
            if !add.is_empty() || !rm.is_empty() {
                plan.push((file.clone(), add, rm));
            }
        }
        if plan.is_empty() {
            eprintln!("All master files are already encrypted to masterRecipients.");
            return Ok(());
        }
        let sops = Sops::new(identities::load(&self.m.master_identities)?);
        eprintln!(
            "Updating recipients of {} master file(s). Confirm on your security key when asked.",
            plan.len()
        );
        for (file, add, rm) in plan {
            eprintln!(
                "  {file}: +{:?} -{:?}",
                [add.pgp.clone(), add.age.clone()].concat(),
                [rm.pgp.clone(), rm.age.clone()].concat()
            );
            let path = self.path(&file);
            if rm.is_empty() {
                sops.update_keys(&path, &want)?;
            } else {
                eprintln!("    removing a recipient rotates the data key, so every group using {file} will be rekeyed");
                sops.rotate(&path, &add, &rm)?;
            }
            self.touched.written.push(path);
        }
        eprintln!("Run `sops-rekey rekey` to refresh the rekeyed files.");
        Ok(())
    }
}
