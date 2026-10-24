use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Json,
    Dotenv,
    Ini,
    Binary,
}

impl Format {
    pub fn from_path(path: &str) -> Self {
        match Path::new(path).extension().and_then(|e| e.to_str()) {
            Some("yaml" | "yml") => Format::Yaml,
            Some("json") => Format::Json,
            Some("env") => Format::Dotenv,
            Some("ini") => Format::Ini,
            _ => Format::Binary,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Yaml => "yaml",
            Format::Json => "json",
            Format::Dotenv => "dotenv",
            Format::Ini => "ini",
            Format::Binary => "binary",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Recipients {
    pub pgp: Vec<String>,
    pub age: Vec<String>,
}

impl Recipients {
    pub fn is_empty(&self) -> bool {
        self.pgp.is_empty() && self.age.is_empty()
    }

    fn args(&self, cmd: &mut Command) {
        if !self.pgp.is_empty() {
            cmd.arg("--pgp").arg(self.pgp.join(","));
        }
        if !self.age.is_empty() {
            cmd.arg("--age").arg(self.age.join(","));
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct EncryptOpts {
    pub flags: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct Metadata {
    pub pgp: Vec<String>,
    pub age: Vec<String>,
    pub foreign_keys: Vec<String>,
    pub key_groups: bool,
    pub opts: EncryptOpts,
    pub mac_only_encrypted: bool,
}

pub struct Sops {
    age_key: Option<String>,
}

impl Sops {
    pub fn new(age_key: Option<String>) -> Self {
        Sops { age_key }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new("sops");
        c.arg("--config").arg("/dev/null");
        if let Some(k) = &self.age_key {
            c.env("SOPS_AGE_KEY", k);
        }
        c
    }

    pub fn decrypt(&self, path: &Path) -> Result<Value> {
        let out = self
            .cmd()
            .arg("decrypt")
            .arg("--output-type")
            .arg("json")
            .arg(path)
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .context("running sops (is it in PATH?)")?;
        if !out.status.success() {
            bail!("sops failed to decrypt {}", path.display());
        }
        serde_json::from_slice(&out.stdout)
            .with_context(|| format!("parsing decrypted {}", path.display()))
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        input: Format,
        output: Format,
        filename: &str,
        recipients: &Recipients,
        opts: &EncryptOpts,
    ) -> Result<Vec<u8>> {
        if recipients.is_empty() {
            bail!("no recipients to encrypt {filename} for");
        }
        let mut cmd = self.cmd();
        cmd.arg("encrypt")
            .arg("--input-type")
            .arg(input.as_str())
            .arg("--output-type")
            .arg(output.as_str())
            .arg("--filename-override")
            .arg(filename);
        recipients.args(&mut cmd);
        for (flag, value) in &opts.flags {
            cmd.arg(flag).arg(value);
        }
        cmd.arg("/dev/stdin");
        crate::util::run_with_stdin(&mut cmd, plaintext)
            .with_context(|| format!("encrypting {filename}"))
    }

    pub fn edit(&self, path: &Path, recipients: &Recipients) -> Result<()> {
        let mut cmd = self.cmd();
        cmd.arg("edit");
        if !path.exists() {
            recipients.args(&mut cmd);
        }
        let status = cmd.arg(path).status().context("running sops")?;
        if !status.success() && status.code() != Some(200) {
            bail!("sops edit failed for {}", path.display());
        }
        Ok(())
    }
}

pub fn read_structure(path: &Path, format: Format) -> Result<Option<Value>> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let ctx = || format!("parsing encrypted {}", path.display());
    let mut v = match format {
        Format::Yaml => serde_yaml_ng::from_slice::<Value>(&data).with_context(ctx)?,
        Format::Json | Format::Binary => {
            serde_json::from_slice::<Value>(&data).with_context(ctx)?
        }
        Format::Dotenv => parse_dotenv(&String::from_utf8_lossy(&data)),
        Format::Ini => parse_ini(&String::from_utf8_lossy(&data)),
    };
    if format == Format::Dotenv {
        if let Value::Object(m) = &mut v {
            m.retain(|k, _| !k.starts_with("sops_"));
        }
    }
    Ok(Some(v))
}

fn parse_dotenv(s: &str) -> Value {
    let mut m = Map::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            m.insert(k.trim().to_string(), Value::String(v.to_string()));
        }
    }
    Value::Object(m)
}

fn parse_ini(s: &str) -> Value {
    let mut root = Map::new();
    let mut section = String::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if section == "sops" {
                continue;
            }
            let entry = root
                .entry(section.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(sec) = entry {
                sec.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
            }
        }
    }
    Value::Object(root)
}

pub fn metadata(path: &Path, format: Format) -> Result<Metadata> {
    if matches!(format, Format::Dotenv | Format::Ini) {
        bail!(
            "reading metadata of {} files is not supported",
            format.as_str()
        );
    }
    let tree = read_structure(path, format)?
        .ok_or_else(|| anyhow!("{} does not exist", path.display()))?;
    let sops = tree
        .get("sops")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("{} is not a sops file (no metadata)", path.display()))?;
    let mut md = Metadata::default();
    let list = |key: &str, field: &str| -> Vec<String> {
        sops.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get(field)?.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    md.pgp = list("pgp", "fp");
    md.age = list("age", "recipient");
    for key in ["kms", "gcp_kms", "azure_kv", "hc_vault", "hckms"] {
        if sops
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
        {
            md.foreign_keys.push(key.to_string());
        }
    }
    md.key_groups = sops
        .get("key_groups")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    md.mac_only_encrypted = sops
        .get("mac_only_encrypted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    for key in [
        "unencrypted_suffix",
        "encrypted_suffix",
        "unencrypted_regex",
        "encrypted_regex",
        "unencrypted_comment_regex",
        "encrypted_comment_regex",
    ] {
        if let Some(v) = sops.get(key).and_then(Value::as_str) {
            md.opts
                .flags
                .push((format!("--{}", key.replace('_', "-")), v.to_string()));
        }
    }
    Ok(md)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(Format::from_path("a/b.yaml"), Format::Yaml);
        assert_eq!(Format::from_path("a/b.yml"), Format::Yaml);
        assert_eq!(Format::from_path("b.json"), Format::Json);
        assert_eq!(Format::from_path("b.env"), Format::Dotenv);
        assert_eq!(Format::from_path("b.ini"), Format::Ini);
        assert_eq!(Format::from_path("b.age"), Format::Binary);
        assert_eq!(Format::from_path("noext"), Format::Binary);
    }

    #[test]
    fn dotenv_structure_hides_metadata() {
        let dir = std::env::temp_dir().join(format!("sops-rekey-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.env");
        std::fs::write(&p, "# c\nFOO=ENC[...]\nsops_version=3.9.0\n").unwrap();
        let v = read_structure(&p, Format::Dotenv).unwrap().unwrap();
        assert_eq!(v, serde_json::json!({"FOO": "ENC[...]"}));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ini_structure() {
        let v = parse_ini("[a]\nx = ENC\n[sops]\nversion = 3\n");
        assert_eq!(v, serde_json::json!({"a": {"x": "ENC"}}));
    }
}
