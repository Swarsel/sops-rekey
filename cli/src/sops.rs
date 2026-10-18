use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde_json::Value;

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
}
