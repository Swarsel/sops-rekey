use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::index::hex;

pub fn find_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    for dir in cwd.ancestors() {
        if dir.join("flake.nix").is_file() {
            return Ok(dir.to_path_buf());
        }
    }
    bail!(
        "no flake.nix found in {} or any parent directory",
        cwd.display()
    )
}

pub fn hash_bytes(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hash_file(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(d) => Ok(Some(hash_bytes(&d))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("sops-rekey.tmp");
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))
}

pub fn to_age_recipient(pubkey: &str) -> Result<String> {
    let pubkey = pubkey.trim();
    if pubkey.starts_with("age1") {
        return Ok(pubkey.to_string());
    }
    if !pubkey.starts_with("ssh-ed25519 ") {
        bail!("unsupported host pubkey (expected age1... or ssh-ed25519 ...): {pubkey}");
    }
    let out = run_with_stdin(&mut Command::new("ssh-to-age"), pubkey.as_bytes())
        .context("running ssh-to-age")?;
    Ok(String::from_utf8(out)?.trim().to_string())
}

pub fn run_with_stdin(cmd: &mut Command, input: &[u8]) -> Result<Vec<u8>> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("running {:?}", cmd.get_program()))?;
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&data));
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out)?;
    writer
        .join()
        .map_err(|_| anyhow!("stdin writer panicked"))??;
    let status = child.wait()?;
    if !status.success() {
        bail!("{:?} exited with {status}", cmd.get_program());
    }
    Ok(out)
}

#[derive(Default)]
pub struct Touched {
    pub written: Vec<PathBuf>,
    pub deleted: Vec<PathBuf>,
}

impl Touched {
    pub fn git_add(&self, root: &Path) -> Result<()> {
        if !self.written.is_empty() {
            let ok = Command::new("git")
                .current_dir(root)
                .args(["add", "--"])
                .args(&self.written)
                .status()?
                .success();
            if !ok {
                bail!("git add failed");
            }
        }
        if !self.deleted.is_empty() {
            let ok = Command::new("git")
                .current_dir(root)
                .args(["rm", "--cached", "--quiet", "--ignore-unmatch", "--"])
                .args(&self.deleted)
                .status()?
                .success();
            if !ok {
                bail!("git rm failed");
            }
        }
        Ok(())
    }
}
