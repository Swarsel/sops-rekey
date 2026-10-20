use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(b"age-encryption.org/v1")
        || data.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
}

pub fn load(paths: &[String]) -> Result<Option<String>> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut lines = Vec::new();
    for path in paths {
        let data =
            std::fs::read(path).with_context(|| format!("reading master identity {path}"))?;
        let data = if is_encrypted(&data) {
            eprintln!("Decrypting master identity {path}");
            let out = Command::new("age")
                .arg("--decrypt")
                .arg(path)
                .stdin(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output()
                .context("running age")?;
            if !out.status.success() {
                bail!("failed to decrypt master identity {path}");
            }
            out.stdout
        } else {
            data
        };
        let text = String::from_utf8(data)
            .with_context(|| format!("master identity {path} is not text"))?;
        lines.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }
    Ok(Some(lines.join("\n")))
}
