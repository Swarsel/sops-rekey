mod commands;
mod graph;
mod identities;
mod index;
mod manifest;
mod sops;
mod tree;
mod util;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sops-rekey",
    version,
    about = "Rekey and generate sops secrets for NixOS hosts",
    long_about = "Rekey and generate sops secrets for NixOS hosts.\n\nNormally run as `nix run .#sops-rekey -- <command>`, which passes the manifest built from your NixOS configurations."
)]
struct Cli {
    #[arg(
        long,
        env = "SOPS_REKEY_MANIFEST",
        help = "Manifest built by the sops-rekey Nix integration"
    )]
    manifest: PathBuf,

    #[arg(
        short = 'a',
        long,
        global = true,
        help = "`git add` all files that were written or deleted"
    )]
    add_to_git: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "Generate missing secrets, then rekey all out-of-date group files")]
    Rekey {
        #[arg(short, long, help = "Rewrite all group files, even if up to date")]
        force: bool,
    },
    #[command(about = "Generate secrets that have a generator")]
    Generate {
        #[arg(
            short,
            long,
            help = "Regenerate even existing secrets, plus everything depending on them"
        )]
        force: bool,
        #[arg(
            short,
            long,
            value_delimiter = ',',
            help = "Only secrets with one of these tags"
        )]
        tags: Vec<String>,
        #[arg(help = "Secret ids, `sops.secrets` names or `host:name` (default: all)")]
        secrets: Vec<String>,
    },
    #[command(about = "Edit (or create) a master file with sops")]
    Edit { file: PathBuf },
    #[command(about = "Exit non-zero if anything needs generating or rekeying; never decrypts")]
    Check,
}

fn run(cli: Cli) -> Result<bool> {
    let manifest = manifest::Manifest::load(&cli.manifest)?;
    let mut repo = commands::Repo::new(util::find_root()?, manifest);
    let ok = match &cli.command {
        Cmd::Rekey { force } => repo.rekey(*force).map(|_| true),
        Cmd::Generate {
            force,
            tags,
            secrets,
        } => repo.generate(secrets, tags, *force).map(|_| true),
        Cmd::Edit { file } => repo.edit(file).map(|_| true),
        Cmd::Check => repo.check(),
    };
    if cli.add_to_git {
        repo.touched.git_add(&repo.root)?;
    }
    ok
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
