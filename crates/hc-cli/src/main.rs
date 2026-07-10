use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
#[cfg(feature = "legacy-research")]
mod config;

#[derive(Parser, Debug)]
#[command(
    name = "hc-cli",
    about = "TinyZKP resource-bounded Plonky3 backend",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Emit machine-readable CLI and backend release identity.
    Release,
    /// Official Plonky3 proof workflows.
    Plonky3 {
        #[command(subcommand)]
        command: Plonky3Command,
    },
    /// Full-pipeline benchmark orchestration.
    Benchmark {
        #[command(subcommand)]
        command: BenchmarkCommand,
    },
    /// Generate JSON Schemas from the Rust contract types.
    Schema {
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Historical generic proving is disabled in production builds.
    Prove,
    /// Historical generic verification is disabled in production builds.
    Verify,
    /// Internal child-process entry point for the Linux cgroup harness.
    #[command(hide = true)]
    BenchmarkWorker {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        mode: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Offline legacy reproduction, available only in an explicit research build.
    #[cfg(feature = "legacy-research")]
    LegacyResearch {
        #[command(subcommand)]
        command: LegacyResearchCommand,
    },
}

#[derive(Subcommand, Debug)]
enum Plonky3Command {
    Prove {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Resume {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        bundle: PathBuf,
    },
    Doctor {
        #[arg(long)]
        policy: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum BenchmarkCommand {
    Plonky3 {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "conventional")]
        baseline: String,
        #[arg(long, default_value = "bounded")]
        candidate: String,
        #[arg(long)]
        report: PathBuf,
    },
}

#[cfg(feature = "legacy-research")]
#[derive(Subcommand, Debug)]
enum LegacyResearchCommand {
    Prove {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Verify {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        allow_legacy_v2: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Release => {
            let release_sha = std::env::var("HC_RELEASE_SHA")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| option_env!("HC_RELEASE_SHA").map(ToString::to_string));
            let release_ref = std::env::var("HC_RELEASE_REF")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| option_env!("HC_RELEASE_REF").map(ToString::to_string));
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "service": "cli",
                    "package_version": env!("CARGO_PKG_VERSION"),
                    "release_sha": release_sha,
                    "release_ref": release_ref,
                    "backend": "plonky3",
                    "plonky3_version": hc_plonky3::PLONKY3_VERSION,
                    "compatibility_profile": hc_plonky3::COMPATIBILITY_PROFILE,
                }))?
            );
            Ok(())
        }
        Commands::Plonky3 { command } => match command {
            Plonky3Command::Prove { manifest, output } => {
                commands::plonky3::prove(&manifest, &output)
            }
            Plonky3Command::Resume { checkpoint, output } => {
                commands::plonky3::resume(&checkpoint, &output)
            }
            Plonky3Command::Verify { bundle } => commands::plonky3::verify(&bundle),
            Plonky3Command::Doctor { policy } => commands::plonky3::doctor(&policy),
        },
        Commands::Benchmark { command } => match command {
            BenchmarkCommand::Plonky3 {
                manifest,
                baseline,
                candidate,
                report,
            } => commands::plonky3::benchmark_guidance(
                &manifest,
                &baseline,
                &candidate,
                &report,
            ),
        },
        Commands::Schema { output_dir } => commands::plonky3::export_schemas(&output_dir),
        Commands::Prove | Commands::Verify => bail!(
            "legacy TinyZKP proving and verification are disabled; use `hc-cli plonky3 --help` or build with `--features legacy-research` for offline reproduction"
        ),
        Commands::BenchmarkWorker {
            manifest,
            mode,
            output,
        } => commands::plonky3::benchmark_worker(&manifest, &mode, &output),
        #[cfg(feature = "legacy-research")]
        Commands::LegacyResearch { command } => run_legacy(command),
    }
}

#[cfg(feature = "legacy-research")]
fn run_legacy(command: LegacyResearchCommand) -> Result<()> {
    use commands::prove::{run_prove, write_proof, ProveOptions};
    match command {
        LegacyResearchCommand::Prove { output } => {
            let proof = run_prove(&ProveOptions::default())?;
            if let Some(path) = output {
                write_proof(&path, &proof)?;
            }
            Ok(())
        }
        LegacyResearchCommand::Verify {
            input,
            allow_legacy_v2,
        } => {
            if let Some(path) = input {
                commands::verify::run_verify_from_file(&path, allow_legacy_v2)
            } else {
                commands::verify::run_verify(allow_legacy_v2)
            }
        }
    }
}
