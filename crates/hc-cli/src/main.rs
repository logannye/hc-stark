use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

mod commands;
#[cfg(feature = "legacy-research")]
mod config;
mod protocol;

#[derive(Parser, Debug)]
#[command(
    name = "tinyzkp-engine",
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
    /// Validate compatibility and resources without reading trace chunk contents.
    Doctor {
        #[arg(long)]
        job: PathBuf,
    },
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
    /// Internal read-only resource estimator for the Linux qualification harness.
    #[command(hide = true)]
    BenchmarkEstimate {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Estimate resources for a declared Plonky3 configuration.
    /// Works on configurations TinyZKP cannot prove.
    Estimate {
        #[arg(long)]
        config: PathBuf,
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
    /// Validate a declarative customer AIR and print its content digest.
    ValidateAir {
        #[arg(long)]
        air: PathBuf,
    },
    /// Validate and package a flat Goldilocks trace into fixed-size Zstandard chunks.
    PackTrace {
        #[arg(long)]
        air: PathBuf,
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        rows: u64,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        chunk_bytes: u64,
    },
    /// Prove a validated declarative AIR against a packed trace.
    ProveAir {
        #[arg(long)]
        air: PathBuf,
        #[arg(long)]
        trace_manifest: PathBuf,
        #[arg(long)]
        chunks_dir: PathBuf,
        #[arg(long)]
        public_inputs: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        /// Dedicated directory whose checkpoint is exactly `checkpoint.json`.
        #[arg(long)]
        checkpoint_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Use the conventional in-memory prover for fixed-host comparison evidence.
        #[arg(long, default_value_t = false)]
        reference: bool,
    },
    /// Resume a bounded declarative AIR proof from a durable checkpoint.
    ResumeAir {
        #[arg(long)]
        air: PathBuf,
        #[arg(long)]
        trace_manifest: PathBuf,
        #[arg(long)]
        chunks_dir: PathBuf,
        #[arg(long)]
        public_inputs: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a bounded checkpoint and all referenced artifacts without resuming it.
    InspectCheckpoint {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        air: PathBuf,
        #[arg(long)]
        trace_manifest: PathBuf,
        #[arg(long)]
        chunks_dir: PathBuf,
        #[arg(long)]
        public_inputs: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Verify a declarative AIR proof with the official Plonky3 adapter.
    VerifyAir {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Estimate and preflight a declarative AIR proof.
    EstimateAir {
        #[arg(long)]
        air: PathBuf,
        #[arg(long)]
        trace_manifest: PathBuf,
        #[arg(long)]
        public_inputs: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
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
}

#[derive(Subcommand, Debug)]
enum BenchmarkCommand {
    Plonky3 {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, value_enum, default_value_t = BenchmarkModeArg::Throughput)]
        mode: BenchmarkModeArg,
        #[arg(long)]
        report: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BenchmarkModeArg {
    Throughput,
    Ceiling,
}

impl BenchmarkModeArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Throughput => "throughput",
            Self::Ceiling => "ceiling",
        }
    }
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

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let failure = protocol::failure_from_anyhow(&error);
            ExitCode::from(protocol::write_error(&failure))
        }
    }
}

fn run() -> Result<u8> {
    match Cli::parse().command {
        Commands::Release => {
            let release_sha = hc_plonky3::release_identity();
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
                    "dependency_lock_sha256": hc_plonky3::DEPENDENCY_LOCK_SHA256,
                }))?
            );
            Ok(0)
        }
        Commands::Doctor { job } => commands::doctor::run(&job),
        Commands::Plonky3 { command } => match command {
            Plonky3Command::ValidateAir { air } => commands::plonky3::validate_air(&air),
            Plonky3Command::PackTrace {
                air,
                trace,
                rows,
                output_dir,
                chunk_bytes,
            } => commands::plonky3::pack_trace(&air, &trace, rows, &output_dir, chunk_bytes),
            Plonky3Command::ProveAir {
                air,
                trace_manifest,
                chunks_dir,
                public_inputs,
                policy,
                checkpoint_dir,
                output,
                reference,
            } => commands::plonky3::prove_air(
                &air,
                &trace_manifest,
                &chunks_dir,
                &public_inputs,
                &policy,
                &checkpoint_dir,
                &output,
                reference,
            ),
            Plonky3Command::ResumeAir {
                air,
                trace_manifest,
                chunks_dir,
                public_inputs,
                checkpoint,
                output,
            } => commands::plonky3::resume_air(
                &air,
                &trace_manifest,
                &chunks_dir,
                &public_inputs,
                &checkpoint,
                &output,
            ),
            Plonky3Command::InspectCheckpoint {
                checkpoint,
                air,
                trace_manifest,
                chunks_dir,
                public_inputs,
                policy,
            } => commands::plonky3::inspect_checkpoint(
                &checkpoint,
                &air,
                &trace_manifest,
                &chunks_dir,
                &public_inputs,
                &policy,
            ),
            Plonky3Command::VerifyAir { bundle } => commands::plonky3::verify_air(&bundle),
            Plonky3Command::EstimateAir {
                air,
                trace_manifest,
                public_inputs,
                policy,
            } => commands::plonky3::estimate_air(&air, &trace_manifest, &public_inputs, &policy),
            Plonky3Command::Prove { manifest, output } => {
                commands::plonky3::prove(&manifest, &output)
            }
            Plonky3Command::Resume { checkpoint, output } => {
                commands::plonky3::resume(&checkpoint, &output)
            }
            Plonky3Command::Verify { bundle } => commands::plonky3::verify(&bundle),
        }
        .map(|()| 0),
        Commands::Benchmark { command } => (match command {
            BenchmarkCommand::Plonky3 {
                manifest,
                mode,
                report,
            } => commands::plonky3::benchmark_guidance(&manifest, mode.as_str(), &report),
        })
        .map(|()| 0),
        Commands::Schema { output_dir } => {
            commands::plonky3::export_schemas(&output_dir).map(|()| 0)
        }
        Commands::Prove | Commands::Verify => Err(protocol::ProtocolFailure::new(
            tinyzkp_contracts::ReasonCodeV1::ManifestContractInvalid,
        )
        .into()),
        Commands::BenchmarkWorker {
            manifest,
            mode,
            output,
        } => commands::plonky3::benchmark_worker(&manifest, &mode, &output).map(|()| 0),
        Commands::BenchmarkEstimate { manifest } => {
            commands::plonky3::benchmark_estimate(&manifest).map(|()| 0)
        }
        Commands::Estimate { config } => {
            let response = commands::estimate_config::run(&config)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(0)
        }
        #[cfg(feature = "legacy-research")]
        Commands::LegacyResearch { command } => run_legacy(command).map(|()| 0),
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
