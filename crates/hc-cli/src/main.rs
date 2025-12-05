use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    commands::{
        bench::{run_bench, BenchArgs, BenchScenario},
        inspect::run_inspect,
        prove::{run_prove, write_proof, AutoProfile, CommitmentFlag, ProveOptions},
        recursion::{run_recursion, RecursionArgs},
        verify::{run_verify, run_verify_from_file},
    },
    config::{load_file_config, lookup_preset, Preset},
};

mod commands;
mod config;

#[derive(Parser, Debug)]
#[command(name = "hc-cli")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Prove {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        block_size: Option<usize>,
        #[arg(long, default_value_t = false)]
        auto_block: bool,
        #[arg(long)]
        trace_length: Option<usize>,
        #[arg(long)]
        target_rss_mb: Option<usize>,
        #[arg(long, value_enum, default_value_t = AutoProfile::Balanced)]
        profile: AutoProfile,
        #[arg(long, default_value_t = false)]
        hardware_detect: bool,
        #[arg(long)]
        preset: Option<String>,
        #[arg(long)]
        tuner_cache: Option<PathBuf>,
        #[arg(long = "no-tuner-cache", default_value_t = false)]
        no_tuner_cache: bool,
        #[arg(long, value_enum, default_value_t = CommitmentFlag::Stark)]
        commitment: CommitmentFlag,
    },
    Verify {
        #[arg(long)]
        input: Option<PathBuf>,
    },
    Inspect,
    Bench {
        #[arg(long, default_value_t = 1)]
        iterations: usize,
        #[arg(long, default_value_t = 2)]
        block_size: usize,
        #[arg(long, value_enum, default_value_t = BenchScenario::Prover)]
        scenario: BenchScenario,
        #[arg(long)]
        leaves: Option<usize>,
        #[arg(long)]
        queries: Option<usize>,
        #[arg(long)]
        fanout: Option<usize>,
        #[arg(long)]
        columns: Option<usize>,
        #[arg(long)]
        degree: Option<usize>,
        #[arg(long)]
        samples: Option<usize>,
        #[arg(long)]
        proofs: Option<usize>,
        #[arg(long, default_value_t = false)]
        auto_block_size: bool,
        #[arg(long)]
        target_rss_mb: Option<usize>,
        #[arg(long)]
        trace_length: Option<usize>,
        #[arg(long, value_enum, default_value_t = AutoProfile::Balanced)]
        profile: AutoProfile,
        #[arg(long, default_value_t = false)]
        hardware_detect: bool,
        #[arg(long)]
        preset: Option<String>,
        #[arg(long)]
        tuner_cache: Option<PathBuf>,
        #[arg(long = "no-tuner-cache", default_value_t = false)]
        no_tuner_cache: bool,
        #[arg(long, default_value = "benchmarks")]
        metrics_dir: PathBuf,
        #[arg(long)]
        metrics_tag: Option<String>,
    },
    Recursion {
        #[arg(long = "proof", required = true, value_name = "FILE")]
        proofs: Vec<PathBuf>,
        #[arg(long)]
        fan_in: Option<usize>,
        #[arg(long)]
        max_depth: Option<usize>,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long)]
        metrics: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let file_cfg = load_file_config(cli.config.as_deref());
    match cli.command {
        Commands::Prove {
            output,
            block_size,
            auto_block,
            trace_length,
            target_rss_mb,
            profile,
            hardware_detect,
            preset,
            tuner_cache,
            no_tuner_cache,
            commitment,
        } => {
            let mut options = ProveOptions {
                block_size,
                auto_block,
                trace_length_hint: trace_length,
                target_rss_mb,
                profile,
                hardware_detect,
                tuner_cache,
                disable_tuner_cache: no_tuner_cache,
                commitment,
            };
            if let Some(name) = preset.as_deref() {
                if let Some(preset_cfg) = lookup_preset(&file_cfg, name) {
                    apply_prove_preset(&preset_cfg, &mut options)?;
                } else {
                    anyhow::bail!("unknown preset '{name}'");
                }
            }
            let proof = run_prove(&options)?;
            if let Some(path) = output {
                write_proof(&path, &proof)?;
                println!("wrote proof to {}", path.display());
            }
            println!(
                "trace commitment: {}",
                commands::prove::describe_commitment(&proof.trace_commitment)
            );
        }
        Commands::Verify { input } => {
            if let Some(path) = input {
                run_verify_from_file(&path)?;
            } else {
                run_verify()?;
            }
            println!("proof verified");
        }
        Commands::Inspect => run_inspect()?,
        Commands::Bench {
            iterations,
            block_size,
            scenario,
            leaves,
            queries,
            fanout,
            columns,
            degree,
            samples,
            auto_block_size,
            proofs,
            target_rss_mb,
            trace_length,
            profile,
            hardware_detect,
            preset,
            tuner_cache,
            no_tuner_cache,
            metrics_dir,
            metrics_tag,
        } => {
            let mut args = BenchArgs {
                iterations,
                block_size,
                scenario,
                leaves,
                queries,
                fanout,
                columns,
                degree,
                samples,
                proofs,
                auto_block_size,
                target_rss_mb,
                trace_length,
                profile,
                hardware_detect,
                tuner_cache,
                disable_tuner_cache: no_tuner_cache,
                metrics_dir,
                metrics_tag,
            };
            if let Some(name) = preset.as_deref() {
                if let Some(preset_cfg) = lookup_preset(&file_cfg, name) {
                    apply_bench_preset(&preset_cfg, &mut args)?;
                } else {
                    anyhow::bail!("unknown preset '{name}'");
                }
            }
            run_bench(args)?
        }
        Commands::Recursion {
            proofs,
            fan_in,
            max_depth,
            artifact,
            metrics,
        } => run_recursion(RecursionArgs {
            proofs,
            fan_in,
            max_depth,
            artifact_path: artifact,
            metrics_path: metrics,
        })?,
    }
    Ok(())
}

fn apply_prove_preset(preset: &Preset, opts: &mut ProveOptions) -> Result<()> {
    if let Some(block_size) = preset.block_size {
        if opts.block_size.is_none() {
            opts.block_size = Some(block_size);
        }
    }
    if let Some(auto_block) = preset.auto_block {
        if !opts.auto_block {
            opts.auto_block = auto_block;
        }
    }
    if let Some(trace_length) = preset.trace_length {
        if opts.trace_length_hint.is_none() {
            opts.trace_length_hint = Some(trace_length);
        }
    }
    if let Some(target_rss) = preset.target_rss_mb {
        if opts.target_rss_mb.is_none() {
            opts.target_rss_mb = Some(target_rss);
        }
    }
    if let Some(hw_detect) = preset.hardware_detect {
        if !opts.hardware_detect {
            opts.hardware_detect = hw_detect;
        }
    }
    if let Some(commitment_label) = preset.commitment.as_deref() {
        if let Some(flag) = CommitmentFlag::from_label(commitment_label) {
            opts.commitment = flag;
        } else {
            anyhow::bail!("unknown commitment '{commitment_label}' in preset");
        }
    }
    if let Some(cache_path) = preset.tuner_cache.as_ref() {
        if opts.tuner_cache.is_none() {
            opts.tuner_cache = Some(PathBuf::from(cache_path));
        }
    }
    if let Some(disable_cache) = preset.disable_tuner_cache {
        if !opts.disable_tuner_cache {
            opts.disable_tuner_cache = disable_cache;
        }
    }
    if let Some(profile_name) = preset.profile.as_deref() {
        if let Some(profile) = AutoProfile::from_label(profile_name) {
            opts.profile = profile;
        } else {
            anyhow::bail!("unknown profile '{profile_name}' in preset");
        }
    }
    Ok(())
}

fn apply_bench_preset(preset: &Preset, args: &mut BenchArgs) -> Result<()> {
    if let Some(block_size) = preset.block_size {
        if !args.auto_block_size {
            args.block_size = block_size;
        }
    }
    if let Some(auto_block) = preset.auto_block {
        if auto_block {
            args.auto_block_size = true;
        }
    }
    if let Some(trace_length) = preset.trace_length {
        if args.trace_length.is_none() {
            args.trace_length = Some(trace_length);
        }
    }
    if let Some(target_rss) = preset.target_rss_mb {
        if args.target_rss_mb.is_none() {
            args.target_rss_mb = Some(target_rss);
        }
    }
    if let Some(hw_detect) = preset.hardware_detect {
        if hw_detect {
            args.hardware_detect = true;
        }
    }
    if let Some(cache_path) = preset.tuner_cache.as_ref() {
        if args.tuner_cache.is_none() {
            args.tuner_cache = Some(PathBuf::from(cache_path));
        }
    }
    if let Some(disable_cache) = preset.disable_tuner_cache {
        if disable_cache {
            args.disable_tuner_cache = true;
        }
    }
    if let Some(profile_name) = preset.profile.as_deref() {
        if let Some(profile) = AutoProfile::from_label(profile_name) {
            args.profile = profile;
        } else {
            anyhow::bail!("unknown profile '{profile_name}' in preset");
        }
    }
    if let Some(dir) = preset.metrics_dir.as_ref() {
        if args.metrics_dir == PathBuf::from("benchmarks") {
            args.metrics_dir = dir.clone();
        }
    }
    if let Some(tag) = preset.metrics_tag.as_ref() {
        if args.metrics_tag.is_none() {
            args.metrics_tag = Some(tag.clone());
        }
    }
    Ok(())
}
