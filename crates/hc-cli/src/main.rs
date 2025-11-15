use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::commands::{
    bench::run_bench,
    inspect::run_inspect,
    prove::{run_prove, write_proof},
    verify::{run_verify, run_verify_from_file},
};

mod commands;
mod config;

#[derive(Parser, Debug)]
#[command(name = "hc-cli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Prove {
        #[arg(long)]
        output: Option<PathBuf>,
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
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Prove { output } => {
            let proof = run_prove()?;
            if let Some(path) = output {
                write_proof(&path, &proof)?;
                println!("wrote proof to {}", path.display());
            }
            println!("trace root: {}", proof.trace_root);
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
        } => run_bench(iterations, block_size)?,
    }
    Ok(())
}
