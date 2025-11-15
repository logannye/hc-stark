use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::commands::{
    bench::run_bench, inspect::run_inspect, prove::run_prove, verify::run_verify,
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
    Prove,
    Verify,
    Inspect,
    Bench {
        #[arg(long, default_value_t = 1)]
        iterations: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Prove => {
            let proof = run_prove()?;
            println!("trace root: {}", proof.trace_root);
        }
        Commands::Verify => {
            run_verify()?;
            println!("proof verified");
        }
        Commands::Inspect => run_inspect()?,
        Commands::Bench { iterations } => run_bench(iterations)?,
    }
    Ok(())
}
