use std::{
    fmt, fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use clap::ValueEnum;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct BenchArgs {
    pub iterations: usize,
    pub block_size: usize,
    pub scenario: BenchScenario,
    pub leaves: Option<usize>,
    pub queries: Option<usize>,
    pub fanout: Option<usize>,
    pub columns: Option<usize>,
    pub degree: Option<usize>,
    pub samples: Option<usize>,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum BenchScenario {
    Prover,
    Merkle,
    Lde,
}

impl fmt::Display for BenchScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BenchScenario::Prover => write!(f, "prover"),
            BenchScenario::Merkle => write!(f, "merkle"),
            BenchScenario::Lde => write!(f, "lde"),
        }
    }
}

pub fn run_bench(args: BenchArgs) -> Result<()> {
    let summary = match args.scenario {
        BenchScenario::Prover => hc_bench::benchmark(args.iterations, args.block_size)?,
        BenchScenario::Merkle => hc_bench::bench_merkle_paths(
            args.leaves.unwrap_or(1 << 12),
            args.queries.unwrap_or(64),
            args.fanout.unwrap_or(2),
        )?,
        BenchScenario::Lde => hc_bench::bench_parallel_lde(
            args.columns.unwrap_or(2),
            args.degree.unwrap_or(256),
            args.samples
                .unwrap_or(args.block_size * args.iterations.max(1)),
        )?,
    };

    println!("{}", summary);
    persist_summary(&summary, &args.scenario)?;
    Ok(())
}

fn persist_summary(summary: &Value, scenario: &BenchScenario) -> Result<()> {
    let payload = json!({
        "scenario": scenario.to_string(),
        "generated_at": timestamp_secs(),
        "metrics": summary,
    });

    let out_dir = Path::new("benchmarks");
    fs::create_dir_all(out_dir)?;
    fs::write(
        out_dir.join("latest.json"),
        serde_json::to_string_pretty(&payload)?,
    )?;

    Ok(())
}

fn timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
