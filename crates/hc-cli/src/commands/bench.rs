use std::{
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use clap::ValueEnum;
use serde_json::{json, Value};

use super::prove::AutoProfile;
use hc_prover::block_tuner::{
    default_history_path, detect_hardware_profile, recommend_block_size_with_feedback,
    AutoBlockConfig, HardwareProfile, TunerHistory,
};

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
    pub proofs: Option<usize>,
    pub auto_block_size: bool,
    pub target_rss_mb: Option<usize>,
    pub trace_length: Option<usize>,
    pub profile: AutoProfile,
    pub hardware_detect: bool,
    pub tuner_cache: Option<PathBuf>,
    pub disable_tuner_cache: bool,
    pub metrics_dir: PathBuf,
    pub metrics_tag: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum BenchScenario {
    Prover,
    Merkle,
    Lde,
    Recursion,
    Height,
}

impl fmt::Display for BenchScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BenchScenario::Prover => write!(f, "prover"),
            BenchScenario::Merkle => write!(f, "merkle"),
            BenchScenario::Lde => write!(f, "lde"),
            BenchScenario::Recursion => write!(f, "recursion"),
            BenchScenario::Height => write!(f, "height"),
        }
    }
}

pub fn run_bench(args: BenchArgs) -> Result<()> {
    let block_size = resolve_block_size(&args)?;
    println!(
        "bench scenario '{}' using block size {} (auto={}, profile={:?})",
        args.scenario, block_size, args.auto_block_size, args.profile
    );

    let summary = match args.scenario {
        BenchScenario::Prover => hc_bench::benchmark(args.iterations, block_size)?,
        BenchScenario::Merkle => hc_bench::bench_merkle_paths(
            args.leaves.unwrap_or(1 << 12),
            args.queries.unwrap_or(64),
            args.fanout.unwrap_or(2),
        )?,
        BenchScenario::Lde => hc_bench::bench_parallel_lde(
            args.columns.unwrap_or(2),
            args.degree.unwrap_or(256),
            args.samples.unwrap_or(block_size * args.iterations.max(1)),
        )?,
        BenchScenario::Recursion => hc_bench::bench_recursion(args.proofs.unwrap_or(4))?,
        BenchScenario::Height => hc_bench::bench_height(
            args.leaves.unwrap_or(1 << 16),
            block_size,
            args.samples.unwrap_or(3),
        )?,
    };

    println!("{summary}");

    let generated_at = timestamp_secs();
    if matches!(args.scenario, BenchScenario::Height) {
        write_height_csv(
            &summary,
            &args.metrics_dir,
            args.metrics_tag.as_deref(),
            generated_at,
        )?;
    }

    let record = persist_summary(
        &summary,
        &args.scenario,
        &args.metrics_dir,
        args.metrics_tag.as_deref(),
        generated_at,
    )?;
    append_history(&record, &args.scenario, &args.metrics_dir)?;
    Ok(())
}

fn persist_summary(
    summary: &Value,
    scenario: &BenchScenario,
    metrics_dir: &Path,
    tag: Option<&str>,
    generated_at: u64,
) -> Result<Value> {
    let payload = json!({
        "scenario": scenario.to_string(),
        "generated_at": generated_at,
        "tag": tag,
        "metrics": summary,
    });

    fs::create_dir_all(metrics_dir)?;
    fs::write(
        metrics_dir.join("latest.json"),
        serde_json::to_string_pretty(&payload)?,
    )?;

    Ok(payload)
}

fn append_history(record: &Value, scenario: &BenchScenario, metrics_dir: &Path) -> Result<()> {
    fs::create_dir_all(metrics_dir)?;
    let history_path = metrics_dir.join(format!("{scenario}_history.jsonl"));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn resolve_block_size(args: &BenchArgs) -> Result<usize> {
    if !args.auto_block_size {
        return Ok(args.block_size);
    }
    let mut tuner = AutoBlockConfig::default().with_strategy(args.profile.into());
    if let Some(target) = args.target_rss_mb {
        tuner = tuner.with_target_rss(target.max(64));
    }
    if args.hardware_detect {
        if let Some(profile) = detect_hardware_profile() {
            tuner = apply_hardware_hints(tuner, &profile, args.target_rss_mb.is_none());
        }
    }
    let hint = args.trace_length.unwrap_or(1 << 20);
    let history_entry = if args.disable_tuner_cache {
        None
    } else {
        let path = args.tuner_cache.clone().or_else(default_history_path);
        path.and_then(|path| {
            let history = TunerHistory::load(&path);
            history.entry(args.profile.into(), hint).cloned()
        })
    };
    recommend_block_size_with_feedback(hint, tuner, None, history_entry.as_ref()).map_err(|err| {
        anyhow::anyhow!(format!(
            "failed to auto-select bench block size (hint={hint}): {err}"
        ))
    })
}

fn write_height_csv(
    summary: &Value,
    metrics_dir: &Path,
    tag: Option<&str>,
    generated_at: u64,
) -> Result<()> {
    let Some(samples) = summary.get("samples_detail").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    fs::create_dir_all(metrics_dir)?;
    let mut csv = String::from("sample,merkle_stream_ms,merkle_stream_peak_mb,merkle_stream_blocks,merkle_stream_elements,merkle_full_ms,merkle_full_peak_mb,kzg_stream_ms,kzg_stream_peak_mb,kzg_stream_blocks,kzg_stream_elements,kzg_full_ms,kzg_full_peak_mb\n");
    for entry in samples {
        let line = [
            entry.get("sample"),
            entry.get("merkle_stream_ms"),
            entry.get("merkle_stream_peak_mb"),
            entry.get("merkle_stream_blocks"),
            entry.get("merkle_stream_elements"),
            entry.get("merkle_full_ms"),
            entry.get("merkle_full_peak_mb"),
            entry.get("kzg_stream_ms"),
            entry.get("kzg_stream_peak_mb"),
            entry.get("kzg_stream_blocks"),
            entry.get("kzg_stream_elements"),
            entry.get("kzg_full_ms"),
            entry.get("kzg_full_peak_mb"),
        ]
        .iter()
        .map(|value| {
            value
                .map(|v| v.to_string())
                .unwrap_or_else(|| "null".into())
        })
        .collect::<Vec<_>>()
        .join(",");
        csv.push_str(&line);
        csv.push('\n');
    }
    fs::write(metrics_dir.join("height_latest.csv"), csv)?;
    append_height_summary_csv(summary, metrics_dir, tag, generated_at)?;
    Ok(())
}

fn append_height_summary_csv(
    summary: &Value,
    metrics_dir: &Path,
    tag: Option<&str>,
    generated_at: u64,
) -> Result<()> {
    let path = metrics_dir.join("height_history.csv");
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let needs_header = file.metadata()?.len() == 0;
    if needs_header {
        writeln!(
            file,
            "timestamp,tag,leaves,block_size,samples,roots_match,merkle_stream_ms_avg,merkle_stream_ms_stddev,merkle_stream_peak_mb_avg,merkle_stream_peak_mb_stddev,merkle_stream_blocks_avg,merkle_stream_blocks_stddev,kzg_stream_ms_avg,kzg_stream_ms_stddev,kzg_stream_peak_mb_avg,kzg_stream_peak_mb_stddev,kzg_stream_blocks_avg,kzg_stream_blocks_stddev"
        )?;
    }
    let line = [
        generated_at.to_string(),
        tag.unwrap_or_default().to_string(),
        get_scalar(summary, "leaves"),
        get_scalar(summary, "block_size"),
        get_scalar(summary, "samples"),
        get_bool_scalar(summary, "roots_match"),
        get_stat(summary, "merkle_stream_ms", "avg"),
        get_stat(summary, "merkle_stream_ms", "stddev"),
        get_stat(summary, "merkle_stream_peak_mb", "avg"),
        get_stat(summary, "merkle_stream_peak_mb", "stddev"),
        get_stat(summary, "merkle_stream_blocks", "avg"),
        get_stat(summary, "merkle_stream_blocks", "stddev"),
        get_stat(summary, "kzg_stream_ms", "avg"),
        get_stat(summary, "kzg_stream_ms", "stddev"),
        get_stat(summary, "kzg_stream_peak_mb", "avg"),
        get_stat(summary, "kzg_stream_peak_mb", "stddev"),
        get_stat(summary, "kzg_stream_blocks", "avg"),
        get_stat(summary, "kzg_stream_blocks", "stddev"),
    ]
    .join(",");
    writeln!(file, "{line}")?;
    Ok(())
}

fn get_scalar(summary: &Value, key: &str) -> String {
    if let Some(value) = summary.get(key) {
        if let Some(num) = value.as_u64() {
            return num.to_string();
        }
        if let Some(num) = value.as_f64() {
            return format!("{num:.6}");
        }
        if let Some(num) = value.as_i64() {
            return num.to_string();
        }
        return value.to_string();
    }
    "NA".into()
}

fn get_bool_scalar(summary: &Value, key: &str) -> String {
    summary
        .get(key)
        .and_then(|v| v.as_bool())
        .map(|b| b.to_string())
        .unwrap_or_else(|| "NA".into())
}

fn get_stat(summary: &Value, field: &str, sub_key: &str) -> String {
    summary
        .get(field)
        .and_then(|v| v.get(sub_key))
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.6}"))
        .unwrap_or_else(|| "NA".into())
}

fn apply_hardware_hints(
    cfg: AutoBlockConfig,
    profile: &HardwareProfile,
    overwrite_rss: bool,
) -> AutoBlockConfig {
    let mut tuned = if overwrite_rss {
        let rss_hint = (profile.total_mem_mb / 4).max(64);
        cfg.with_target_rss(rss_hint)
    } else {
        cfg
    };
    if let Some(l3) = profile.l3_cache_kb {
        let max_block = ((l3 / 2) / 16).max(cfg.min_block);
        tuned = tuned.with_max_block(max_block);
    }
    tuned
}
