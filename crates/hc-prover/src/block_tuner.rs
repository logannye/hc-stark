use crate::metrics::ProverMetrics;
use dirs::home_dir;
use hc_core::error::{HcError, HcResult};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

#[cfg(target_os = "linux")]
use std::thread;

/// Selection bias the user cares about when auto-tuning block sizes.
#[derive(Clone, Copy, Debug, Default)]
pub enum AutoStrategy {
    #[default]
    Balanced,
    Memory,
    Latency,
}

/// Heuristic parameters used for auto-selecting the prover block size.
#[derive(Clone, Copy, Debug)]
pub struct AutoBlockConfig {
    pub min_block: usize,
    pub max_block: usize,
    pub target_rss_mb: usize,
    pub strategy: AutoStrategy,
}

impl AutoBlockConfig {
    pub fn with_target_rss(mut self, target: usize) -> Self {
        if target > 0 {
            self.target_rss_mb = target;
        }
        self
    }

    pub fn with_max_block(mut self, max_block: usize) -> Self {
        if max_block >= self.min_block {
            self.max_block = max_block;
        }
        self
    }

    pub fn with_strategy(mut self, strategy: AutoStrategy) -> Self {
        self.strategy = strategy;
        self
    }
}

impl Default for AutoBlockConfig {
    fn default() -> Self {
        Self {
            min_block: 32,
            max_block: 1 << 15,
            target_rss_mb: 512,
            strategy: AutoStrategy::Balanced,
        }
    }
}

const CACHE_DIR: &str = ".hc-stark";
const CACHE_FILE: &str = "tuner_history.json";

impl AutoStrategy {
    pub fn label(self) -> &'static str {
        match self {
            AutoStrategy::Balanced => "balanced",
            AutoStrategy::Memory => "memory",
            AutoStrategy::Latency => "latency",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TunerHistory {
    #[serde(default)]
    entries: HashMap<String, TunerHistoryEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunerHistoryEntry {
    pub avg_block_size: f64,
    pub avg_replay_factor: f64,
    pub samples: usize,
    pub last_block_size: usize,
    pub last_trace_length: usize,
}

impl Default for TunerHistoryEntry {
    fn default() -> Self {
        Self {
            avg_block_size: 0.0,
            avg_replay_factor: 0.0,
            samples: 0,
            last_block_size: 0,
            last_trace_length: 0,
        }
    }
}

impl TunerHistory {
    pub fn load(path: &Path) -> Self {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(parsed) = serde_json::from_slice::<TunerHistory>(&bytes) {
                return parsed;
            }
        }
        TunerHistory::default()
    }

    pub fn save(&self, path: &Path) -> HcResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self)
            .map_err(|err| HcError::serialization(format!("tuner history: {err}")))?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn entry(&self, strategy: AutoStrategy, trace_length: usize) -> Option<&TunerHistoryEntry> {
        let key = history_key(strategy, trace_length);
        self.entries.get(&key)
    }

    pub fn record(
        &mut self,
        strategy: AutoStrategy,
        trace_length: usize,
        block_size: usize,
        metrics: &ProverMetrics,
    ) {
        let key = history_key(strategy, trace_length);
        let entry = self.entries.entry(key).or_default();
        entry.record(trace_length, block_size, metrics);
    }
}

impl TunerHistoryEntry {
    fn record(&mut self, trace_length: usize, block_size: usize, metrics: &ProverMetrics) {
        let expected_blocks = expected_block_count(trace_length, block_size) as f64;
        let replay = if expected_blocks > 0.0 {
            metrics.trace_blocks_loaded as f64 / expected_blocks
        } else {
            1.0
        };
        self.samples += 1;
        let count = self.samples as f64;
        if self.samples == 1 {
            self.avg_block_size = block_size as f64;
            self.avg_replay_factor = replay;
        } else {
            self.avg_block_size =
                ((self.avg_block_size * (count - 1.0)) + block_size as f64) / count;
            self.avg_replay_factor = ((self.avg_replay_factor * (count - 1.0)) + replay) / count;
        }
        self.last_block_size = block_size;
        self.last_trace_length = trace_length;
    }
}

pub fn default_history_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(CACHE_DIR).join(CACHE_FILE))
}

fn history_key(strategy: AutoStrategy, trace_length: usize) -> String {
    format!("{}:{}", strategy.label(), bucket_trace_length(trace_length))
}

fn bucket_trace_length(trace_length: usize) -> usize {
    if trace_length == 0 {
        return 1;
    }
    trace_length.next_power_of_two()
}

/// Basic √T heuristic without additional feedback.
pub fn recommend_block_size(trace_length: usize, cfg: AutoBlockConfig) -> HcResult<usize> {
    recommend_block_size_with_feedback(trace_length, cfg, None, None)
}

/// Recommend a block size using trace length, memory budget, existing metrics, and strategy bias.
pub fn recommend_block_size_with_feedback(
    trace_length: usize,
    cfg: AutoBlockConfig,
    metrics: Option<&ProverMetrics>,
    history: Option<&TunerHistoryEntry>,
) -> HcResult<usize> {
    if trace_length == 0 {
        return Err(HcError::invalid_argument(
            "trace length must be greater than zero for auto block sizing",
        ));
    }

    let sqrt_len = (trace_length as f64).sqrt().ceil();
    // Empirical constant: assume ~8 MB working-set per 1k rows.
    let memory_hint = (((cfg.target_rss_mb as f64) / 8.0).sqrt())
        .max(cfg.min_block as f64)
        .min(cfg.max_block as f64);
    let mut block = sqrt_len.min(memory_hint).round() as usize;

    if let Some(metrics) = metrics {
        let expected_blocks = expected_block_count(trace_length, block);
        let replay_factor = if expected_blocks == 0 {
            1.0
        } else {
            metrics.trace_blocks_loaded as f64 / expected_blocks as f64
        };
        if replay_factor > 3.0 {
            block = ((block as f64) * 1.25).round() as usize;
        } else if replay_factor < 1.2 {
            block = ((block as f64) * 0.85).round() as usize;
        }
    }

    if let Some(entry) = history {
        if entry.avg_block_size > 0.0 {
            let blend = 0.35;
            block =
                ((block as f64) * (1.0 - blend) + entry.avg_block_size * blend).round() as usize;
        }
        if entry.avg_replay_factor > 2.0 {
            block = ((block as f64) * 1.15).round() as usize;
        } else if entry.avg_replay_factor < 1.05 && entry.avg_block_size > 0.0 {
            block = ((block as f64) * 0.9).round() as usize;
        }
        if entry.last_block_size > 0 {
            let target = entry.last_block_size;
            block = ((block as f64) * 0.7 + target as f64 * 0.3).round() as usize;
        }
    }

    block = match cfg.strategy {
        AutoStrategy::Balanced => block,
        AutoStrategy::Memory => ((block as f64) * 0.85).round() as usize,
        AutoStrategy::Latency => ((block as f64) * 1.15).round() as usize,
    };

    block = block.clamp(cfg.min_block, cfg.max_block);
    Ok(block.min(trace_length))
}

/// High-level view of the current hardware. Used to seed auto-tuning defaults.
#[derive(Clone, Copy, Debug)]
pub struct HardwareProfile {
    pub os: &'static str,
    pub total_mem_mb: usize,
    pub l3_cache_kb: Option<usize>,
    pub cpu_cores: Option<usize>,
}

impl HardwareProfile {
    fn with_os(os: &'static str, total_mem_mb: usize) -> Self {
        Self {
            os,
            total_mem_mb,
            l3_cache_kb: None,
            cpu_cores: None,
        }
    }
}

/// Attempt to detect the local hardware profile. Returns `None` when probing fails.
pub fn detect_hardware_profile() -> Option<HardwareProfile> {
    #[cfg(target_os = "linux")]
    {
        detect_linux()
    }
    #[cfg(target_os = "macos")]
    {
        detect_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn detect_linux() -> Option<HardwareProfile> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let total_kb = parse_meminfo_kb(&meminfo, "MemTotal")?;
    let mut profile = HardwareProfile::with_os("linux", total_kb / 1024);
    profile.l3_cache_kb = fs::read_to_string("/sys/devices/system/cpu/cpu0/cache/index3/size")
        .ok()
        .and_then(|s| parse_cache_kb(&s));
    profile.cpu_cores = thread::available_parallelism().ok().map(|n| n.get());
    Some(profile)
}

#[cfg(target_os = "macos")]
fn detect_macos() -> Option<HardwareProfile> {
    let mem_bytes = sysctl_value("hw.memsize")?;
    let mut profile = HardwareProfile::with_os("macos", (mem_bytes / (1024 * 1024)) as usize);
    profile.l3_cache_kb = sysctl_value("hw.l3cachesize").map(|bytes| (bytes / 1024) as usize);
    profile.cpu_cores = sysctl_value("hw.physicalcpu").map(|cores| cores as usize);
    Some(profile)
}

#[cfg(target_os = "linux")]
fn parse_meminfo_kb(data: &str, key: &str) -> Option<usize> {
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let value = rest.trim_start_matches(':').trim();
            if let Some(end) = value.split_whitespace().next() {
                if let Ok(val) = usize::from_str(end) {
                    return Some(val);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn parse_cache_kb(data: &str) -> Option<usize> {
    let cleaned = data.trim().to_ascii_lowercase();
    if cleaned.ends_with("k") {
        return usize::from_str(&cleaned[..cleaned.len() - 1]).ok();
    }
    if cleaned.ends_with("m") {
        return usize::from_str(&cleaned[..cleaned.len() - 1])
            .ok()
            .map(|mb| mb * 1024);
    }
    usize::from_str(&cleaned).ok()
}

#[cfg(target_os = "macos")]
fn sysctl_value(name: &str) -> Option<u64> {
    let output = Command::new("sysctl").args(["-n", name]).output().ok()?;
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    u64::from_str(&value).ok()
}

fn expected_block_count(trace_length: usize, block_size: usize) -> usize {
    if block_size == 0 {
        return 0;
    }
    trace_length.div_ceil(block_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_strategy_returns_value() {
        let cfg = AutoBlockConfig::default();
        let block = recommend_block_size(1 << 20, cfg).unwrap();
        assert!(block >= cfg.min_block);
    }

    #[test]
    fn memory_strategy_reduces_block() {
        let cfg = AutoBlockConfig::default().with_strategy(AutoStrategy::Memory);
        let balanced = recommend_block_size(1 << 18, AutoBlockConfig::default()).unwrap();
        let memory = recommend_block_size(1 << 18, cfg).unwrap();
        assert!(memory <= balanced);
    }

    #[test]
    fn latency_strategy_increases_block() {
        let cfg = AutoBlockConfig::default().with_strategy(AutoStrategy::Latency);
        let balanced = recommend_block_size(1 << 18, AutoBlockConfig::default()).unwrap();
        let latency = recommend_block_size(1 << 18, cfg).unwrap();
        assert!(latency >= balanced);
    }

    #[test]
    fn replay_feedback_adjusts_block() {
        let cfg = AutoBlockConfig::default();
        let metrics = ProverMetrics {
            trace_blocks_loaded: 10_000,
            ..ProverMetrics::default()
        };
        let baseline = recommend_block_size_with_feedback(1 << 10, cfg, None, None).unwrap();
        let tuned = recommend_block_size_with_feedback(1 << 10, cfg, Some(&metrics), None).unwrap();
        assert!(tuned > baseline);
    }

    #[test]
    fn historical_feedback_biases_block_upwards() {
        let cfg = AutoBlockConfig::default();
        let baseline = recommend_block_size(1 << 12, cfg).unwrap();
        let history = TunerHistoryEntry {
            avg_block_size: 256.0,
            avg_replay_factor: 2.4,
            samples: 4,
            last_block_size: 256,
            last_trace_length: 1 << 12,
        };
        let tuned = recommend_block_size_with_feedback(1 << 12, cfg, None, Some(&history)).unwrap();
        assert!(tuned >= baseline);
    }

    #[test]
    fn historical_feedback_biases_block_downwards() {
        let cfg = AutoBlockConfig {
            target_rss_mb: 600_000,
            ..AutoBlockConfig::default()
        };
        let trace_len = 1 << 16;
        let baseline = recommend_block_size(trace_len, cfg).unwrap();
        let history = TunerHistoryEntry {
            avg_block_size: 64.0,
            avg_replay_factor: 1.0,
            samples: 6,
            last_block_size: 64,
            last_trace_length: trace_len,
        };
        let tuned =
            recommend_block_size_with_feedback(trace_len, cfg, None, Some(&history)).unwrap();
        assert!(tuned <= baseline);
    }
}
