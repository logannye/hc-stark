use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use ark_bn254::Fr;
use ark_ec::Group;
use ark_ff::PrimeField;
use hc_commit::merkle::standard::MerkleTree;
use hc_core::{
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement},
};
use hc_hash::blake3::Blake3;
use hc_height::{commit_streaming, StarkMerkleCommitment, StreamingKzgCommitment};
use hc_replay::{
    block_range::BlockRange, config::ReplayConfig, trace_replay::TraceReplay, traits::BlockProducer,
};
use serde_json::{json, Value};

#[cfg(unix)]
use libc::{getrusage, rusage, RUSAGE_SELF};

pub fn bench_height(leaves: usize, block_size: usize, samples: usize) -> HcResult<Value> {
    if leaves == 0 {
        return Err(HcError::invalid_argument(
            "height bench requires at least one leaf",
        ));
    }
    let block_size = block_size.max(1).min(leaves);
    let iterations = samples.max(1);
    let trace_values: Arc<Vec<GoldilocksField>> = Arc::new(
        (0..leaves)
            .map(|i| GoldilocksField::from_u64((i + 1) as u64))
            .collect(),
    );
    let poly_values: Arc<Vec<Fr>> =
        Arc::new((0..leaves).map(|i| Fr::from((i + 1) as u64)).collect());

    let mut details = Vec::with_capacity(iterations);
    let mut merkle_stream_ms = Vec::with_capacity(iterations);
    let mut merkle_stream_peak = Vec::with_capacity(iterations);
    let mut merkle_full_ms = Vec::with_capacity(iterations);
    let mut merkle_full_peak = Vec::with_capacity(iterations);
    let mut kzg_stream_ms = Vec::with_capacity(iterations);
    let mut kzg_stream_peak = Vec::with_capacity(iterations);
    let mut kzg_full_ms = Vec::with_capacity(iterations);
    let mut kzg_full_peak = Vec::with_capacity(iterations);
    let mut merkle_stream_blocks = Vec::with_capacity(iterations);
    let mut merkle_stream_elems = Vec::with_capacity(iterations);
    let mut kzg_stream_blocks = Vec::with_capacity(iterations);
    let mut kzg_stream_elems = Vec::with_capacity(iterations);
    let mut roots_match = true;

    for sample in 0..iterations {
        let (mut trace_replay, trace_loads, trace_elems) =
            replay_from_arc(Arc::clone(&trace_values), block_size)?;
        let (merkle_stream_time, merkle_stream_peak_mb, merkle_stream_root) =
            measure_with_peak(|| {
                commit_streaming(&mut trace_replay, StarkMerkleCommitment::new())
            })?;

        let (merkle_full_time, merkle_full_peak_mb, merkle_full_root) = measure_with_peak(|| {
            let leaves_hashes: Vec<_> = trace_values
                .iter()
                .map(StarkMerkleCommitment::hash_field)
                .collect();
            let tree = MerkleTree::<Blake3>::from_leaves(&leaves_hashes).map_err(|err| {
                HcError::message(format!("failed to build baseline Merkle tree: {err}"))
            })?;
            Ok(tree.root())
        })?;

        let (mut poly_replay, poly_loads, poly_elems) =
            replay_from_arc(Arc::clone(&poly_values), block_size)?;
        let (kzg_stream_time, kzg_stream_peak_mb, kzg_stream_root) = measure_with_peak(|| {
            commit_streaming(&mut poly_replay, StreamingKzgCommitment::new())
        })?;

        let (kzg_full_time, kzg_full_peak_mb, kzg_full_root) =
            measure_with_peak(|| Ok(compute_full_kzg(&poly_values)))?;

        roots_match &= merkle_stream_root == merkle_full_root && kzg_stream_root == kzg_full_root;

        let sample_detail = json!({
            "sample": sample,
            "merkle_stream_ms": merkle_stream_time,
            "merkle_stream_peak_mb": merkle_stream_peak_mb,
            "merkle_stream_blocks": trace_loads.load(Ordering::Relaxed),
            "merkle_stream_elements": trace_elems.load(Ordering::Relaxed),
            "merkle_full_ms": merkle_full_time,
            "merkle_full_peak_mb": merkle_full_peak_mb,
            "kzg_stream_ms": kzg_stream_time,
            "kzg_stream_peak_mb": kzg_stream_peak_mb,
            "kzg_stream_blocks": poly_loads.load(Ordering::Relaxed),
            "kzg_stream_elements": poly_elems.load(Ordering::Relaxed),
            "kzg_full_ms": kzg_full_time,
            "kzg_full_peak_mb": kzg_full_peak_mb,
        });
        details.push(sample_detail);
        merkle_stream_ms.push(merkle_stream_time);
        if let Some(peak) = merkle_stream_peak_mb {
            merkle_stream_peak.push(peak);
        }
        merkle_full_ms.push(merkle_full_time);
        if let Some(peak) = merkle_full_peak_mb {
            merkle_full_peak.push(peak);
        }
        kzg_stream_ms.push(kzg_stream_time);
        if let Some(peak) = kzg_stream_peak_mb {
            kzg_stream_peak.push(peak);
        }
        kzg_full_ms.push(kzg_full_time);
        if let Some(peak) = kzg_full_peak_mb {
            kzg_full_peak.push(peak);
        }
        merkle_stream_blocks.push(trace_loads.load(Ordering::Relaxed) as f64);
        merkle_stream_elems.push(trace_elems.load(Ordering::Relaxed) as f64);
        kzg_stream_blocks.push(poly_loads.load(Ordering::Relaxed) as f64);
        kzg_stream_elems.push(poly_elems.load(Ordering::Relaxed) as f64);
    }

    Ok(json!({
        "leaves": leaves,
        "block_size": block_size,
        "samples": iterations,
        "merkle_stream_ms": summarize(&merkle_stream_ms),
        "merkle_stream_peak_mb": summarize_optional(&merkle_stream_peak),
        "merkle_stream_blocks": summarize(&merkle_stream_blocks),
        "merkle_stream_elements": summarize(&merkle_stream_elems),
        "merkle_full_ms": summarize(&merkle_full_ms),
        "merkle_full_peak_mb": summarize_optional(&merkle_full_peak),
        "kzg_stream_ms": summarize(&kzg_stream_ms),
        "kzg_stream_peak_mb": summarize_optional(&kzg_stream_peak),
        "kzg_stream_blocks": summarize(&kzg_stream_blocks),
        "kzg_stream_elements": summarize(&kzg_stream_elems),
        "kzg_full_ms": summarize(&kzg_full_ms),
        "kzg_full_peak_mb": summarize_optional(&kzg_full_peak),
        "roots_match": roots_match,
        "samples_detail": details,
    }))
}

fn summarize(values: &[f64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let mean = values.iter().copied().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|v| {
            let diff = v - mean;
            diff * diff
        })
        .sum::<f64>()
        / values.len() as f64;
    json!({
        "avg": mean,
        "stddev": variance.sqrt(),
    })
}

fn summarize_optional(values: &[f64]) -> Value {
    if values.is_empty() {
        Value::Null
    } else {
        summarize(values)
    }
}

type ReplayWithCounters<T> = (
    TraceReplay<CountingProducer<T>, T>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
);

fn replay_from_arc<T: Clone + Send + Sync>(
    values: Arc<Vec<T>>,
    block_size: usize,
) -> HcResult<ReplayWithCounters<T>> {
    let trace_length = values.len();
    let (producer, loads, elements) = CountingProducer::new(values);
    let config = ReplayConfig::new(block_size, trace_length)?;
    TraceReplay::new(config, producer).map(|replay| (replay, loads, elements))
}

struct CountingProducer<T> {
    data: Arc<Vec<T>>,
    loads: Arc<AtomicUsize>,
    elements: Arc<AtomicUsize>,
}

impl<T> CountingProducer<T> {
    fn new(data: Arc<Vec<T>>) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let loads = Arc::new(AtomicUsize::new(0));
        let elements = Arc::new(AtomicUsize::new(0));
        (
            Self {
                data,
                loads: loads.clone(),
                elements: elements.clone(),
            },
            loads,
            elements,
        )
    }
}

impl<T: Clone + Send + Sync> BlockProducer<T> for CountingProducer<T> {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<T>> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        self.elements.fetch_add(range.len, Ordering::Relaxed);
        Ok(self.data[range.start..range.end()].to_vec())
    }
}

fn compute_full_kzg(values: &[Fr]) -> ark_bn254::G1Projective {
    let mut acc = Fr::from(0u64);
    let mut tau_power = Fr::from(1u64);
    let tau = Fr::from(5u64);
    for coeff in values {
        acc += *coeff * tau_power;
        tau_power *= tau;
    }
    StreamingKzgCommitment::g1_generator().mul_bigint(acc.into_bigint())
}

fn measure_with_peak<F, T>(mut f: F) -> HcResult<(f64, Option<f64>, T)>
where
    F: FnMut() -> HcResult<T>,
{
    let before = peak_rss_mb();
    let start = Instant::now();
    let value = f()?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    let after = peak_rss_mb();
    let delta = match (before, after) {
        (Some(b), Some(a)) if a >= b => Some(a - b),
        (Some(_), Some(_)) => Some(0.0),
        _ => None,
    };
    Ok((elapsed, delta, value))
}

fn peak_rss_mb() -> Option<f64> {
    #[cfg(unix)]
    unsafe {
        let mut usage: rusage = std::mem::zeroed();
        if getrusage(RUSAGE_SELF, &mut usage) == 0 {
            #[cfg(target_os = "macos")]
            {
                return Some(usage.ru_maxrss as f64 / (1024.0 * 1024.0));
            }
            #[cfg(not(target_os = "macos"))]
            {
                return Some(usage.ru_maxrss as f64 / 1024.0);
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        None
    }
}
