use std::time::Instant;

use hc_core::{
    error::HcResult,
    field::{prime_field::GoldilocksField, FieldElement},
    poly::{evaluate_batch, evaluate_columns_parallel},
};
use serde_json::json;

pub fn bench_parallel_lde(
    columns: usize,
    degree: usize,
    samples: usize,
) -> HcResult<serde_json::Value> {
    if columns == 0 || degree == 0 || samples == 0 {
        return Err(hc_core::error::HcError::invalid_argument(
            "columns, degree, and samples must be > 0",
        ));
    }

    let coeffs = build_coeff_columns(columns, degree);
    let points: Vec<_> = (0..samples)
        .map(|i| GoldilocksField::from_u64((i as u64) + 1))
        .collect();

    let seq_start = Instant::now();
    for coeff in &coeffs {
        let _ = evaluate_batch(coeff, &points);
    }
    let sequential_ms = seq_start.elapsed().as_secs_f64() * 1000.0;

    let column_refs: Vec<_> = coeffs.iter().map(|col| col.as_slice()).collect();
    let par_start = Instant::now();
    let _ = evaluate_columns_parallel(&column_refs, &points);
    let parallel_ms = par_start.elapsed().as_secs_f64() * 1000.0;

    Ok(json!({
        "mode": "lde_parallel",
        "columns": columns,
        "degree": degree,
        "samples": samples,
        "sequential_ms": sequential_ms,
        "parallel_ms": parallel_ms,
        "speedup": if parallel_ms > 0.0 { sequential_ms / parallel_ms } else { 0.0 },
    }))
}

fn build_coeff_columns(columns: usize, degree: usize) -> Vec<Vec<GoldilocksField>> {
    (0..columns)
        .map(|c| {
            (0..degree)
                .map(|i| GoldilocksField::from_u64((c * degree + i) as u64 + 1))
                .collect()
        })
        .collect()
}
