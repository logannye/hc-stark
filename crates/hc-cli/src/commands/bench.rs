use std::time::Instant;

use anyhow::Result;

use super::prove::run_prove;

pub fn run_bench(iterations: usize) -> Result<()> {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = run_prove()?;
    }
    let elapsed = start.elapsed();
    println!(
        "Ran {iterations} iterations in {:.2?} ({:.2?} avg)",
        elapsed,
        elapsed / iterations as u32
    );
    Ok(())
}
