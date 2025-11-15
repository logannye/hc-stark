use anyhow::Result;

pub fn run_bench(iterations: usize, block_size: usize) -> Result<()> {
    hc_bench::benchmark(iterations, block_size)?;
    Ok(())
}
