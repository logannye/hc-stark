use clap::Args;

#[derive(Args, Debug)]
pub struct CliConfig {
    #[arg(long, default_value_t = 2)]
    pub block_size: usize,
}
