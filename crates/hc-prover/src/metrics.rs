#[derive(Clone, Default, Debug)]
pub struct ProverMetrics {
    pub trace_blocks_loaded: usize,
    pub fri_blocks_loaded: usize,
    pub composition_blocks_loaded: usize,
}

impl ProverMetrics {
    pub fn add_trace_blocks(&mut self, count: usize) {
        self.trace_blocks_loaded += count;
    }

    pub fn add_fri_blocks(&mut self, count: usize) {
        self.fri_blocks_loaded += count;
    }

    pub fn add_composition_blocks(&mut self, count: usize) {
        self.composition_blocks_loaded += count;
    }
}
