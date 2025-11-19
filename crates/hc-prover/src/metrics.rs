#[derive(Clone, Default, Debug)]
pub struct ProverMetrics {
    pub trace_blocks_loaded: usize,
    pub fri_blocks_loaded: usize,
    pub composition_blocks_loaded: usize,
    pub fri_query_batches: usize,
    pub fri_queries_answered: usize,
    pub fri_query_duration_ms: u64,
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

    pub fn record_fri_queries(&mut self, batches: usize, queries: usize, duration_ms: u64) {
        self.fri_query_batches = batches;
        self.fri_queries_answered = queries;
        self.fri_query_duration_ms = duration_ms;
    }
}
