#[derive(Clone, Debug)]
pub struct RecursionSpec {
    pub max_depth: usize,
}

impl Default for RecursionSpec {
    fn default() -> Self {
        Self { max_depth: 8 }
    }
}
