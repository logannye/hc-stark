#[derive(Clone, Copy, Debug)]
pub struct BlockRange {
    pub start: usize,
    pub len: usize,
}

impl BlockRange {
    pub fn new(start: usize, len: usize) -> Self {
        Self { start, len }
    }

    pub fn end(&self) -> usize {
        self.start + self.len
    }
}
