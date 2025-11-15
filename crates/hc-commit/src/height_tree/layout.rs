use hc_core::{
    error::{HcError, HcResult},
    utils::is_power_of_two,
};

/// Describes the height-compressed layout of a Merkle tree.
#[derive(Clone, Copy, Debug)]
pub struct HeightTreeLayout {
    leaves: usize,
    height: usize,
}

impl HeightTreeLayout {
    pub fn new(leaves: usize) -> HcResult<Self> {
        if leaves == 0 {
            return Err(HcError::invalid_argument("merkle tree must contain leaves"));
        }
        let power_of_two = leaves.next_power_of_two();
        let height = if is_power_of_two(leaves) {
            leaves.trailing_zeros() as usize
        } else {
            power_of_two.trailing_zeros() as usize
        };
        Ok(Self { leaves, height })
    }

    pub fn leaves(&self) -> usize {
        self.leaves
    }

    pub fn height(&self) -> usize {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn height_matches_next_power_of_two() {
        let layout = HeightTreeLayout::new(5).unwrap();
        assert_eq!(layout.height(), 3);
        let layout = HeightTreeLayout::new(8).unwrap();
        assert_eq!(layout.height(), 3);
    }
}
