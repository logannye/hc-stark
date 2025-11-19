use hc_core::error::{HcError, HcResult};

#[derive(Clone, Debug)]
pub struct RecursionSpec {
    pub max_depth: usize,
    pub fan_in: usize,
}

impl RecursionSpec {
    pub fn validate_batch(&self, proofs: usize) -> HcResult<()> {
        if proofs > self.fan_in {
            return Err(HcError::invalid_argument(format!(
                "recursion fan-in exceeded: {proofs} > {}",
                self.fan_in
            )));
        }
        Ok(())
    }

    pub fn plan_for(&self, total_proofs: usize) -> HcResult<RecursionSchedule> {
        if total_proofs == 0 {
            return Err(HcError::invalid_argument(
                "cannot build recursion schedule for zero proofs",
            ));
        }
        let mut current: Vec<NodeRef> = (0..total_proofs).map(|idx| NodeRef { id: idx }).collect();
        let mut levels = Vec::new();
        let mut next_node_id = total_proofs;
        let mut depth = 0;

        while current.len() > 1 {
            if depth >= self.max_depth {
                return Err(HcError::invalid_argument(format!(
                    "recursion depth exceeded: {} > {}",
                    depth, self.max_depth
                )));
            }

            let mut batches = Vec::new();
            let mut next = Vec::new();

            for chunk in current.chunks(self.fan_in) {
                let inputs = chunk.iter().map(|node| node.id).collect::<Vec<_>>();
                let output = NodeRef { id: next_node_id };
                next_node_id += 1;
                batches.push(BatchPlan {
                    inputs,
                    output: output.id,
                });
                next.push(output);
            }

            levels.push(RecursionLevel {
                level_index: depth + 1,
                batches,
            });

            depth += 1;
            current = next;
        }

        Ok(RecursionSchedule {
            total_inputs: total_proofs,
            levels,
            root: current[0].id,
        })
    }
}

impl Default for RecursionSpec {
    fn default() -> Self {
        Self {
            max_depth: 4,
            fan_in: 8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursionSchedule {
    pub total_inputs: usize,
    pub levels: Vec<RecursionLevel>,
    pub root: usize,
}

impl RecursionSchedule {
    pub fn depth(&self) -> usize {
        self.levels.len()
    }

    pub fn total_batches(&self) -> usize {
        self.levels.iter().map(|level| level.batches.len()).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursionLevel {
    pub level_index: usize,
    pub batches: Vec<BatchPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPlan {
    pub inputs: Vec<usize>,
    pub output: usize,
}

#[derive(Clone, Debug)]
struct NodeRef {
    id: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_balanced_tree() {
        let spec = RecursionSpec {
            max_depth: 3,
            fan_in: 2,
        };
        let schedule = spec.plan_for(5).unwrap();
        assert_eq!(schedule.total_inputs, 5);
        assert_eq!(schedule.depth(), 3);
        assert_eq!(schedule.total_batches(), 6);
        assert_eq!(schedule.levels[0].batches[0].inputs, vec![0, 1]);
        assert_eq!(schedule.levels[0].batches[1].inputs, vec![2, 3]);
    }

    #[test]
    fn rejects_excess_depth() {
        let spec = RecursionSpec {
            max_depth: 1,
            fan_in: 2,
        };
        let err = spec.plan_for(6).unwrap_err();
        assert!(format!("{err}").contains("depth exceeded"));
    }
}
