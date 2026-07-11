use hc_plonky3::{
    GeneratedTraceV1, GoldilocksWord, ResourceBoundedWorkload, WorkloadError, WorkloadIdentityV1,
};
use hc_stream::{MatrixStore, ResourcePolicyV1};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Minimal example of a partner-owned AIR linked against TinyZKP's public
/// block-generating workload interface.
pub struct PartnerCounterAir;

impl<F> BaseAir<F> for PartnerCounterAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        2
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for PartnerCounterAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice()[0];
        let next = main.next_slice()[0];
        let public = builder.public_values();
        let initial = public[0];
        let final_value = public[1];
        builder.when_first_row().assert_eq(local, initial);
        builder
            .when_transition()
            .assert_eq(next, local + AB::Expr::ONE);
        builder.when_last_row().assert_eq(local, final_value);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PartnerCounterWorkload {
    pub start: u64,
    pub logical_rows: u64,
}

impl ResourceBoundedWorkload for PartnerCounterWorkload {
    type Air = PartnerCounterAir;

    fn identity(&self) -> WorkloadIdentityV1 {
        WorkloadIdentityV1 {
            id: "partner_counter_example",
            version: 1,
        }
    }

    fn rows(&self) -> u64 {
        self.logical_rows
    }

    fn air(&self) -> Self::Air {
        PartnerCounterAir
    }

    fn public_values(&self) -> Vec<Goldilocks> {
        let Some(final_value) = self
            .logical_rows
            .checked_sub(1)
            .and_then(|offset| self.start.checked_add(offset))
        else {
            return vec![];
        };
        vec![
            Goldilocks::from_u64(self.start),
            Goldilocks::from_u64(final_value),
        ]
    }

    fn input_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tinyzkp:partner-counter-example:v1");
        hasher.update(&self.start.to_le_bytes());
        hasher.update(&self.logical_rows.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    fn write_trace<S: MatrixStore<GoldilocksWord>>(
        &self,
        store: &mut S,
        block_rows: usize,
    ) -> Result<GeneratedTraceV1, WorkloadError> {
        if self.logical_rows == 0
            || !self.logical_rows.is_power_of_two()
            || store.rows() != self.logical_rows
            || store.columns() != 1
            || block_rows == 0
            || self.start.checked_add(self.logical_rows - 1).is_none()
        {
            return Err(WorkloadError::InvalidShape);
        }
        let rows = usize::try_from(self.logical_rows).map_err(|_| WorkloadError::InvalidShape)?;
        let block_rows = block_rows.min(rows);
        let mut values = vec![GoldilocksWord::default(); block_rows];
        for row_start in (0..rows).step_by(block_rows) {
            let row_count = (rows - row_start).min(block_rows);
            for (offset, value) in values[..row_count].iter_mut().enumerate() {
                value.0 = Goldilocks::from_u64(
                    self.start
                        .checked_add((row_start + offset) as u64)
                        .ok_or(WorkloadError::InvalidShape)?,
                );
            }
            store.write_rows(row_start as u64, row_count, &values[..row_count])?;
        }
        let trace_digest = store.finalize()?;
        Ok(GeneratedTraceV1 {
            identity: self.identity(),
            rows: self.logical_rows,
            columns: 1,
            public_values: self.public_values(),
            input_digest: self.input_digest(),
            trace_digest,
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartnerEvaluationManifestV1 {
    pub schema_version: u32,
    pub start: u64,
    pub logical_rows: u64,
    pub resource_policy: ResourcePolicyV1,
}

impl PartnerEvaluationManifestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.logical_rows == 0
            || !self.logical_rows.is_power_of_two()
            || self.start.checked_add(self.logical_rows - 1).is_none()
            || self.resource_policy.validate().is_err()
        {
            return Err("invalid partner evaluation manifest".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_stream::{CheckpointPolicy, ResourceMode};

    #[test]
    fn bounded_partner_proof_matches_conventional_official_proof() {
        let dir = tempfile::tempdir().unwrap();
        let workload = PartnerCounterWorkload {
            start: 7,
            logical_rows: 16,
        };
        let policy = ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 1024 * 1024 * 1024,
            scratch_dir: dir.path().into(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        };
        let bounded = hc_plonky3::prove_resource_bounded(&workload, &policy).unwrap();
        let conventional = hc_plonky3::prove_resource_reference(&workload).unwrap();
        assert_eq!(bounded, conventional);
        hc_plonky3::verify_resource_bounded_proof(&workload, &bounded).unwrap();
        let mut mutated = bounded;
        *mutated.last_mut().unwrap() ^= 1;
        assert!(hc_plonky3::verify_resource_bounded_proof(&workload, &mutated).is_err());
    }

    #[test]
    fn manifest_and_trace_reject_counter_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = PartnerEvaluationManifestV1 {
            schema_version: 1,
            start: u64::MAX,
            logical_rows: 2,
            resource_policy: ResourcePolicyV1 {
                mode: ResourceMode::Scratch,
                max_resident_bytes: 128 * 1024 * 1024,
                max_scratch_bytes: 1024 * 1024 * 1024,
                scratch_dir: dir.path().into(),
                max_threads: 1,
                checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
            },
        };
        assert!(manifest.validate().is_err());
    }
}
