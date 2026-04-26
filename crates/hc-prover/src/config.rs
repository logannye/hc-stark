use crate::commitment::CommitmentScheme;
use hc_core::error::{HcError, HcResult};

/// Production security bounds for prover parameters.
///
/// Default values enforce ≥128-bit security. Use `SecurityFloor::relaxed()` in
/// tests and benchmarks to allow small parameters.
#[derive(Clone, Copy, Debug)]
pub struct SecurityFloor {
    pub min_query_count: usize,
    pub min_lde_blowup_factor: usize,
    pub max_block_size: usize,
    pub max_query_count: usize,
    pub max_lde_blowup_factor: usize,
}

impl Default for SecurityFloor {
    fn default() -> Self {
        Self {
            min_query_count: 80,
            min_lde_blowup_factor: 2,
            max_block_size: 1 << 20,
            max_query_count: 200,
            max_lde_blowup_factor: 16,
        }
    }
}

impl SecurityFloor {
    /// No limits — for tests and benchmarks only.
    pub fn relaxed() -> Self {
        Self {
            min_query_count: 1,
            min_lde_blowup_factor: 1,
            max_block_size: usize::MAX,
            max_query_count: usize::MAX,
            max_lde_blowup_factor: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ZkConfig {
    /// Enable ZK masking in the prover.
    pub enabled: bool,
    /// Degree bound for the random masking polynomial R(X).
    ///
    /// See `docs/proof_format_v4_zk.md` for the construction.
    pub mask_degree: usize,
    /// Optional deterministic seed for tests/benchmarks.
    ///
    /// If unset, the prover must sample randomness from the OS.
    pub seed: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug)]
pub struct ProverConfig {
    pub block_size: usize,
    pub fri_final_poly_size: usize,
    pub query_count: usize,
    pub lde_blowup_factor: usize,
    pub commitment: CommitmentScheme,
    /// Protocol version for proof format / transcript (consensus-critical).
    pub protocol_version: u32,
    pub zk: ZkConfig,
}

impl ProverConfig {
    pub fn new(block_size: usize, fri_final_poly_size: usize) -> HcResult<Self> {
        Self::with_full_config_and_floor(
            block_size,
            fri_final_poly_size,
            80,
            2,
            SecurityFloor::default(),
        )
    }

    pub fn with_lde_blowup(
        block_size: usize,
        fri_final_poly_size: usize,
        lde_blowup_factor: usize,
    ) -> HcResult<Self> {
        Self::with_full_config_and_floor(
            block_size,
            fri_final_poly_size,
            80,
            lde_blowup_factor,
            SecurityFloor::default(),
        )
    }

    pub fn with_query_count(
        block_size: usize,
        fri_final_poly_size: usize,
        query_count: usize,
    ) -> HcResult<Self> {
        Self::with_full_config_and_floor(
            block_size,
            fri_final_poly_size,
            query_count,
            2,
            SecurityFloor::default(),
        )
    }

    pub fn with_full_config(
        block_size: usize,
        fri_final_poly_size: usize,
        query_count: usize,
        lde_blowup_factor: usize,
    ) -> HcResult<Self> {
        Self::with_full_config_and_floor(
            block_size,
            fri_final_poly_size,
            query_count,
            lde_blowup_factor,
            SecurityFloor::default(),
        )
    }

    pub fn with_full_config_and_floor(
        block_size: usize,
        fri_final_poly_size: usize,
        query_count: usize,
        lde_blowup_factor: usize,
        floor: SecurityFloor,
    ) -> HcResult<Self> {
        if block_size == 0 || fri_final_poly_size == 0 || query_count == 0 || lde_blowup_factor == 0
        {
            return Err(HcError::invalid_argument("config values must be positive"));
        }
        if block_size > 1 && !block_size.is_power_of_two() {
            return Err(HcError::invalid_argument(
                "block_size must be a power of two",
            ));
        }
        if block_size > floor.max_block_size {
            return Err(HcError::invalid_argument(format!(
                "block_size {} exceeds maximum {}",
                block_size, floor.max_block_size
            )));
        }
        if query_count < floor.min_query_count {
            return Err(HcError::invalid_argument(format!(
                "query_count {} is below minimum {} for security",
                query_count, floor.min_query_count
            )));
        }
        if query_count > floor.max_query_count {
            return Err(HcError::invalid_argument(format!(
                "query_count {} exceeds maximum {}",
                query_count, floor.max_query_count
            )));
        }
        if lde_blowup_factor < floor.min_lde_blowup_factor {
            return Err(HcError::invalid_argument(format!(
                "lde_blowup_factor {} is below minimum {}",
                lde_blowup_factor, floor.min_lde_blowup_factor
            )));
        }
        if lde_blowup_factor > floor.max_lde_blowup_factor {
            return Err(HcError::invalid_argument(format!(
                "lde_blowup_factor {} exceeds maximum {}",
                lde_blowup_factor, floor.max_lde_blowup_factor
            )));
        }
        Ok(Self {
            block_size,
            fri_final_poly_size,
            query_count,
            lde_blowup_factor,
            commitment: CommitmentScheme::Stark,
            protocol_version: 3,
            zk: ZkConfig::default(),
        })
    }

    /// Override the security floor (tests use `SecurityFloor::relaxed()`).
    pub fn with_security_floor(
        block_size: usize,
        fri_final_poly_size: usize,
        query_count: usize,
        lde_blowup_factor: usize,
        floor: SecurityFloor,
    ) -> HcResult<Self> {
        Self::with_full_config_and_floor(
            block_size,
            fri_final_poly_size,
            query_count,
            lde_blowup_factor,
            floor,
        )
    }

    pub fn with_commitment(mut self, scheme: CommitmentScheme) -> Self {
        self.commitment = scheme;
        // KZG mode is kept experimental and currently pinned to the legacy v2 transcript/proof.
        if matches!(self.commitment, CommitmentScheme::Kzg) {
            self.protocol_version = 2;
        }
        self
    }

    pub fn with_protocol_version(mut self, version: u32) -> Self {
        self.protocol_version = version;
        self
    }

    /// Enable ZK masking for the native STARK (protocol v4).
    pub fn with_zk_masking(mut self, mask_degree: usize) -> Self {
        if mask_degree == 0 {
            self.zk = ZkConfig::default();
            return self;
        }
        self.zk = ZkConfig {
            enabled: true,
            mask_degree,
            seed: None,
        };
        // ZK masking is defined for the native Stark path only.
        if matches!(self.commitment, CommitmentScheme::Stark) {
            self.protocol_version = 4;
        }
        self
    }

    pub fn with_zk_seed(mut self, seed: [u8; 32]) -> Self {
        self.zk.seed = Some(seed);
        self
    }
}
