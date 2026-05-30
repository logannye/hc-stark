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
    /// Minimum required grinding bits (proof-of-work). Default: 20.
    pub min_grinding_bits: u32,
}

impl Default for SecurityFloor {
    fn default() -> Self {
        Self {
            min_query_count: 80,
            min_lde_blowup_factor: 2,
            max_block_size: 1 << 20,
            max_query_count: 200,
            max_lde_blowup_factor: 16,
            min_grinding_bits: 20,
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
            min_grinding_bits: 0,
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
    /// Number of proof-of-work grinding bits required.
    ///
    /// The prover will search for a nonce whose transcript-derived digest has
    /// at least this many leading zero bits, then include the nonce in the
    /// proof. The verifier re-checks this condition. Default: 20.
    pub grinding_bits: u32,
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
        // Default grinding_bits = 20; check against floor (skip when floor = 0, i.e. relaxed).
        let grinding_bits: u32 = 20;
        if floor.min_grinding_bits > 0 && grinding_bits < floor.min_grinding_bits {
            return Err(HcError::invalid_argument(format!(
                "grinding_bits {} is below minimum {} for security",
                grinding_bits, floor.min_grinding_bits
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
            grinding_bits,
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

    // ─── v5 (sound) production policy ────────────────────────────────────────
    //
    // The v5 verifier enforces a hard security floor (`hc_verifier::v5::
    // VerifierSecurityFloor::default`): blowup ≥ 8, query_count ≥ 40,
    // grinding_bits ≥ 20, protocol version ≥ 5. A v5 prove config that asks for
    // less than the floor produces a proof the verifier (and therefore the live
    // /verify endpoint) will reject. These helpers keep the production prove
    // path self-consistent: the proof a server produces always re-verifies under
    // the default floor.

    /// Minimum LDE blowup the v5 production floor accepts.
    pub const V5_MIN_BLOWUP: usize = 8;
    /// Minimum FRI query count the v5 production floor accepts.
    pub const V5_MIN_QUERY_COUNT: usize = 40;
    /// Grinding bits the v5 production floor requires.
    pub const V5_GRINDING_BITS: u32 = 20;

    /// Clamp this config UP to the v5 production security floor: blowup ≥ 8,
    /// query_count ≥ 40, grinding_bits = 20. Values already at/above the floor
    /// are preserved (a tier may legitimately ask for more security). Never
    /// clamps DOWN.
    ///
    /// Also raises `fri_final_poly_size` so the v5 final-layer degree check is
    /// well-formed: the committed final-coeffs count is
    /// `fri_final_poly_size / blowup`, which must be ≥ 1, so
    /// `fri_final_poly_size ≥ blowup`. With blowup clamped to 8 a requested
    /// `fri_final_poly_size` of 2 would otherwise yield `2 / 8 = 0` coeffs and
    /// the verifier's `final-layer degree check` would fail. The value is
    /// rounded up to a power of two (required by `FriConfig`). NOTE: the v5
    /// prover also requires the padded trace length to be ≥ `fri_final_poly_size`
    /// — i.e. the production v5 floor is only satisfiable for programs whose
    /// padded trace length is ≥ `blowup` (≥ 8). Smaller programs cannot be
    /// proven soundly at this floor.
    ///
    /// Leaves `block_size`, ZK config, and protocol version untouched — call
    /// this on a config whose protocol version is already 5 (or 6 for ZK).
    pub fn clamped_to_v5_floor(mut self) -> Self {
        self.lde_blowup_factor = self.lde_blowup_factor.max(Self::V5_MIN_BLOWUP);
        self.query_count = self.query_count.max(Self::V5_MIN_QUERY_COUNT);
        self.grinding_bits = self.grinding_bits.max(Self::V5_GRINDING_BITS);
        // fri_final_poly_size must be ≥ blowup (so final_coeffs.len ≥ 1) and a
        // power of two (FriConfig). Round max(requested, blowup) up to a pow2.
        let min_final = self.fri_final_poly_size.max(self.lde_blowup_factor).max(1);
        self.fri_final_poly_size = min_final.next_power_of_two();
        self
    }

    /// Build a production v5 prove config from request-derived parameters,
    /// clamping every security knob UP to the v5 verifier floor and pinning the
    /// protocol version to 5 (or 6 when ZK masking is enabled).
    ///
    /// `block_size` and `fri_final_poly_size` come from the request/tier;
    /// `query_count` and `lde_blowup_factor` are treated as lower bounds (the
    /// floor wins if a tier asked for less). Uses [`SecurityFloor::relaxed`] for
    /// the *constructor* validation because the clamp below already enforces the
    /// real v5 floor — this avoids a double rejection when a tier requests
    /// below-floor params that we are about to clamp up anyway.
    pub fn production_v5(
        block_size: usize,
        fri_final_poly_size: usize,
        query_count: usize,
        lde_blowup_factor: usize,
        zk_mask_degree: Option<usize>,
    ) -> HcResult<Self> {
        let mut config = Self::with_security_floor(
            block_size,
            fri_final_poly_size,
            query_count.max(Self::V5_MIN_QUERY_COUNT),
            lde_blowup_factor.max(Self::V5_MIN_BLOWUP),
            SecurityFloor::relaxed(),
        )?;
        // Apply ZK masking BEFORE pinning the protocol version: `with_zk_masking`
        // forces protocol_version = 4, so the version pin must come last.
        if let Some(degree) = zk_mask_degree {
            if degree > 0 {
                config = config.with_zk_masking(degree);
            }
        }
        // v6 when ZK, else v5 — matches `prove_stark_v5`'s own version selection.
        let version = if config.zk.enabled { 6 } else { 5 };
        config = config.with_protocol_version(version);
        Ok(config.clamped_to_v5_floor())
    }
}
