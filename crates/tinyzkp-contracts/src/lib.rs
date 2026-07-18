//! Stable public JSON contracts shared by the MIT TinyZKP engine and Guard.
//!
//! This crate intentionally contains no prover, commerce client, or network
//! client. It is the sole authority for the local CLI/file boundary and the
//! JSON Schemas published with exact releases.

#![forbid(unsafe_code)]

use schemars::{schema_for, JsonSchema};
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

pub const COMPATIBILITY_PROFILE: &str = "tinyzkp-p3-goldilocks-v1";
pub const PLONKY3_VERSION: &str = "0.6.1";
pub const FIELD: &str = "goldilocks";
pub const EXTENSION_DEGREE: u8 = 2;
pub const PERMUTATION: &str = "poseidon2_width_8";
pub const VERIFIER: &str = "p3_uni_stark_0.6.1";
pub const MIN_ROWS: u64 = 1 << 10;
pub const MAX_ROWS: u64 = 1 << 24;
pub const MAX_TRACE_WIDTH: u32 = 256;
pub const MAX_CONSTRAINT_DEGREE: u8 = 3;
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub const MAX_AIR_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_TRACE_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_PUBLIC_INPUT_BYTES: u64 = 1024 * 1024;
pub const MAX_TRACE_COMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub const PUBLIC_SCHEMA_NAMES: &[&str] = &[
    "job-manifest-v1.schema.json",
    "doctor-report-v1.schema.json",
    "compatibility-report-v1.schema.json",
    "reason-v1.schema.json",
    "error-envelope-v1.schema.json",
    "progress-event-v1.schema.json",
    "job-result-v1.schema.json",
    "support-report-v1.schema.json",
    "job-inspect-result-v1.schema.json",
    "guard-channel-v1.schema.json",
    "guard-release-index-v1.schema.json",
    "policy-baseline-v1.schema.json",
];

pub const COMPATIBILITY_MANIFEST_SCHEMA_NAME: &str = "compatibility-manifest-v1.schema.json";

/// All schema artifacts shipped and signed with a release: the twelve frozen
/// API contracts plus the standalone compatibility profile used by Guard.
pub const PUBLISHED_SCHEMA_NAMES: &[&str] = &[
    "job-manifest-v1.schema.json",
    "doctor-report-v1.schema.json",
    "compatibility-report-v1.schema.json",
    "reason-v1.schema.json",
    "error-envelope-v1.schema.json",
    "progress-event-v1.schema.json",
    "job-result-v1.schema.json",
    "support-report-v1.schema.json",
    "job-inspect-result-v1.schema.json",
    "guard-channel-v1.schema.json",
    "guard-release-index-v1.schema.json",
    "policy-baseline-v1.schema.json",
    COMPATIBILITY_MANIFEST_SCHEMA_NAME,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestedModeV1 {
    Auto,
    Conventional,
    Bounded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelectedModeV1 {
    Conventional,
    Bounded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobRootsV1 {
    pub input_root: PathBuf,
    pub job_root: PathBuf,
    pub output_root: PathBuf,
    pub scratch_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AirFeaturesV1 {
    pub uses_lookups: bool,
    pub uses_buses: bool,
    pub uses_permutations: bool,
    pub uses_multi_table: bool,
    pub uses_preprocessed_columns: bool,
    pub uses_periodic_columns: bool,
    pub uses_recursion: bool,
    pub uses_gpu: bool,
}

impl AirFeaturesV1 {
    pub fn has_unsupported_enabled(&self) -> bool {
        self.uses_lookups
            || self.uses_buses
            || self.uses_permutations
            || self.uses_multi_table
            || self.uses_preprocessed_columns
            || self.uses_periodic_columns
            || self.uses_recursion
            || self.uses_gpu
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadInputV1 {
    pub air_package: PathBuf,
    pub trace_manifest: PathBuf,
    pub chunks_dir: PathBuf,
    pub public_inputs: PathBuf,
    pub logical_rows: u64,
    pub trace_width: u32,
    pub max_constraint_degree: u8,
    pub field: String,
    pub extension_degree: u8,
    pub permutation: String,
    pub verifier: String,
    pub features: AirFeaturesV1,
}

/// Field-compatible with the original Guard `JobManifestV1`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobManifestV1 {
    pub schema_version: u32,
    pub compatibility_profile: String,
    pub workload: WorkloadInputV1,
    pub mode: RequestedModeV1,
    pub ram_budget_bytes: u64,
    pub scratch_budget_bytes: u64,
    pub max_threads: u16,
    pub roots: JobRootsV1,
    pub job_dir: PathBuf,
    pub output_dir: PathBuf,
    pub scratch_dir: PathBuf,
}

impl JobManifestV1 {
    /// Validate declarations only. This does not read any workload file.
    pub fn compatibility_reasons(&self) -> Vec<ReasonV1> {
        let mut reasons = Vec::new();
        if self.schema_version != 1 || !(1..=256).contains(&self.max_threads) {
            push_unique(
                &mut reasons,
                ReasonV1::new(ReasonCodeV1::ManifestContractInvalid),
            );
        }
        if self.compatibility_profile != COMPATIBILITY_PROFILE
            || !(MIN_ROWS..=MAX_ROWS).contains(&self.workload.logical_rows)
            || !self.workload.logical_rows.is_power_of_two()
            || !(1..=MAX_TRACE_WIDTH).contains(&self.workload.trace_width)
            || !(1..=MAX_CONSTRAINT_DEGREE).contains(&self.workload.max_constraint_degree)
            || self.workload.field != FIELD
            || self.workload.extension_degree != EXTENSION_DEGREE
            || self.workload.permutation != PERMUTATION
            || self.workload.verifier != VERIFIER
        {
            push_unique(
                &mut reasons,
                ReasonV1::new(ReasonCodeV1::UnsupportedProfile).profiles(
                    Some(ProfileIdentifierV1::TinyzkpP3GoldilocksV1),
                    Some(ProfileIdentifierV1::Other),
                ),
            );
        }
        if self.workload.features.has_unsupported_enabled() {
            push_unique(
                &mut reasons,
                ReasonV1::new(ReasonCodeV1::UnsupportedAirFeature),
            );
        }
        if self.ram_budget_bytes < 16 * 1024 * 1024 {
            push_unique(
                &mut reasons,
                ReasonV1::new(ReasonCodeV1::RamBudgetInsufficient).resource(
                    16 * 1024 * 1024,
                    None,
                    Some(self.ram_budget_bytes),
                ),
            );
        }
        if self.scratch_budget_bytes == 0 {
            push_unique(
                &mut reasons,
                ReasonV1::new(ReasonCodeV1::ScratchBudgetInsufficient).resource(1, None, Some(0)),
            );
        }
        reasons
    }
}

fn push_unique(reasons: &mut Vec<ReasonV1>, reason: ReasonV1) {
    if !reasons.iter().any(|existing| existing.code == reason.code) {
        reasons.push(reason);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExitClassV1 {
    Incompatible,
    InvalidInput,
    InsufficientResources,
    ResumableInterruption,
    CorruptCheckpoint,
    VerificationFailure,
    LicenseFailure,
    InternalError,
}

impl ExitClassV1 {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Incompatible => 10,
            Self::InvalidInput => 11,
            Self::InsufficientResources => 12,
            Self::ResumableInterruption => 13,
            Self::CorruptCheckpoint => 14,
            Self::VerificationFailure => 15,
            Self::LicenseFailure => 16,
            Self::InternalError => 70,
        }
    }
}

/// The complete public reason vocabulary. New internal detail must map to one
/// of these values until a new public contract version is released.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCodeV1 {
    UnsupportedPlatform,
    UnsupportedProfile,
    UnsupportedAirFeature,
    ManifestContractInvalid,
    UnsafePath,
    InputLimitExceeded,
    RamBudgetInsufficient,
    ScratchBudgetInsufficient,
    ScratchSpaceInsufficient,
    JobStateExists,
    InterruptedResumable,
    CheckpointMissing,
    CheckpointCorrupt,
    CheckpointReleaseMismatch,
    JobNotResumable,
    VerificationRejected,
    ReleaseNotActivated,
    LicenseInactive,
    LicenseProviderUnavailable,
    EngineArtifactMismatch,
    EngineProtocolInvalid,
    ReleaseIdentityMismatch,
    InternalError,
}

impl ReasonCodeV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsupportedProfile => "unsupported_profile",
            Self::UnsupportedAirFeature => "unsupported_air_feature",
            Self::ManifestContractInvalid => "manifest_contract_invalid",
            Self::UnsafePath => "unsafe_path",
            Self::InputLimitExceeded => "input_limit_exceeded",
            Self::RamBudgetInsufficient => "ram_budget_insufficient",
            Self::ScratchBudgetInsufficient => "scratch_budget_insufficient",
            Self::ScratchSpaceInsufficient => "scratch_space_insufficient",
            Self::JobStateExists => "job_state_exists",
            Self::InterruptedResumable => "interrupted_resumable",
            Self::CheckpointMissing => "checkpoint_missing",
            Self::CheckpointCorrupt => "checkpoint_corrupt",
            Self::CheckpointReleaseMismatch => "checkpoint_release_mismatch",
            Self::JobNotResumable => "job_not_resumable",
            Self::VerificationRejected => "verification_rejected",
            Self::ReleaseNotActivated => "release_not_activated",
            Self::LicenseInactive => "license_inactive",
            Self::LicenseProviderUnavailable => "license_provider_unavailable",
            Self::EngineArtifactMismatch => "engine_artifact_mismatch",
            Self::EngineProtocolInvalid => "engine_protocol_invalid",
            Self::ReleaseIdentityMismatch => "release_identity_mismatch",
            Self::InternalError => "internal_error",
        }
    }

    pub const fn class(self) -> ExitClassV1 {
        match self {
            Self::UnsupportedPlatform | Self::UnsupportedProfile | Self::UnsupportedAirFeature => {
                ExitClassV1::Incompatible
            }
            Self::ManifestContractInvalid
            | Self::UnsafePath
            | Self::InputLimitExceeded
            | Self::JobStateExists
            | Self::JobNotResumable => ExitClassV1::InvalidInput,
            Self::RamBudgetInsufficient
            | Self::ScratchBudgetInsufficient
            | Self::ScratchSpaceInsufficient => ExitClassV1::InsufficientResources,
            Self::InterruptedResumable => ExitClassV1::ResumableInterruption,
            Self::CheckpointMissing | Self::CheckpointCorrupt | Self::CheckpointReleaseMismatch => {
                ExitClassV1::CorruptCheckpoint
            }
            Self::VerificationRejected => ExitClassV1::VerificationFailure,
            Self::ReleaseNotActivated
            | Self::LicenseInactive
            | Self::LicenseProviderUnavailable => ExitClassV1::LicenseFailure,
            Self::EngineArtifactMismatch
            | Self::EngineProtocolInvalid
            | Self::ReleaseIdentityMismatch
            | Self::InternalError => ExitClassV1::InternalError,
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "Production proving requires Linux x86-64.",
            Self::UnsupportedProfile => "The declared proof profile is unsupported.",
            Self::UnsupportedAirFeature => "The AIR uses a feature outside the v1 profile.",
            Self::ManifestContractInvalid => "The job manifest or declaration is invalid.",
            Self::UnsafePath => "A configured path is unsafe.",
            Self::InputLimitExceeded => "A local input exceeds a published limit.",
            Self::RamBudgetInsufficient => "The RAM budget is below the required capacity.",
            Self::ScratchBudgetInsufficient => {
                "The scratch budget is below the estimate plus headroom."
            }
            Self::ScratchSpaceInsufficient => {
                "Available scratch space is below the estimate plus headroom."
            }
            Self::JobStateExists => "The requested job directory already contains state.",
            Self::InterruptedResumable => "The proof was interrupted and can resume.",
            Self::CheckpointMissing => "The expected checkpoint is missing.",
            Self::CheckpointCorrupt => "The checkpoint is corrupt.",
            Self::CheckpointReleaseMismatch => "The checkpoint belongs to another exact release.",
            Self::JobNotResumable => "The job is not in a resumable state.",
            Self::VerificationRejected => "The ordinary verifier rejected the proof.",
            Self::ReleaseNotActivated => "This exact release is not activated.",
            Self::LicenseInactive => "The subscription license is inactive.",
            Self::LicenseProviderUnavailable => "The license provider is unavailable.",
            Self::EngineArtifactMismatch => "The engine artifact does not match the release.",
            Self::EngineProtocolInvalid => "The local engine protocol is invalid.",
            Self::ReleaseIdentityMismatch => "Release identities do not match.",
            Self::InternalError => "The local program encountered an internal error.",
        }
    }

    pub const fn remediation(self) -> &'static str {
        match self.class() {
            ExitClassV1::Incompatible => "use_supported_profile",
            ExitClassV1::InvalidInput => "repair_local_input",
            ExitClassV1::InsufficientResources => "increase_budget_or_capacity",
            ExitClassV1::ResumableInterruption => "resume_exact_release",
            ExitClassV1::CorruptCheckpoint => "restore_or_restart_job",
            ExitClassV1::VerificationFailure => "retain_artifacts_and_report",
            ExitClassV1::LicenseFailure => "activate_eligible_release",
            ExitClassV1::InternalError => "generate_support_report",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlatformIdentifierV1 {
    LinuxX86_64,
    LinuxOther,
    Macos,
    Windows,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfileIdentifierV1 {
    TinyzkpP3GoldilocksV1,
    Other,
}

/// No free-form diagnostic context is allowed on the public error boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReasonV1 {
    pub code: ReasonCodeV1,
    pub class: ExitClassV1,
    pub summary: String,
    pub remediation: String,
    pub docs_url: String,
    pub required_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
    pub expected_platform: Option<PlatformIdentifierV1>,
    pub detected_platform: Option<PlatformIdentifierV1>,
    pub expected_profile: Option<ProfileIdentifierV1>,
    pub detected_profile: Option<ProfileIdentifierV1>,
}

impl ReasonV1 {
    pub fn new(code: ReasonCodeV1) -> Self {
        Self {
            code,
            class: code.class(),
            summary: code.summary().to_owned(),
            remediation: code.remediation().to_owned(),
            docs_url: format!("/troubleshooting#{}", code.as_str()),
            required_bytes: None,
            available_bytes: None,
            limit_bytes: None,
            expected_platform: None,
            detected_platform: None,
            expected_profile: None,
            detected_profile: None,
        }
    }

    pub fn resource(mut self, required: u64, available: Option<u64>, limit: Option<u64>) -> Self {
        self.required_bytes = Some(required);
        self.available_bytes = available;
        self.limit_bytes = limit;
        self
    }

    pub fn platforms(
        mut self,
        expected: Option<PlatformIdentifierV1>,
        detected: Option<PlatformIdentifierV1>,
    ) -> Self {
        self.expected_platform = expected;
        self.detected_platform = detected;
        self
    }

    pub fn profiles(
        mut self,
        expected: Option<ProfileIdentifierV1>,
        detected: Option<ProfileIdentifierV1>,
    ) -> Self {
        self.expected_profile = expected;
        self.detected_profile = detected;
        self
    }

    pub fn validate(&self) -> bool {
        let canonical = Self::new(self.code);
        if self.class != canonical.class
            || self.summary != canonical.summary
            || self.remediation != canonical.remediation
            || self.docs_url != canonical.docs_url
        {
            return false;
        }
        let has_resource = self.required_bytes.is_some()
            || self.available_bytes.is_some()
            || self.limit_bytes.is_some();
        let has_platform = self.expected_platform.is_some() || self.detected_platform.is_some();
        let has_profile = self.expected_profile.is_some() || self.detected_profile.is_some();
        let resource_allowed = matches!(
            self.code,
            ReasonCodeV1::InputLimitExceeded
                | ReasonCodeV1::RamBudgetInsufficient
                | ReasonCodeV1::ScratchBudgetInsufficient
                | ReasonCodeV1::ScratchSpaceInsufficient
        );
        (!has_resource || resource_allowed)
            && (!has_platform
                || (self.code == ReasonCodeV1::UnsupportedPlatform
                    && self.expected_platform == Some(PlatformIdentifierV1::LinuxX86_64)))
            && (!has_profile
                || (self.code == ReasonCodeV1::UnsupportedProfile
                    && self.expected_profile == Some(ProfileIdentifierV1::TinyzkpP3GoldilocksV1)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasonWireV1 {
    code: ReasonCodeV1,
    class: ExitClassV1,
    summary: String,
    remediation: String,
    docs_url: String,
    required_bytes: Option<u64>,
    available_bytes: Option<u64>,
    limit_bytes: Option<u64>,
    expected_platform: Option<PlatformIdentifierV1>,
    detected_platform: Option<PlatformIdentifierV1>,
    expected_profile: Option<ProfileIdentifierV1>,
    detected_profile: Option<ProfileIdentifierV1>,
}

impl<'de> Deserialize<'de> for ReasonV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReasonWireV1::deserialize(deserializer)?;
        let reason = Self {
            code: wire.code,
            class: wire.class,
            summary: wire.summary,
            remediation: wire.remediation,
            docs_url: wire.docs_url,
            required_bytes: wire.required_bytes,
            available_bytes: wire.available_bytes,
            limit_bytes: wire.limit_bytes,
            expected_platform: wire.expected_platform,
            detected_platform: wire.detected_platform,
            expected_profile: wire.expected_profile,
            detected_profile: wire.detected_profile,
        };
        if !reason.validate() {
            return Err(serde::de::Error::custom("non-canonical ReasonV1"));
        }
        Ok(reason)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceEstimateV1 {
    pub peak_resident_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceEstimatesV1 {
    pub conventional: ResourceEstimateV1,
    pub bounded: ResourceEstimateV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourcePreflightV1 {
    pub ram_budget_bytes: u64,
    pub scratch_budget_bytes: u64,
    pub available_scratch_bytes: Option<u64>,
    pub memory_selection_threshold_bytes: u64,
    pub scratch_required_with_headroom_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorReportV1 {
    pub schema_version: u32,
    pub engine_release_identity: String,
    pub compatibility_profile: String,
    pub ready: bool,
    pub requested_mode: RequestedModeV1,
    pub selected_mode: Option<SelectedModeV1>,
    pub estimates: Option<ResourceEstimatesV1>,
    pub preflight: ResourcePreflightV1,
    pub reasons: Vec<ReasonV1>,
}

impl DoctorReportV1 {
    pub fn validate(&self, expected_release_identity: &str) -> bool {
        self.schema_version == 1
            && self.engine_release_identity == expected_release_identity
            && is_safe_release_identity(&self.engine_release_identity)
            && self.compatibility_profile == COMPATIBILITY_PROFILE
            && self.reasons.iter().all(ReasonV1::validate)
            && self.preflight.memory_selection_threshold_bytes
                == memory_selection_threshold(self.preflight.ram_budget_bytes)
            && self.ready == (self.selected_mode.is_some() && self.reasons.is_empty())
            && (!self.ready || self.estimates.is_some())
            && match self.selected_mode {
                Some(SelectedModeV1::Conventional) => self
                    .preflight
                    .scratch_required_with_headroom_bytes
                    .is_none(),
                Some(SelectedModeV1::Bounded) => self
                    .preflight
                    .scratch_required_with_headroom_bytes
                    .is_some(),
                None => true,
            }
    }

    /// Validate all doctor semantics that can be recomputed from the original
    /// job contract, including exact auto selection and resource preflight.
    pub fn validate_for_manifest(
        &self,
        expected_release_identity: &str,
        manifest: &JobManifestV1,
    ) -> bool {
        if !self.validate(expected_release_identity)
            || self.requested_mode != manifest.mode
            || self.preflight.ram_budget_bytes != manifest.ram_budget_bytes
            || self.preflight.scratch_budget_bytes != manifest.scratch_budget_bytes
        {
            return false;
        }
        let Some(estimates) = &self.estimates else {
            return !self.ready
                && self.selected_mode.is_none()
                && !self.reasons.is_empty()
                && self
                    .reasons
                    .iter()
                    .all(|reason| reason.class == ExitClassV1::Incompatible)
                && self
                    .preflight
                    .scratch_required_with_headroom_bytes
                    .is_none();
        };
        let declaration_resource_reasons: Vec<_> = manifest
            .compatibility_reasons()
            .into_iter()
            .filter(|reason| reason.class == ExitClassV1::InsufficientResources)
            .collect();
        if !declaration_resource_reasons.is_empty() {
            return !self.ready
                && self.selected_mode.is_none()
                && self.reasons == declaration_resource_reasons
                && self.preflight
                    == declaration_failure_preflight(
                        manifest,
                        self.preflight.available_scratch_bytes,
                    );
        }
        match select_and_preflight(manifest, estimates, self.preflight.available_scratch_bytes) {
            Ok((selected_mode, preflight)) => {
                self.ready
                    && self.selected_mode == Some(selected_mode)
                    && self.preflight == preflight
                    && self.reasons.is_empty()
            }
            Err(reason) => {
                !self.ready
                    && self.selected_mode.is_none()
                    && self.reasons.as_slice() == [reason.clone()]
                    && self.preflight
                        == failed_resource_preflight(
                            manifest,
                            self.preflight.available_scratch_bytes,
                            &reason,
                        )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentityV1 {
    pub guard_version: String,
    pub guard_source_identity: String,
    pub engine_source_identity: String,
    pub engine_artifact_sha256: String,
    pub release_identity: String,
    pub compatibility_profile: String,
    pub qualification: String,
}

impl ReleaseIdentityV1 {
    pub fn validate(&self) -> bool {
        is_safe_release_identity(&self.guard_version)
            && is_safe_release_identity(&self.guard_source_identity)
            && is_safe_release_identity(&self.engine_source_identity)
            && is_lower_hex_digest(&self.engine_artifact_sha256)
            && is_safe_release_identity(&self.release_identity)
            && self.compatibility_profile == COMPATIBILITY_PROFILE
            && is_safe_release_identity(&self.qualification)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformV1 {
    pub operating_system: String,
    pub architecture: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityLimitsV1 {
    pub minimum_rows: u64,
    pub maximum_rows: u64,
    pub maximum_trace_width: u32,
    pub maximum_constraint_degree: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityManifestV1 {
    pub schema_version: u32,
    pub profile: String,
    pub platform: PlatformV1,
    pub plonky3_version: String,
    pub field: String,
    pub extension_degree: u8,
    pub permutation: String,
    pub verifier: String,
    pub declarative_operators: Vec<String>,
    pub limits: CompatibilityLimitsV1,
    pub explicitly_unsupported: Vec<String>,
    pub release: ReleaseIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityReportV1 {
    pub schema_version: u32,
    pub compatible: bool,
    pub reasons: Vec<ReasonV1>,
    pub manifest: CompatibilityManifestV1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsageV1 {
    pub resident_bytes: Option<u64>,
    pub scratch_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgressEventV1 {
    pub schema_version: u32,
    pub engine_release_identity: String,
    pub event: String,
    pub stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_phases: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_phases: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_usage: Option<ResourceUsageV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_durable: Option<bool>,
}

impl ProgressEventV1 {
    pub fn simple(engine_release_identity: &str, event: &str, stage: &str) -> Self {
        Self {
            schema_version: 1,
            engine_release_identity: engine_release_identity.to_owned(),
            event: event.to_owned(),
            stage: stage.to_owned(),
            phase: None,
            completed_phases: None,
            total_phases: None,
            progress: None,
            resource_usage: None,
            checkpoint_durable: None,
        }
    }

    fn validate_shape(&self) -> bool {
        const EVENTS: &[&str] = &[
            "doctor_started",
            "doctor_paths_validated",
            "doctor_inputs_validated",
            "doctor_estimating",
            "doctor_completed",
            "resource_estimate",
            "phase",
            "run_started",
            "run_proving",
            "run_verifying",
            "run_interrupted",
            "run_completed",
            "resume_started",
            "resume_proving",
            "resume_verifying",
            "resume_interrupted",
            "resume_completed",
            "verify_started",
            "verify_completed",
            "diagnostics_started",
            "diagnostics_completed",
            "policy_started",
            "policy_completed",
        ];
        const STAGES: &[&str] = &[
            "validation",
            "resource_estimate",
            "orchestration",
            "proving",
            "verification",
            "diagnostics",
            "policy",
            "complete",
        ];
        let phase_allowed = self.phase.as_deref().is_none_or(|phase| {
            matches!(
                phase,
                "trace"
                    | "trace_lde"
                    | "trace_commitment"
                    | "quotient"
                    | "quotient_lde"
                    | "quotient_commitment"
                    | "openings"
                    | "proof_assembly"
            ) || phase.strip_prefix("fri_layer_").is_some_and(|layer| {
                !layer.is_empty() && layer.bytes().all(|byte| byte.is_ascii_digit())
            })
        });
        let event_stage_allowed = matches!(
            (self.event.as_str(), self.stage.as_str()),
            (
                "doctor_started" | "doctor_paths_validated" | "doctor_inputs_validated",
                "validation"
            ) | (
                "doctor_estimating" | "resource_estimate",
                "resource_estimate"
            ) | ("run_started" | "resume_started", "orchestration")
                | ("phase" | "run_proving" | "resume_proving", "proving")
                | (
                    "run_verifying" | "resume_verifying" | "verify_started",
                    "verification"
                )
                | ("diagnostics_started", "diagnostics")
                | ("policy_started", "policy")
                | (
                    "doctor_completed"
                        | "run_interrupted"
                        | "run_completed"
                        | "resume_interrupted"
                        | "resume_completed"
                        | "verify_completed"
                        | "diagnostics_completed"
                        | "policy_completed",
                    "complete"
                )
        );
        is_safe_release_identity(&self.engine_release_identity)
            && EVENTS.contains(&self.event.as_str())
            && STAGES.contains(&self.stage.as_str())
            && event_stage_allowed
            && phase_allowed
            && self
                .progress
                .is_none_or(|progress| progress.is_finite() && (0.0..=1.0).contains(&progress))
            && match (self.completed_phases, self.total_phases) {
                (Some(completed), Some(total)) => total > 0 && completed <= total,
                (None, None) => true,
                _ => false,
            }
    }

    pub fn validate(&self, expected_release_identity: &str) -> bool {
        self.engine_release_identity == expected_release_identity && self.validate_shape()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressEventWireV1 {
    schema_version: u32,
    engine_release_identity: String,
    event: String,
    stage: String,
    phase: Option<String>,
    completed_phases: Option<u32>,
    total_phases: Option<u32>,
    progress: Option<f64>,
    resource_usage: Option<ResourceUsageV1>,
    checkpoint_durable: Option<bool>,
}

impl<'de> Deserialize<'de> for ProgressEventV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProgressEventWireV1::deserialize(deserializer)?;
        let event = Self {
            schema_version: wire.schema_version,
            engine_release_identity: wire.engine_release_identity,
            event: wire.event,
            stage: wire.stage,
            phase: wire.phase,
            completed_phases: wire.completed_phases,
            total_phases: wire.total_phases,
            progress: wire.progress,
            resource_usage: wire.resource_usage,
            checkpoint_durable: wire.checkpoint_durable,
        };
        if event.schema_version != 1 || !event.validate_shape() {
            return Err(serde::de::Error::custom("invalid ProgressEventV1"));
        }
        Ok(event)
    }
}

pub type EngineProgressEventV1 = ProgressEventV1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetailV1 {
    pub class: ExitClassV1,
    pub exit_code: u8,
    pub reason: ReasonV1,
    pub resumable: bool,
    pub checkpoint_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelopeV1 {
    pub schema_version: u32,
    pub engine_release_identity: String,
    pub ok: bool,
    pub error: ErrorDetailV1,
}

impl ErrorEnvelopeV1 {
    pub fn new(
        engine_release_identity: impl Into<String>,
        reason: ReasonV1,
        resumable: bool,
        checkpoint_present: bool,
    ) -> Self {
        let class = reason.class;
        Self {
            schema_version: 1,
            engine_release_identity: engine_release_identity.into(),
            ok: false,
            error: ErrorDetailV1 {
                class,
                exit_code: class.exit_code(),
                reason,
                resumable,
                checkpoint_present,
            },
        }
    }

    pub fn validate(&self, expected_release_identity: &str) -> bool {
        self.schema_version == 1
            && !self.ok
            && self.engine_release_identity == expected_release_identity
            && is_safe_release_identity(&self.engine_release_identity)
            && self.error.reason.validate()
            && self.error.class == self.error.reason.class
            && self.error.exit_code == self.error.class.exit_code()
            && (!self.error.resumable || self.error.checkpoint_present)
    }
}

pub type EngineErrorEnvelopeV1 = ErrorEnvelopeV1;
pub type EngineErrorDetailV1 = ErrorDetailV1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineEstimateResultV1 {
    pub schema_version: u32,
    pub engine_release_identity: String,
    pub selected_mode: SelectedModeV1,
    pub estimates: ResourceEstimatesV1,
    pub preflight: ResourcePreflightV1,
}

impl EngineEstimateResultV1 {
    pub fn validate(&self, expected_release_identity: &str) -> bool {
        self.schema_version == 1
            && self.engine_release_identity == expected_release_identity
            && is_safe_release_identity(&self.engine_release_identity)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineOperationReportV1 {
    pub schema_version: u32,
    pub engine_release_identity: String,
    pub selected_mode: SelectedModeV1,
    pub peak_resident_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub wall_time_millis: u64,
}

impl EngineOperationReportV1 {
    pub fn validate(&self, expected_release_identity: &str) -> bool {
        self.schema_version == 1
            && self.engine_release_identity == expected_release_identity
            && is_safe_release_identity(&self.engine_release_identity)
            && self.wall_time_millis > 0
    }
}

/// Internal engine-to-Guard wire result for read-only checkpoint inspection.
///
/// This type is intentionally not one of the frozen public schema artifacts.
/// It carries only the minimum non-sensitive facts Guard needs before deciding
/// whether to offer a resume operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineCheckpointInspectResultV1 {
    pub schema_version: u32,
    pub engine_release_identity: String,
    pub compatibility_profile: String,
    pub valid: bool,
    pub checkpoint_release_identity_match: bool,
    pub selected_mode: SelectedModeV1,
}

impl EngineCheckpointInspectResultV1 {
    pub fn validate(&self, expected_release_identity: &str) -> bool {
        self.schema_version == 1
            && self.engine_release_identity == expected_release_identity
            && is_safe_release_identity(&self.engine_release_identity)
            && self.compatibility_profile == COMPATIBILITY_PROFILE
            && self.valid
            && self.checkpoint_release_identity_match
            && self.selected_mode == SelectedModeV1::Bounded
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineVerifyResultV1 {
    pub schema_version: u32,
    pub engine_release_identity: String,
    pub accepted: bool,
}

impl EngineVerifyResultV1 {
    pub fn validate(&self, expected_release_identity: &str) -> bool {
        self.schema_version == 1
            && self.engine_release_identity == expected_release_identity
            && is_safe_release_identity(&self.engine_release_identity)
            && self.accepted
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedResourcesV1 {
    pub peak_resident_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub wall_time_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobStatusV1 {
    Succeeded,
    Interrupted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReferenceV1 {
    pub relative_path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerifierOutcomeV1 {
    Accepted,
    Rejected,
    NotRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobResultV1 {
    pub schema_version: u32,
    pub status: JobStatusV1,
    pub requested_mode: RequestedModeV1,
    pub selected_mode: SelectedModeV1,
    pub estimates: ResourceEstimatesV1,
    pub observed_resources: Option<ObservedResourcesV1>,
    pub release: ReleaseIdentityV1,
    pub proof: Option<ArtifactReferenceV1>,
    pub verifier_outcome: VerifierOutcomeV1,
    pub reason: Option<ReasonV1>,
    pub resumable: bool,
    pub checkpoint_relative_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobInspectStatusV1 {
    Running,
    Interrupted,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobInspectResultV1 {
    pub schema_version: u32,
    pub status: JobInspectStatusV1,
    pub requested_mode: RequestedModeV1,
    pub selected_mode: SelectedModeV1,
    pub required_release_identity: String,
    pub attempt_count: u32,
    pub exact_release_match: bool,
    pub manifest_integrity: bool,
    pub checkpoint_present: bool,
    pub checkpoint_integrity: Option<bool>,
    pub result_present: bool,
    pub resumable: bool,
}

pub type JobInspectionV1 = JobInspectResultV1;
pub type JobInspectionStatusV1 = JobInspectStatusV1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportSafeObservationsV1 {
    pub peak_resident_bytes: Option<u64>,
    pub scratch_high_water_bytes: Option<u64>,
    pub wall_time_millis: Option<u64>,
    pub attempt_count: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVerificationV1 {
    Verified,
    Failed,
    NotChecked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoarseActivationStatusV1 {
    ActivatedForExactRelease,
    NotActivatedForExactRelease,
    NotChecked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportRedactionPolicyV1 {
    NoPathsNoContentNoDigestsNoIdentifiersV1,
}

/// Path-free and content-free diagnostic record safe to attach to an issue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportReportV1 {
    pub schema_version: u32,
    pub release: ReleaseIdentityV1,
    pub platform: PlatformV1,
    pub compatibility_profile: ProfileIdentifierV1,
    pub reasons: Vec<ReasonV1>,
    pub requested_mode: Option<RequestedModeV1>,
    pub selected_mode: Option<SelectedModeV1>,
    pub estimates: Option<ResourceEstimatesV1>,
    pub observations: SupportSafeObservationsV1,
    pub resumable: bool,
    pub checkpoint_release_match: Option<bool>,
    pub verifier_outcome: Option<VerifierOutcomeV1>,
    pub artifact_verification: ArtifactVerificationV1,
    pub activation: CoarseActivationStatusV1,
    pub redaction_policy: SupportRedactionPolicyV1,
}

impl SupportReportV1 {
    pub fn validate(&self) -> bool {
        self.schema_version == 1
            && self.release.validate()
            && platform_is_allowlisted(&self.platform)
            && self.compatibility_profile == ProfileIdentifierV1::TinyzkpP3GoldilocksV1
            && self.reasons.iter().all(ReasonV1::validate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptorV1 {
    pub name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Exact Lemon Squeezy catalog identifiers bound into a qualified release.
/// Runtime entitlement transport remains behind Guard's provider adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MerchantCatalogIdentityV1 {
    pub merchant: String,
    pub entitlement_mode: String,
    pub store_id: String,
    pub product_id: String,
    pub monthly_variant_id: String,
    pub annual_variant_id: String,
}

impl MerchantCatalogIdentityV1 {
    pub fn validate(&self) -> bool {
        self.merchant == "lemon_squeezy"
            && self.entitlement_mode == "lemon_squeezy_subscription_license_keys"
            && is_decimal_identifier(&self.store_id)
            && is_decimal_identifier(&self.product_id)
            && is_decimal_identifier(&self.monthly_variant_id)
            && is_decimal_identifier(&self.annual_variant_id)
            && self.monthly_variant_id != self.annual_variant_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardChannelV1 {
    pub schema_version: u32,
    pub guard_version: String,
    pub release_identity: String,
    pub guard_source_sha: String,
    pub engine_source_sha: String,
    pub engine_artifact_sha256: String,
    pub artifacts: Vec<ArtifactDescriptorV1>,
    pub oci_digest: String,
    pub schemas: BTreeMap<String, String>,
    pub eula_sha256: String,
    pub release_date: String,
    pub compatibility_profile: String,
    pub merchant_catalog: MerchantCatalogIdentityV1,
    pub qualification: String,
}

impl GuardChannelV1 {
    pub fn validate(&self) -> bool {
        self.schema_version == 1
            && is_safe_release_identity(&self.guard_version)
            && is_safe_release_identity(&self.release_identity)
            && is_git_sha(&self.guard_source_sha)
            && is_git_sha(&self.engine_source_sha)
            && is_lower_hex_digest(&self.engine_artifact_sha256)
            && !self.artifacts.is_empty()
            && self.artifacts.iter().all(|artifact| {
                safe_artifact_name(&artifact.name)
                    && is_lower_hex_digest(&artifact.sha256)
                    && artifact.size_bytes > 0
            })
            && all_unique(self.artifacts.iter().map(|artifact| artifact.name.as_str()))
            && self
                .oci_digest
                .strip_prefix("sha256:")
                .is_some_and(is_lower_hex_digest)
            && self.schemas.len() == PUBLISHED_SCHEMA_NAMES.len()
            && PUBLISHED_SCHEMA_NAMES.iter().all(|name| {
                self.schemas
                    .get(*name)
                    .is_some_and(|digest| is_lower_hex_digest(digest))
            })
            && is_lower_hex_digest(&self.eula_sha256)
            && is_iso_date(&self.release_date)
            && self.compatibility_profile == COMPATIBILITY_PROFILE
            && self.merchant_catalog.validate()
            && is_safe_release_identity(&self.qualification)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardReleaseIndexV1 {
    pub schema_version: u32,
    pub product: String,
    pub current_release_identity: String,
    pub releases: Vec<GuardReleaseIndexEntryV1>,
}

impl GuardReleaseIndexV1 {
    pub fn validate(&self) -> bool {
        self.schema_version == 1
            && self.product == "tinyzkp-guard"
            && is_safe_release_identity(&self.current_release_identity)
            && self
                .releases
                .iter()
                .filter(|release| release.state == GuardReleaseStateV1::Current)
                .count()
                == 1
            && self.releases.iter().all(GuardReleaseIndexEntryV1::validate)
            && self.releases.iter().any(|release| {
                release.state == GuardReleaseStateV1::Current
                    && release.release_identity == self.current_release_identity
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardReleaseIndexEntryV1 {
    pub guard_version: String,
    pub release_identity: String,
    pub compatibility_profile: String,
    pub release_date: String,
    pub channel_url: String,
    pub channel_sha256: String,
    pub artifacts: Vec<ImmutableReleaseArtifactV1>,
    pub state: GuardReleaseStateV1,
    pub successor_release_identity: Option<String>,
    pub advisory_url: Option<String>,
}

impl GuardReleaseIndexEntryV1 {
    pub fn validate(&self) -> bool {
        is_safe_release_identity(&self.guard_version)
            && is_safe_release_identity(&self.release_identity)
            && self.compatibility_profile == COMPATIBILITY_PROFILE
            && is_https_url(&self.channel_url)
            && is_lower_hex_digest(&self.channel_sha256)
            && !self.artifacts.is_empty()
            && self.artifacts.iter().all(|artifact| {
                safe_artifact_name(&artifact.name)
                    && is_https_url(&artifact.url)
                    && is_lower_hex_digest(&artifact.sha256)
            })
            && self
                .successor_release_identity
                .as_deref()
                .is_none_or(is_safe_release_identity)
            && self.advisory_url.as_deref().is_none_or(is_https_url)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImmutableReleaseArtifactV1 {
    pub name: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuardReleaseStateV1 {
    Current,
    Superseded,
    Withdrawn,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBaselineV1 {
    pub schema_version: u32,
    pub maximum_peak_resident_bytes: u64,
    pub maximum_scratch_high_water_bytes: u64,
    pub maximum_wall_time_millis: Option<u64>,
    pub allowed_modes: Vec<SelectedModeV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckResultV1 {
    pub schema_version: u32,
    pub passed: bool,
    pub reasons: Vec<ReasonV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LicenseStatusV1 {
    pub schema_version: u32,
    pub status: String,
    pub release_identity: String,
    pub provider: Option<String>,
    pub organization: Option<String>,
    pub activated_at_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationResultV1 {
    pub schema_version: u32,
    pub activated: bool,
    pub release_identity: String,
    pub provider: String,
    pub organization: String,
}

/// Immutable build class carried by the Guard binary itself.
///
/// Promotion, sales, support, supersession, and withdrawal are deliberately
/// absent: those states can change without rebuilding and belong to the
/// signed release channel and launch evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuardArtifactClassV1 {
    Development,
    SignedCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionResultV1 {
    pub schema_version: u32,
    pub product: String,
    pub release: ReleaseIdentityV1,
    pub compatibility_profile: String,
    /// Compile-time merchant identity used by this exact Guard binary.
    ///
    /// Release automation compares this value byte-for-byte with the signed
    /// Guard channel and reviewed commerce evidence. It is intentionally
    /// public metadata, not a credential.
    pub merchant_catalog: MerchantCatalogIdentityV1,
    pub artifact_class: GuardArtifactClassV1,
}

/// Auto mode chooses the conventional path only at or below this exact 70%
/// boundary.
pub fn memory_selection_threshold(ram_budget_bytes: u64) -> u64 {
    let quotient = ram_budget_bytes / 10;
    let remainder = ram_budget_bytes % 10;
    quotient * 7 + remainder * 7 / 10
}

pub fn is_safe_release_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'+' | b'/')
        })
        && !value.starts_with('/')
        && !value.contains("..")
        && !value.contains("//")
}

pub fn is_lower_hex_digest(value: &str) -> bool {
    is_lower_hex_with_length(value, 64)
}

fn is_git_sha(value: &str) -> bool {
    is_lower_hex_with_length(value, 40)
}

fn is_lower_hex_with_length(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_decimal_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let month = (bytes[5] - b'0') * 10 + bytes[6] - b'0';
    let day = (bytes[8] - b'0') * 10 + bytes[9] - b'0';
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn all_unique<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.all(|value| seen.insert(value))
}

fn is_https_url(value: &str) -> bool {
    value.len() <= 2048
        && value.starts_with("https://")
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        && !value[8..].contains('@')
}

fn safe_artifact_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value != "."
        && value != ".."
}

fn platform_is_allowlisted(platform: &PlatformV1) -> bool {
    matches!(
        platform.operating_system.as_str(),
        "linux" | "macos" | "windows" | "other"
    ) && matches!(
        platform.architecture.as_str(),
        "x86_64" | "aarch64" | "other"
    )
}

/// Capacity for which `required` uses no more than 90%, rounded upward.
pub fn required_scratch_capacity_with_headroom(required: u64) -> Option<u64> {
    let extra = required / 9 + u64::from(!required.is_multiple_of(9));
    required.checked_add(extra)
}

#[allow(
    clippy::result_large_err,
    reason = "the public preflight API returns the complete typed wire reason without allocation indirection"
)]
pub fn select_and_preflight(
    manifest: &JobManifestV1,
    estimates: &ResourceEstimatesV1,
    available_scratch_bytes: Option<u64>,
) -> Result<(SelectedModeV1, ResourcePreflightV1), ReasonV1> {
    let threshold = memory_selection_threshold(manifest.ram_budget_bytes);
    let selected = match manifest.mode {
        RequestedModeV1::Conventional => SelectedModeV1::Conventional,
        RequestedModeV1::Bounded => SelectedModeV1::Bounded,
        RequestedModeV1::Auto if estimates.conventional.peak_resident_bytes <= threshold => {
            SelectedModeV1::Conventional
        }
        RequestedModeV1::Auto => SelectedModeV1::Bounded,
    };
    let estimate = match selected {
        SelectedModeV1::Conventional => &estimates.conventional,
        SelectedModeV1::Bounded => &estimates.bounded,
    };
    if estimate.peak_resident_bytes > manifest.ram_budget_bytes {
        return Err(ReasonV1::new(ReasonCodeV1::RamBudgetInsufficient).resource(
            estimate.peak_resident_bytes,
            None,
            Some(manifest.ram_budget_bytes),
        ));
    }
    let scratch_required_with_headroom_bytes = if selected == SelectedModeV1::Bounded {
        let needed = required_scratch_capacity_with_headroom(estimate.scratch_high_water_bytes)
            .ok_or_else(|| ReasonV1::new(ReasonCodeV1::InternalError))?;
        if needed > manifest.scratch_budget_bytes {
            return Err(
                ReasonV1::new(ReasonCodeV1::ScratchBudgetInsufficient).resource(
                    needed,
                    available_scratch_bytes,
                    Some(manifest.scratch_budget_bytes),
                ),
            );
        }
        let available = available_scratch_bytes
            .ok_or_else(|| ReasonV1::new(ReasonCodeV1::ScratchSpaceInsufficient))?;
        if needed > available {
            return Err(
                ReasonV1::new(ReasonCodeV1::ScratchSpaceInsufficient).resource(
                    needed,
                    Some(available),
                    Some(manifest.scratch_budget_bytes),
                ),
            );
        }
        Some(needed)
    } else {
        None
    };
    Ok((
        selected,
        ResourcePreflightV1 {
            ram_budget_bytes: manifest.ram_budget_bytes,
            scratch_budget_bytes: manifest.scratch_budget_bytes,
            available_scratch_bytes,
            memory_selection_threshold_bytes: threshold,
            scratch_required_with_headroom_bytes,
        },
    ))
}

pub fn failed_resource_preflight(
    manifest: &JobManifestV1,
    available_scratch_bytes: Option<u64>,
    reason: &ReasonV1,
) -> ResourcePreflightV1 {
    let scratch_required_with_headroom_bytes = match reason.code {
        ReasonCodeV1::ScratchBudgetInsufficient | ReasonCodeV1::ScratchSpaceInsufficient => {
            reason.required_bytes
        }
        _ => None,
    };
    ResourcePreflightV1 {
        ram_budget_bytes: manifest.ram_budget_bytes,
        scratch_budget_bytes: manifest.scratch_budget_bytes,
        available_scratch_bytes,
        memory_selection_threshold_bytes: memory_selection_threshold(manifest.ram_budget_bytes),
        scratch_required_with_headroom_bytes,
    }
}

pub fn declaration_failure_preflight(
    manifest: &JobManifestV1,
    available_scratch_bytes: Option<u64>,
) -> ResourcePreflightV1 {
    ResourcePreflightV1 {
        ram_budget_bytes: manifest.ram_budget_bytes,
        scratch_budget_bytes: manifest.scratch_budget_bytes,
        available_scratch_bytes,
        memory_selection_threshold_bytes: memory_selection_threshold(manifest.ram_budget_bytes),
        scratch_required_with_headroom_bytes: None,
    }
}

pub fn public_schema<T: JsonSchema>(name: &str) -> Value {
    let mut schema = serde_json::to_value(schema_for!(T)).expect("schema must serialize");
    let object = schema
        .as_object_mut()
        .expect("generated schema root must be an object");
    object.insert(
        "$id".to_owned(),
        json!(format!("https://tinyzkp.com/schemas/{name}")),
    );
    object.insert(
        "$schema".to_owned(),
        json!("https://json-schema.org/draft/2020-12/schema"),
    );
    harden_schema(&mut schema);
    if name == "job-manifest-v1.schema.json" {
        harden_job_manifest_schema(&mut schema);
    }
    if matches!(
        name,
        "compatibility-report-v1.schema.json" | COMPATIBILITY_MANIFEST_SCHEMA_NAME
    ) {
        let manifest_root = if name == COMPATIBILITY_MANIFEST_SCHEMA_NAME {
            ""
        } else {
            "/$defs/CompatibilityManifestV1"
        };
        harden_compatibility_manifest_at(&mut schema, manifest_root);
        set_const(
            &mut schema,
            "/$defs/PlatformV1/properties/operating_system",
            json!("linux"),
        );
        set_const(
            &mut schema,
            "/$defs/PlatformV1/properties/architecture",
            json!("x86_64"),
        );
        for (field, value) in [
            ("minimum_rows", MIN_ROWS),
            ("maximum_rows", MAX_ROWS),
            ("maximum_trace_width", u64::from(MAX_TRACE_WIDTH)),
            (
                "maximum_constraint_degree",
                u64::from(MAX_CONSTRAINT_DEGREE),
            ),
        ] {
            set_const(
                &mut schema,
                &format!("/$defs/CompatibilityLimitsV1/properties/{field}"),
                json!(value),
            );
        }
    }
    if name == "guard-channel-v1.schema.json" {
        if let Some(schemas) = schema
            .pointer_mut("/properties/schemas")
            .and_then(Value::as_object_mut)
        {
            schemas.insert("minProperties".into(), json!(PUBLISHED_SCHEMA_NAMES.len()));
            schemas.insert("maxProperties".into(), json!(PUBLISHED_SCHEMA_NAMES.len()));
            schemas.insert(
                "propertyNames".into(),
                json!({"enum": PUBLISHED_SCHEMA_NAMES}),
            );
            if let Some(additional) = schemas
                .get_mut("additionalProperties")
                .and_then(Value::as_object_mut)
            {
                additional.insert("pattern".into(), json!(r"^[0-9a-f]{64}$"));
            }
        }
        if let Some(artifacts) = schema
            .pointer_mut("/properties/artifacts")
            .and_then(Value::as_object_mut)
        {
            artifacts.insert("minItems".into(), json!(1));
            artifacts.insert("uniqueItems".into(), json!(true));
        }
        set_min_max(
            &mut schema,
            "/$defs/ArtifactDescriptorV1/properties/size_bytes",
            1,
            u64::MAX,
        );
    }
    schema
}

fn harden_schema(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(harden_schema),
        Value::Object(object) => {
            if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
                for (name, property) in properties.iter_mut() {
                    let Some(property) = property.as_object_mut() else {
                        continue;
                    };
                    match name.as_str() {
                        "schema_version" => {
                            property.insert("const".into(), json!(1));
                        }
                        "compatibility_profile" => {
                            property.insert("const".into(), json!(COMPATIBILITY_PROFILE));
                        }
                        "plonky3_version" => {
                            property.insert("const".into(), json!(PLONKY3_VERSION));
                        }
                        "field" => {
                            property.insert("const".into(), json!(FIELD));
                        }
                        "extension_degree" => {
                            property.insert("const".into(), json!(EXTENSION_DEGREE));
                        }
                        "permutation" => {
                            property.insert("const".into(), json!(PERMUTATION));
                        }
                        "verifier" => {
                            property.insert("const".into(), json!(VERIFIER));
                        }
                        "engine_release_identity"
                        | "release_identity"
                        | "current_release_identity"
                        | "required_release_identity"
                        | "successor_release_identity"
                        | "guard_source_identity"
                        | "engine_source_identity" => {
                            property.insert(
                                "pattern".into(),
                                json!(r"^(?!/)(?!.*\.\.)(?!.*//)[A-Za-z0-9._:+/-]{1,256}$"),
                            );
                        }
                        "guard_source_sha" | "engine_source_sha" => {
                            property.insert("pattern".into(), json!(r"^[0-9a-f]{40}$"));
                        }
                        "sha256" | "channel_sha256" | "engine_artifact_sha256" | "eula_sha256" => {
                            property.insert("pattern".into(), json!(r"^[0-9a-f]{64}$"));
                        }
                        "oci_digest" => {
                            property.insert("pattern".into(), json!(r"^sha256:[0-9a-f]{64}$"));
                        }
                        "url" | "channel_url" | "advisory_url" => {
                            property.insert("format".into(), json!("uri"));
                            property.insert("pattern".into(), json!(r"^https://"));
                            property.insert("maxLength".into(), json!(2048));
                        }
                        "merchant" => {
                            property.insert("const".into(), json!("lemon_squeezy"));
                        }
                        "entitlement_mode" => {
                            property.insert(
                                "const".into(),
                                json!("lemon_squeezy_subscription_license_keys"),
                            );
                        }
                        "store_id" | "product_id" | "monthly_variant_id" | "annual_variant_id" => {
                            property.insert("pattern".into(), json!(r"^[1-9][0-9]{0,19}$"));
                        }
                        "release_date" => {
                            property.insert(
                                "pattern".into(),
                                json!(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$"),
                            );
                        }
                        "relative_path"
                        | "air_package"
                        | "trace_manifest"
                        | "chunks_dir"
                        | "public_inputs"
                        | "input_root"
                        | "job_root"
                        | "output_root"
                        | "scratch_root"
                        | "job_dir"
                        | "output_dir"
                        | "scratch_dir"
                        | "checkpoint_relative_path" => {
                            property.insert(
                                "pattern".into(),
                                json!(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]{1,1024}$"),
                            );
                        }
                        "operating_system" => {
                            property.insert(
                                "enum".into(),
                                json!(["linux", "macos", "windows", "other"]),
                            );
                        }
                        "architecture" => {
                            property.insert("enum".into(), json!(["x86_64", "aarch64", "other"]));
                        }
                        _ => {}
                    }
                }
                if properties.contains_key("code")
                    && properties.contains_key("class")
                    && properties.contains_key("docs_url")
                {
                    harden_reason_object(object);
                } else if properties.contains_key("event")
                    && properties.contains_key("stage")
                    && properties.contains_key("engine_release_identity")
                {
                    harden_progress_object(object);
                }
            }
            object.values_mut().for_each(harden_schema);
        }
        _ => {}
    }
}

fn harden_reason_object(object: &mut serde_json::Map<String, Value>) {
    const CODES: &[ReasonCodeV1] = &[
        ReasonCodeV1::UnsupportedPlatform,
        ReasonCodeV1::UnsupportedProfile,
        ReasonCodeV1::UnsupportedAirFeature,
        ReasonCodeV1::ManifestContractInvalid,
        ReasonCodeV1::UnsafePath,
        ReasonCodeV1::InputLimitExceeded,
        ReasonCodeV1::RamBudgetInsufficient,
        ReasonCodeV1::ScratchBudgetInsufficient,
        ReasonCodeV1::ScratchSpaceInsufficient,
        ReasonCodeV1::JobStateExists,
        ReasonCodeV1::InterruptedResumable,
        ReasonCodeV1::CheckpointMissing,
        ReasonCodeV1::CheckpointCorrupt,
        ReasonCodeV1::CheckpointReleaseMismatch,
        ReasonCodeV1::JobNotResumable,
        ReasonCodeV1::VerificationRejected,
        ReasonCodeV1::ReleaseNotActivated,
        ReasonCodeV1::LicenseInactive,
        ReasonCodeV1::LicenseProviderUnavailable,
        ReasonCodeV1::EngineArtifactMismatch,
        ReasonCodeV1::EngineProtocolInvalid,
        ReasonCodeV1::ReleaseIdentityMismatch,
        ReasonCodeV1::InternalError,
    ];
    let rules: Vec<_> = CODES
        .iter()
        .copied()
        .map(|code| {
            let canonical = ReasonV1::new(code);
            let mut context = serde_json::Map::new();
            let resource = matches!(
                code,
                ReasonCodeV1::InputLimitExceeded
                    | ReasonCodeV1::RamBudgetInsufficient
                    | ReasonCodeV1::ScratchBudgetInsufficient
                    | ReasonCodeV1::ScratchSpaceInsufficient
            );
            if !resource {
                for field in ["required_bytes", "available_bytes", "limit_bytes"] {
                    context.insert(field.into(), json!({"type": "null"}));
                }
            }
            if code == ReasonCodeV1::UnsupportedPlatform {
                context.insert("expected_platform".into(), json!({"const": "linux_x86_64"}));
            } else {
                context.insert("expected_platform".into(), json!({"type": "null"}));
                context.insert("detected_platform".into(), json!({"type": "null"}));
            }
            if code == ReasonCodeV1::UnsupportedProfile {
                context.insert(
                    "expected_profile".into(),
                    json!({"const": "tinyzkp_p3_goldilocks_v1"}),
                );
            } else {
                context.insert("expected_profile".into(), json!({"type": "null"}));
                context.insert("detected_profile".into(), json!({"type": "null"}));
            }
            context.insert("class".into(), json!({"const": canonical.class}));
            context.insert("summary".into(), json!({"const": canonical.summary}));
            context.insert(
                "remediation".into(),
                json!({"const": canonical.remediation}),
            );
            context.insert("docs_url".into(), json!({"const": canonical.docs_url}));
            json!({
                "if": {"properties": {"code": {"const": code.as_str()}}},
                "then": {"properties": context}
            })
        })
        .collect();
    object.insert("allOf".into(), Value::Array(rules));
}

fn harden_progress_object(object: &mut serde_json::Map<String, Value>) {
    let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };
    properties.insert(
        "event".into(),
        json!({"enum": [
            "doctor_started", "doctor_paths_validated", "doctor_inputs_validated",
            "doctor_estimating", "doctor_completed", "resource_estimate", "phase",
            "run_started", "run_proving", "run_verifying", "run_interrupted", "run_completed",
            "resume_started", "resume_proving", "resume_verifying", "resume_interrupted",
            "resume_completed", "verify_started", "verify_completed", "diagnostics_started",
            "diagnostics_completed", "policy_started", "policy_completed"
        ], "type": "string"}),
    );
    properties.insert(
        "stage".into(),
        json!({"enum": [
            "validation", "resource_estimate", "orchestration", "proving", "verification",
            "diagnostics", "policy", "complete"
        ], "type": "string"}),
    );
    properties.insert(
        "phase".into(),
        json!({"anyOf": [
            {"enum": ["trace", "trace_lde", "trace_commitment", "quotient", "quotient_lde",
                "quotient_commitment", "openings", "proof_assembly"]},
            {"pattern": "^fri_layer_[0-9]+$", "type": "string"},
            {"type": "null"}
        ]}),
    );
}

fn harden_job_manifest_schema(schema: &mut Value) {
    set_const(
        schema,
        "/properties/compatibility_profile",
        json!(COMPATIBILITY_PROFILE),
    );
    set_min_max(
        schema,
        "/properties/ram_budget_bytes",
        16 * 1024 * 1024,
        u64::MAX,
    );
    set_min_max(schema, "/properties/scratch_budget_bytes", 1, u64::MAX);
    set_min_max(schema, "/properties/max_threads", 1, 256);
    set_const(
        schema,
        "/$defs/WorkloadInputV1/properties/field",
        json!(FIELD),
    );
    set_const(
        schema,
        "/$defs/WorkloadInputV1/properties/extension_degree",
        json!(EXTENSION_DEGREE),
    );
    set_const(
        schema,
        "/$defs/WorkloadInputV1/properties/permutation",
        json!(PERMUTATION),
    );
    set_const(
        schema,
        "/$defs/WorkloadInputV1/properties/verifier",
        json!(VERIFIER),
    );
    if let Some(rows) = schema
        .pointer_mut("/$defs/WorkloadInputV1/properties/logical_rows")
        .and_then(Value::as_object_mut)
    {
        rows.insert(
            "enum".into(),
            Value::Array((10..=24).map(|power| json!(1u64 << power)).collect()),
        );
    }
    set_min_max(
        schema,
        "/$defs/WorkloadInputV1/properties/trace_width",
        1,
        u64::from(MAX_TRACE_WIDTH),
    );
    set_min_max(
        schema,
        "/$defs/WorkloadInputV1/properties/max_constraint_degree",
        1,
        u64::from(MAX_CONSTRAINT_DEGREE),
    );
    for feature in [
        "uses_lookups",
        "uses_buses",
        "uses_permutations",
        "uses_multi_table",
        "uses_preprocessed_columns",
        "uses_periodic_columns",
        "uses_recursion",
        "uses_gpu",
    ] {
        set_const(
            schema,
            &format!("/$defs/AirFeaturesV1/properties/{feature}"),
            json!(false),
        );
    }
}

fn harden_compatibility_manifest_at(schema: &mut Value, root: &str) {
    set_const(
        schema,
        &format!("{root}/properties/profile"),
        json!(COMPATIBILITY_PROFILE),
    );
    set_const(
        schema,
        &format!("{root}/properties/plonky3_version"),
        json!(PLONKY3_VERSION),
    );
    set_const(schema, &format!("{root}/properties/field"), json!(FIELD));
    set_const(
        schema,
        &format!("{root}/properties/extension_degree"),
        json!(EXTENSION_DEGREE),
    );
    set_const(
        schema,
        &format!("{root}/properties/permutation"),
        json!(PERMUTATION),
    );
    set_const(
        schema,
        &format!("{root}/properties/verifier"),
        json!(VERIFIER),
    );
}

fn set_const(schema: &mut Value, pointer: &str, constant: Value) {
    if let Some(property) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        property.insert("const".into(), constant);
    }
}

fn set_min_max(schema: &mut Value, pointer: &str, minimum: u64, maximum: u64) {
    if let Some(property) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        property.insert("minimum".into(), json!(minimum));
        property.insert("maximum".into(), json!(maximum));
    }
}

pub fn schema_by_name(name: &str) -> Option<Value> {
    Some(match name {
        "job-manifest-v1.schema.json" => public_schema::<JobManifestV1>(name),
        "doctor-report-v1.schema.json" => public_schema::<DoctorReportV1>(name),
        "compatibility-report-v1.schema.json" => public_schema::<CompatibilityReportV1>(name),
        "reason-v1.schema.json" => public_schema::<ReasonV1>(name),
        "error-envelope-v1.schema.json" => public_schema::<ErrorEnvelopeV1>(name),
        "progress-event-v1.schema.json" => public_schema::<ProgressEventV1>(name),
        "job-result-v1.schema.json" => public_schema::<JobResultV1>(name),
        "support-report-v1.schema.json" => public_schema::<SupportReportV1>(name),
        "job-inspect-result-v1.schema.json" => public_schema::<JobInspectResultV1>(name),
        "guard-channel-v1.schema.json" => public_schema::<GuardChannelV1>(name),
        "guard-release-index-v1.schema.json" => public_schema::<GuardReleaseIndexV1>(name),
        "policy-baseline-v1.schema.json" => public_schema::<PolicyBaselineV1>(name),
        COMPATIBILITY_MANIFEST_SCHEMA_NAME => public_schema::<CompatibilityManifestV1>(name),
        _ => return None,
    })
}

/// Deserialize JSON while rejecting duplicate object keys and non-finite
/// floating-point values before the typed contract is constructed.
pub fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    serde_json::from_value(strict.0)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E: DeError>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E: DeError>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E: DeError>(self, value: f64) -> Result<Self::Value, E> {
        if !value.is_finite() {
            return Err(E::custom("non-finite JSON number"));
        }
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E: DeError>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(mode: RequestedModeV1) -> JobManifestV1 {
        JobManifestV1 {
            schema_version: 1,
            compatibility_profile: COMPATIBILITY_PROFILE.to_owned(),
            workload: WorkloadInputV1 {
                air_package: "air.json".into(),
                trace_manifest: "trace.json".into(),
                chunks_dir: "chunks".into(),
                public_inputs: "public.json".into(),
                logical_rows: MIN_ROWS,
                trace_width: 2,
                max_constraint_degree: 2,
                field: FIELD.to_owned(),
                extension_degree: EXTENSION_DEGREE,
                permutation: PERMUTATION.to_owned(),
                verifier: VERIFIER.to_owned(),
                features: AirFeaturesV1 {
                    uses_lookups: false,
                    uses_buses: false,
                    uses_permutations: false,
                    uses_multi_table: false,
                    uses_preprocessed_columns: false,
                    uses_periodic_columns: false,
                    uses_recursion: false,
                    uses_gpu: false,
                },
            },
            mode,
            ram_budget_bytes: 1_000,
            scratch_budget_bytes: 10_000,
            max_threads: 1,
            roots: JobRootsV1 {
                input_root: "inputs".into(),
                job_root: "jobs".into(),
                output_root: "outputs".into(),
                scratch_root: "scratch".into(),
            },
            job_dir: "job".into(),
            output_dir: "job".into(),
            scratch_dir: "job".into(),
        }
    }

    fn estimates(conventional: u64, bounded: u64, scratch: u64) -> ResourceEstimatesV1 {
        ResourceEstimatesV1 {
            conventional: ResourceEstimateV1 {
                peak_resident_bytes: conventional,
                scratch_high_water_bytes: 0,
                total_read_bytes: 0,
                total_write_bytes: 0,
            },
            bounded: ResourceEstimateV1 {
                peak_resident_bytes: bounded,
                scratch_high_water_bytes: scratch,
                total_read_bytes: 0,
                total_write_bytes: 0,
            },
        }
    }

    #[test]
    fn reason_vocabulary_is_exact_and_docs_are_local_anchors() {
        let encoded = serde_json::to_value(schema_for!(ReasonCodeV1)).unwrap();
        let text = encoded.to_string();
        assert!(text.contains("unsupported_platform"));
        assert!(text.contains("internal_error"));
        assert!(!text.contains("unsupported_field"));
        for name in PUBLIC_SCHEMA_NAMES {
            assert!(schema_by_name(name).is_some());
        }
        assert_eq!(PUBLIC_SCHEMA_NAMES.len(), 12);
        assert_eq!(PUBLISHED_SCHEMA_NAMES.len(), 13);
        assert_eq!(
            PUBLISHED_SCHEMA_NAMES.last().copied(),
            Some(COMPATIBILITY_MANIFEST_SCHEMA_NAME)
        );
        assert!(schema_by_name(COMPATIBILITY_MANIFEST_SCHEMA_NAME).is_some());
        assert!(schema_by_name("engine-checkpoint-inspect-result-v1.schema.json").is_none());
        let reason = ReasonV1::new(ReasonCodeV1::InterruptedResumable);
        assert_eq!(reason.docs_url, "/troubleshooting#interrupted_resumable");
        let mut tampered = serde_json::to_value(&reason).unwrap();
        tampered["summary"] = json!("untrusted detail");
        assert!(serde_json::from_value::<ReasonV1>(tampered).is_err());
    }

    #[test]
    fn automatic_selection_uses_exact_seventy_percent_boundary() {
        let job = manifest(RequestedModeV1::Auto);
        assert_eq!(
            select_and_preflight(&job, &estimates(700, 200, 90), Some(10_000))
                .unwrap()
                .0,
            SelectedModeV1::Conventional
        );
        assert_eq!(
            select_and_preflight(&job, &estimates(701, 200, 90), Some(10_000))
                .unwrap()
                .0,
            SelectedModeV1::Bounded
        );
    }

    #[test]
    fn scratch_reserves_exact_ten_percent_headroom() {
        assert_eq!(required_scratch_capacity_with_headroom(900), Some(1_000));
        let job = manifest(RequestedModeV1::Bounded);
        let (_, preflight) =
            select_and_preflight(&job, &estimates(700, 200, 900), Some(1_000)).unwrap();
        assert_eq!(preflight.scratch_required_with_headroom_bytes, Some(1_000));
        let error = select_and_preflight(&job, &estimates(700, 200, 900), Some(999)).unwrap_err();
        assert_eq!(error.code, ReasonCodeV1::ScratchSpaceInsufficient);
    }

    #[test]
    fn doctor_reports_roundtrip_for_success_incompatible_and_resource_exits() {
        fn roundtrip(report: &DoctorReportV1) -> DoctorReportV1 {
            serde_json::from_slice(&serde_json::to_vec(report).unwrap()).unwrap()
        }

        let mut job = manifest(RequestedModeV1::Bounded);
        job.ram_budget_bytes = 1_000_000_000;
        let resource_estimates = estimates(700, 200, 900);
        let (selected_mode, preflight) =
            select_and_preflight(&job, &resource_estimates, Some(1_000)).unwrap();
        let report = DoctorReportV1 {
            schema_version: 1,
            engine_release_identity: "release-1".into(),
            compatibility_profile: COMPATIBILITY_PROFILE.into(),
            ready: true,
            requested_mode: job.mode,
            selected_mode: Some(selected_mode),
            estimates: Some(resource_estimates.clone()),
            preflight,
            reasons: Vec::new(),
        };
        assert!(roundtrip(&report).validate_for_manifest("release-1", &job));

        let mut tampered = report.clone();
        tampered.preflight.memory_selection_threshold_bytes += 1;
        assert!(!tampered.validate_for_manifest("release-1", &job));

        let incompatible = DoctorReportV1 {
            schema_version: 1,
            engine_release_identity: "release-1".into(),
            compatibility_profile: COMPATIBILITY_PROFILE.into(),
            ready: false,
            requested_mode: job.mode,
            selected_mode: None,
            estimates: None,
            preflight: declaration_failure_preflight(&job, None),
            reasons: vec![ReasonV1::new(ReasonCodeV1::UnsupportedProfile)],
        };
        assert_eq!(incompatible.reasons[0].class.exit_code(), 10);
        assert!(roundtrip(&incompatible).validate_for_manifest("release-1", &job));

        let mut hard_minimum = job.clone();
        hard_minimum.ram_budget_bytes = 100;
        hard_minimum.scratch_budget_bytes = 0;
        let minimum_reasons: Vec<_> = hard_minimum
            .compatibility_reasons()
            .into_iter()
            .filter(|reason| reason.class == ExitClassV1::InsufficientResources)
            .collect();
        let minimum_failure = DoctorReportV1 {
            schema_version: 1,
            engine_release_identity: "release-1".into(),
            compatibility_profile: COMPATIBILITY_PROFILE.into(),
            ready: false,
            requested_mode: hard_minimum.mode,
            selected_mode: None,
            estimates: Some(resource_estimates),
            preflight: declaration_failure_preflight(&hard_minimum, Some(1_000)),
            reasons: minimum_reasons,
        };
        assert_eq!(minimum_failure.reasons[0].class.exit_code(), 12);
        assert!(roundtrip(&minimum_failure).validate_for_manifest("release-1", &hard_minimum));

        let mut constrained = job.clone();
        constrained.mode = RequestedModeV1::Conventional;
        constrained.ram_budget_bytes = 16 * 1024 * 1024;
        let runtime_estimates = estimates(32 * 1024 * 1024, 200, 900);
        let reason =
            select_and_preflight(&constrained, &runtime_estimates, Some(1_000)).unwrap_err();
        assert_eq!(reason.code, ReasonCodeV1::RamBudgetInsufficient);
        let failed = DoctorReportV1 {
            schema_version: 1,
            engine_release_identity: "release-1".into(),
            compatibility_profile: COMPATIBILITY_PROFILE.into(),
            ready: false,
            requested_mode: constrained.mode,
            selected_mode: None,
            estimates: Some(runtime_estimates),
            preflight: failed_resource_preflight(&constrained, Some(1_000), &reason),
            reasons: vec![reason],
        };
        assert_eq!(failed.preflight.scratch_required_with_headroom_bytes, None);
        assert_eq!(failed.reasons[0].class.exit_code(), 12);
        assert!(roundtrip(&failed).validate_for_manifest("release-1", &constrained));
    }

    #[test]
    fn resource_arithmetic_matches_wide_integer_reference_at_u64_edges() {
        for value in [
            0,
            1,
            9,
            10,
            11,
            u64::MAX / 10,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ] {
            assert_eq!(
                memory_selection_threshold(value),
                ((u128::from(value) * 7) / 10) as u64
            );
            let wide = (u128::from(value) * 10).div_ceil(9);
            let expected = u64::try_from(wide).ok();
            assert_eq!(required_scratch_capacity_with_headroom(value), expected);
        }
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_and_progress_vocabulary_is_closed() {
        assert!(parse_strict_json::<serde_json::Value>(br#"{"a":1,"a":2}"#).is_err());
        let invalid = serde_json::json!({
            "schema_version": 1,
            "engine_release_identity": "release",
            "event": "arbitrary",
            "stage": "proving",
            "phase": null,
            "completed_phases": null,
            "total_phases": null,
            "progress": null,
            "resource_usage": null,
            "checkpoint_durable": null
        });
        assert!(serde_json::from_value::<ProgressEventV1>(invalid).is_err());
    }

    #[test]
    fn schemas_exclude_obvious_non_v1_and_unbounded_values() {
        let job = schema_by_name("job-manifest-v1.schema.json").unwrap();
        assert_eq!(
            job.pointer("/properties/schema_version/const"),
            Some(&json!(1))
        );
        assert_eq!(
            job.pointer("/properties/compatibility_profile/const"),
            Some(&json!(COMPATIBILITY_PROFILE))
        );
        assert_eq!(
            job.pointer("/$defs/WorkloadInputV1/properties/field/const"),
            Some(&json!(FIELD))
        );
        assert_eq!(
            job.pointer("/$defs/WorkloadInputV1/properties/trace_width/maximum"),
            Some(&json!(MAX_TRACE_WIDTH))
        );
        assert_eq!(
            job.pointer("/$defs/AirFeaturesV1/properties/uses_lookups/const"),
            Some(&json!(false))
        );
        assert!(job
            .pointer("/properties/job_dir/pattern")
            .and_then(Value::as_str)
            .is_some_and(|pattern| pattern.contains(r"\.\.")));

        let reason = schema_by_name("reason-v1.schema.json").unwrap();
        assert_eq!(
            reason
                .pointer("/allOf")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(23)
        );
        let progress = schema_by_name("progress-event-v1.schema.json").unwrap();
        assert!(progress
            .pointer("/properties/event/enum")
            .and_then(Value::as_array)
            .is_some_and(|values| values.contains(&json!("run_started"))
                && !values.contains(&json!("arbitrary"))));
        let channel = schema_by_name("guard-channel-v1.schema.json").unwrap();
        assert_eq!(
            channel.pointer("/$defs/MerchantCatalogIdentityV1/properties/entitlement_mode/const"),
            Some(&json!("lemon_squeezy_subscription_license_keys"))
        );
        assert_eq!(
            channel.pointer("/$defs/MerchantCatalogIdentityV1/properties/merchant/const"),
            Some(&json!("lemon_squeezy"))
        );
        assert_eq!(
            channel.pointer("/properties/schemas/minProperties"),
            Some(&json!(PUBLISHED_SCHEMA_NAMES.len()))
        );
        let compatibility = schema_by_name(COMPATIBILITY_MANIFEST_SCHEMA_NAME).unwrap();
        assert_eq!(
            compatibility.pointer("/properties/profile/const"),
            Some(&json!(COMPATIBILITY_PROFILE))
        );
    }

    #[test]
    fn exit_classes_are_stable() {
        assert_eq!(ExitClassV1::Incompatible.exit_code(), 10);
        assert_eq!(ExitClassV1::InvalidInput.exit_code(), 11);
        assert_eq!(ExitClassV1::InsufficientResources.exit_code(), 12);
        assert_eq!(ExitClassV1::ResumableInterruption.exit_code(), 13);
        assert_eq!(ExitClassV1::CorruptCheckpoint.exit_code(), 14);
        assert_eq!(ExitClassV1::VerificationFailure.exit_code(), 15);
        assert_eq!(ExitClassV1::LicenseFailure.exit_code(), 16);
        assert_eq!(ExitClassV1::InternalError.exit_code(), 70);
    }

    #[test]
    fn published_job_manifest_sample_is_contract_valid() {
        let manifest: JobManifestV1 = parse_strict_json(include_bytes!(
            "../../../examples/plonky3/job-manifest-v1.example.json"
        ))
        .unwrap();
        assert!(manifest.compatibility_reasons().is_empty());
        assert_eq!(manifest.mode, RequestedModeV1::Auto);
    }

    #[test]
    fn merchant_catalog_identity_is_exact_and_variant_distinct() {
        let mut catalog = MerchantCatalogIdentityV1 {
            merchant: "lemon_squeezy".into(),
            entitlement_mode: "lemon_squeezy_subscription_license_keys".into(),
            store_id: "123".into(),
            product_id: "456".into(),
            monthly_variant_id: "789".into(),
            annual_variant_id: "790".into(),
        };
        assert!(catalog.validate());
        catalog.annual_variant_id = catalog.monthly_variant_id.clone();
        assert!(!catalog.validate());
    }
}
