use std::path::Path;

use anyhow::Result;
use tinyzkp_contracts::{EstimateRequestV1, EstimateResponseV1, ReasonCodeV1};

use crate::protocol::ProtocolFailure;

/// Cost a declared configuration read from a manifest file on disk.
///
/// This is purely the CLI-only file-reading wrapper: it reads and parses
/// `config_path`, then delegates the entire request-to-response mapping to
/// `hc_plonky3::estimate_params::estimate_request`. That function is the
/// single implementation of the cost model — the hosted WASM API
/// (`hc-wasm`'s `estimate_json`) calls the exact same function, so the CLI
/// and the API cannot diverge on a number the way Phase 1a's `conventional`
/// estimate did (computed two ways, 7.8x apart). `hc-plonky3` sits below
/// both `hc-cli` and `hc-wasm` in the dependency graph, so each reaches it
/// without depending on the other. Nothing here recomputes any part of that
/// mapping.
///
/// Errors map onto the same `ProtocolFailure`/`ReasonCodeV1` vocabulary every
/// other command uses (see `doctor.rs`/`plonky3.rs`), so the CLI's structured
/// JSON error envelope names the actual problem instead of collapsing every
/// failure into `internal_error`. `ReasonV1` forbids free-form diagnostic
/// text on that public boundary, so no config value (e.g. an unsupported
/// field name) is ever embedded in the returned error.
pub fn run(config_path: &Path) -> Result<EstimateResponseV1> {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    let request: EstimateRequestV1 = serde_json::from_str(&raw)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;

    hc_plonky3::estimate_params::estimate_request(request)
        .map_err(|failure| anyhow::Error::new(ProtocolFailure::new(failure.reason_code())))
}
