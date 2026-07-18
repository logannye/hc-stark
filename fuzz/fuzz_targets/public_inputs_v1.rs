#![no_main]

use hc_plonky3::contracts::{
    AirConstraintKindV1, AirConstraintV1, AirExpressionV1, AirPackageV1, PublicInputsV1,
    MAX_MANIFEST_JSON_BYTES,
};
use hc_plonky3::COMPATIBILITY_PROFILE;
use libfuzzer_sys::fuzz_target;

fn declarative_air() -> AirPackageV1 {
    AirPackageV1 {
        schema_version: 1,
        backend: "plonky3".to_owned(),
        profile: COMPATIBILITY_PROFILE.to_owned(),
        field: "goldilocks".to_owned(),
        expected_verifier: "p3_uni_stark_0.6.1".to_owned(),
        trace_width: 1,
        public_inputs: Vec::new(),
        expressions: vec![
            AirExpressionV1::Current { column: 0 },
            AirExpressionV1::Next { column: 0 },
            AirExpressionV1::Sub { left: 1, right: 0 },
        ],
        constraints: vec![AirConstraintV1 {
            kind: AirConstraintKindV1::Transition,
            expression: 2,
        }],
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_MANIFEST_JSON_BYTES {
        return;
    }
    if let Ok(public_inputs) = serde_json::from_slice::<PublicInputsV1>(data) {
        // Public inputs are meaningful only when bound to their exact AIR.
        // Keep a valid fixed AIR so mutations reach validation and digest code.
        let air = declarative_air();
        let _ = public_inputs.validate_for_air(&air);
        let _ = public_inputs.digest(&air);
    }
});
