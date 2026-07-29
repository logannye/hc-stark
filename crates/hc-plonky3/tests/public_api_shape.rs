// Compiles only if `hc_plonky3::MatrixOpening<'a>` names a type with ONE
// lifetime parameter, exactly as it did before Task 8.
#[allow(dead_code)]
fn external_caller_shape<'a>(_: Option<hc_plonky3::MatrixOpening<'a>>) {}
