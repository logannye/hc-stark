// Compiles only if `hc_plonky3::MatrixOpening<'a>` names a type with ONE
// lifetime parameter, exactly as it did before Task 8.
#[allow(dead_code)]
fn external_caller_shape<'a>(_: Option<hc_plonky3::MatrixOpening<'a>>) {}

/// Regression guard for the E0283 ambiguity introduced when
/// `FibonacciWorkload` gained an all-profile blanket impl. This file is an
/// INTEGRATION test, so it sees only the public API — exactly what an
/// external consumer sees. Every in-crate call site had already been
/// rewritten to UFCS, which is why the break was invisible until now.
///
/// These are bare method calls with NO turbofish and NO type annotation. If
/// the inherent methods are ever removed, this stops compiling.
#[test]
fn fibonacci_workload_methods_are_callable_without_naming_a_profile() {
    let fib = hc_plonky3::FibonacciWorkload {
        initial_a: 0,
        initial_b: 1,
        logical_rows: 16,
    };

    assert_eq!(fib.rows(), 16);
    assert_eq!(fib.identity().id, "fibonacci");
    assert_eq!(fib.input_digest().len(), 32);
    let _air = fib.air();
}
