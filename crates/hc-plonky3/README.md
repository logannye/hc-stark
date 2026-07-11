# hc-plonky3

`hc-plonky3` is TinyZKP's MIT-licensed resource-bounded prover backend for the
exact Plonky3 0.6.1 proof format and unmodified `p3-uni-stark` verifier.

The crate adds streamed trace/quotient evaluation, scratch-backed transforms,
durable MMCS/FRI layers, deterministic checkpoint recovery, and local artifact
contracts. It does not introduce a new transcript, verifier, proof format, or
zero-knowledge claim.

Partner AIR crates implement `ResourceBoundedWorkload`, including deterministic
identity, public values, input digest, and blockwise trace production. They can
call `estimate_resource_bounded_workload`, `prove_resource_bounded`, and
`verify_resource_bounded_proof` without registering the AIR in TinyZKP's CLI.

The backend remains pre-production until the fixed-host resource evidence,
independent reviews, and external design-partner gates pass.
