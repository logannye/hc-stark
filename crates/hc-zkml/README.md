# hc-zkml

Verifiable AI inference on top of the height-compressed STARK prover.

## What it does

Given a quantized model graph (matmul / conv2d / ReLU / softmax / add) and an
input tensor, `hc-zkml` produces a STARK proof that

```
output = model(input)
```

without revealing the input (or, in ZK-masked mode, without revealing the
intermediate activations either). Verifiers receive only:

- A `ModelCommitment` (architecture + weights digest)
- The output tensor in the clear (or the output digest, in ZK-masked mode)
- A succinct proof

## Why height compression matters here

A modern transformer or CNN run produces tens of GB of intermediate
activations. Materializing them in RAM is the dominant cost of every existing
zkML system. Inference is, however, the canonical height-compressible
computation:

| Operation | Tree shape | Working set under √T discipline |
|-----------|------------|---------------------------------|
| MatMul C = A·B over inner dim K | balanced summation tree | O(√K) per output element |
| Conv2d (lowered to im2col + MatMul) | same as MatMul | O(√K) |
| ReLU / Add | pointwise (depth-0 trees) | O(tile_dim) |
| Softmax | linear scan + max + exp + sum tree | O(tile_dim + log) |

Because every layer's output is a deterministic function of its input plus the
weights, intermediate tensors are *replayable* from a constant-size checkpoint
(the input commitment + layer index). The prover never holds more than one
tile of activations in RAM at a time.

## Status

This crate currently ships the locked-in **public API surface**: types, model
graph, witness/proof envelopes, configuration, and validation helpers.

The cryptographic body (matmul AIR, tiled FFT, layer-boundary commitments)
returns `HcError::unimplemented` and is tracked in `ROADMAP_EXTENSIONS.md`
under Phase 1. API stability is enforced by the unit tests in this crate.

## Roadmap

See [`ROADMAP_EXTENSIONS.md`](../../ROADMAP_EXTENSIONS.md) at the workspace
root for the phased delivery plan and target commercial templates
(`zkml_inference`, `zkml_attestation`, `zkml_provenance`).
