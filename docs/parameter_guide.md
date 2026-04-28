# Parameter Guide

## Security Parameters

### query_count

Number of FRI oracle queries. Each query provides ~log2(blowup_factor) bits of security.

| query_count | blowup=2 | blowup=4 | Notes |
|-------------|----------|----------|-------|
| 30 | ~30 bits | ~60 bits | Legacy default, **insecure** |
| 80 | ~80 bits | ~160 bits | New default, production minimum |
| 128 | ~128 bits | ~256 bits | Conservative |
| 200 | ~200 bits | ~400 bits | Maximum allowed |

**Server minimum:** 80 (configurable via `HC_SERVER_MIN_QUERY_COUNT`)

### lde_blowup_factor

Low-degree extension blowup. Must be a power of 2. Higher values increase security per query but use more memory.

| Factor | Effect |
|--------|--------|
| 2 | Default. Minimal overhead. |
| 4 | 2x security bits per query. 2x memory. |
| 8 | Good for high-assurance. 4x memory. |
| 16 | Maximum allowed. 8x memory. |

### ZK Masking (zk_mask_degree)

Set `zk_mask_degree > 0` to enable zero-knowledge proofs (protocol v4). The masking polynomial adds randomness to prevent information leakage about the witness.

## Performance Parameters

### block_size

Number of trace rows processed per block. Must be a power of 2.

| block_size | Memory | Speed | Use case |
|------------|--------|-------|----------|
| 2-8 | Minimal | Slowest | Tests only |
| 64-256 | Low | Good | Small traces |
| 1024-4096 | Medium | Better | Medium traces |
| 65536+ | High | Best throughput | Large traces |
| 1048576 (2^20) | ~8GB | Maximum | Server maximum |

**Server maximum:** 1048576 (configurable via `HC_SERVER_MAX_BLOCK_SIZE`)

### fri_final_poly_size

Size of the final FRI polynomial. Smaller values mean more FRI rounds (larger proof) but stronger soundness guarantees. Typical values: 1-4.

## Server Parameters

### Rate Limits

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_prove_rpm` | 100 | Prove requests per minute per tenant |
| `max_verify_rpm` | 300 | Verify requests per minute per tenant |

Disable with `HC_SERVER_RATE_LIMIT_DISABLED=1`.

### Inflight Limits

- `max_inflight_jobs`: Max concurrent prove jobs per tenant (default: 4)
- `max_verify_inflight`: Max concurrent verify requests (default: 8)

### Retention & GC

- `retention_secs`: How long to keep completed job artifacts (default: 24h)
- Background GC runs every 300s (configurable via `HC_SERVER_GC_INTERVAL_SECS`)
