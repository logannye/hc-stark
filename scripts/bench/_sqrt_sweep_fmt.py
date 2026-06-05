#!/usr/bin/env python3
"""Format one height-bench JSON line into a sqrt-sweep CSV row.

Reads the bench JSON on stdin; argv = [T, block_size]. Used by run_sqrt_sweep.sh.
"""
import sys
import json

T = int(sys.argv[1])
BLK = int(sys.argv[2])
d = json.load(sys.stdin)

blocks = int(d["merkle_stream_blocks"]["avg"])
working = BLK  # the streaming commit holds one block (= √T elements) at a time
reduction = T / working

print(",".join(str(x) for x in [
    d["leaves"], d["block_size"], blocks, working, T, f"{reduction:.1f}",
    f"{d['merkle_stream_peak_mb']['avg']:.3f}", f"{d['merkle_full_peak_mb']['avg']:.3f}",
    f"{d['merkle_stream_ms']['avg']:.3f}", f"{d['merkle_full_ms']['avg']:.3f}",
    d["roots_match"],
]))
