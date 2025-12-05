#!/usr/bin/env python3
"""
Aggregate height benchmark history into markdown/PNG dashboard artifacts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from typing import Any, Dict, List, Optional, Tuple

try:
    import matplotlib.pyplot as plt

    HAS_MATPLOTLIB = True
except Exception:  # pragma: no cover
    HAS_MATPLOTLIB = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aggregate height benchmark metrics")
    parser.add_argument(
        "--history",
        default="benchmarks/height_history.jsonl",
        help="Path to the JSONL history produced by hc-cli bench --scenario height",
    )
    parser.add_argument(
        "--out-dir",
        default="benchmarks",
        help="Directory where dashboard artifacts should be written",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of recent entries to include in the markdown table",
    )
    return parser.parse_args()


def load_history(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    entries: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def extract_metric(metrics: Dict[str, Any], field: str, key: str) -> Optional[float]:
    section = metrics.get(field)
    if isinstance(section, dict):
        value = section.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return None


def extract_scalar(metrics: Dict[str, Any], field: str) -> Optional[float]:
    value = metrics.get(field)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def render_markdown(
    rows: List[Dict[str, Any]], out_path: str, total_entries: int
) -> None:
    lines = ["# Height Benchmark Dashboard", ""]
    if not rows:
        lines.append("No height benchmark history found.")
    else:
        lines.append(f"Total recorded runs: **{total_entries}**")
        lines.append("")
        header = [
            "Timestamp (UTC)",
            "Tag",
            "Leaves",
            "Block",
            "Samples",
            "Merkle stream avg (ms)",
            "KZG stream avg (ms)",
            "Merkle blocks avg",
            "KZG blocks avg",
            "Roots OK",
        ]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join([" --- "] * len(header)) + "|")
        for row in rows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        row["timestamp_str"],
                        row.get("tag") or "",
                        row.get("leaves") or "NA",
                        row.get("block_size") or "NA",
                        row.get("samples") or "NA",
                        row.get("merkle_ms") or "NA",
                        row.get("kzg_ms") or "NA",
                        row.get("merkle_blocks") or "NA",
                        row.get("kzg_blocks") or "NA",
                        row.get("roots_match") or "NA",
                    ]
                )
                + " |"
            )
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def maybe_render_chart(rows: List[Dict[str, Any]], out_path: str) -> None:
    if not HAS_MATPLOTLIB or not rows:
        return
    dates: List[dt.datetime] = []
    merkle_vals: List[float] = []
    kzg_vals: List[float] = []
    for row in rows:
        ts = row.get("timestamp_dt")
        merkle = row.get("merkle_ms_val")
        kzg = row.get("kzg_ms_val")
        if ts and merkle is not None and kzg is not None:
            dates.append(ts)
            merkle_vals.append(merkle)
            kzg_vals.append(kzg)
    if not dates:
        return
    plt.figure(figsize=(8, 4))
    plt.plot(dates, merkle_vals, marker="o", label="Merkle stream ms (avg)")
    plt.plot(dates, kzg_vals, marker="o", label="KZG stream ms (avg)")
    plt.xlabel("Run timestamp (UTC)")
    plt.ylabel("Duration (ms)")
    plt.title("Height benchmark streaming throughput")
    plt.legend()
    plt.tight_layout()
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    plt.savefig(out_path)
    plt.close()


def main() -> None:
    args = parse_args()
    history = load_history(args.history)
    if not history:
        render_markdown([], os.path.join(args.out_dir, "height_dashboard.md"), 0)
        print(f"No history found at {args.history}, dashboard stub created.")
        return

    processed_rows: List[Dict[str, Any]] = []
    for entry in history[-args.limit :]:
        metrics = entry.get("metrics", {})
        timestamp = entry.get("generated_at", 0)
        timestamp_dt = dt.datetime.utcfromtimestamp(timestamp)
        def fmt_float(value: Optional[float]) -> Optional[str]:
            return f"{value:.3f}" if value is not None else None

        row = {
            "timestamp_str": timestamp_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_dt": timestamp_dt,
            "tag": entry.get("tag"),
            "leaves": fmt_float(extract_scalar(metrics, "leaves")),
            "block_size": fmt_float(extract_scalar(metrics, "block_size")),
            "samples": fmt_float(extract_scalar(metrics, "samples")),
            "merkle_ms": fmt_float(extract_metric(metrics, "merkle_stream_ms", "avg")),
            "merkle_ms_val": extract_metric(metrics, "merkle_stream_ms", "avg"),
            "kzg_ms": fmt_float(extract_metric(metrics, "kzg_stream_ms", "avg")),
            "kzg_ms_val": extract_metric(metrics, "kzg_stream_ms", "avg"),
            "merkle_blocks": fmt_float(
                extract_metric(metrics, "merkle_stream_blocks", "avg")
            ),
            "kzg_blocks": fmt_float(
                extract_metric(metrics, "kzg_stream_blocks", "avg")
            ),
            "roots_match": str(metrics.get("roots_match", "NA")),
        }
        processed_rows.append(row)

    dashboard_path = os.path.join(args.out_dir, "height_dashboard.md")
    render_markdown(processed_rows[::-1], dashboard_path, len(history))
    chart_path = os.path.join(args.out_dir, "height_trend.png")
    maybe_render_chart(processed_rows, chart_path)

    print(
        f"Wrote dashboard markdown to {dashboard_path} "
        f"and {'created' if HAS_MATPLOTLIB else 'skipped'} height_trend.png"
    )


if __name__ == "__main__":
    main()

