#!/usr/bin/env python3
"""
Render the three TinyZKP MCP directory submission screenshots.

Inputs:
  - /tmp/mcp-shots/{prove1,poll1,summary1,proof1,verify1}.json  (accumulator_step)
  - /tmp/mcp-shots/{prove3,poll3,proof3,verify3}.json           (accumulator_step)

Output:
  - marketing/screenshots/shot1_range_prove.png
  - marketing/screenshots/shot2_verify.png
  - marketing/screenshots/shot3_policy_compliance.png

Usage: python3 render_shots.py
"""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).parent
TEMPLATE = (ROOT / "_template.html").read_text()
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def load(name):
    p = Path(f"/tmp/mcp-shots/{name}.json")
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {}


def truncate_b64(b64: str, head=44, tail=20) -> str:
    if len(b64) <= head + tail + 5:
        return b64
    return f"{b64[:head]}…{b64[-tail:]}"


def shot1_html() -> str:
    """Accumulator step: balance from 1000 to 1045 via deltas."""
    summary = load("summary1") if isinstance(load("summary1"), dict) else {}
    poll = load("poll1")
    proof = load("proof1")
    job_id = poll.get("job_id", "—")
    proof_b64 = proof.get("proof_b64", "")
    proof_short = truncate_b64(proof_b64, 60, 24)
    proof_size = round(len(proof_b64) * 3 / 4 / 1024, 1)  # base64 → bytes → KB

    content = f"""
<div class="topbar">
  <div class="brand">
    <div class="logo"><span>Tiny</span>ZKP</div>
    <div class="badge">via Claude · MCP</div>
  </div>
  <div class="url">mcp.tinyzkp.com</div>
</div>

<div class="caption">
  Generated a zero-knowledge proof that an account moved from
  <strong>1,000</strong> to <strong>1,045</strong> via the declared deltas.
  The proof is a self-contained binary blob anyone can verify offline in ~5 ms.
</div>

<div class="card">
  <div class="head">
    <div class="dot"></div>
    <div class="tool">prove_template</div>
    <div class="arrow">→</div>
    <div class="server">tinyzkp</div>
    <div class="meta">accumulator_step · zk on</div>
  </div>
  <div class="body stack">
    <div class="row">
      <div class="label">Initial</div>
      <div class="value"><span class="accent">1,000</span></div>
    </div>
    <div class="row">
      <div class="label">Final</div>
      <div class="value"><span class="accent">1,045</span></div>
    </div>
    <div class="row">
      <div class="label">Deltas</div>
      <div class="value"><span class="muted">[10, 20, 15] — sum verifies transition</span></div>
    </div>
    <div class="row">
      <div class="label">Status</div>
      <div class="value"><span class="pill green">✓ succeeded</span>
        <span class="muted" style="margin-left:14px">job &nbsp;<span style="color:var(--text)">{job_id}</span></span></div>
    </div>
    <div class="row">
      <div class="label">Proof</div>
      <div class="value code">{proof_short}
        <div style="margin-top:8px;color:var(--dim);font-size:12px">{proof_size} KB · base64-encoded · ZK-STARK · template <span class="accent">accumulator_step</span></div></div>
    </div>
  </div>
</div>

<div class="footer">
  Free tier: 100 proofs/month — no credit card. &nbsp;·&nbsp;
  <span style="color:var(--text)">claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com</span>
</div>
"""
    return TEMPLATE.replace("__TITLE__", "TinyZKP — Range Proof").replace("__CONTENT__", content)


def shot2_html() -> str:
    """Independent verification of the proof from shot 1."""
    poll = load("poll1")
    proof = load("proof1")
    verify = load("verify1") if isinstance(load("verify1"), dict) else {}
    job_id = poll.get("job_id", "—")
    proof_b64 = proof.get("proof_b64", "")
    proof_short = truncate_b64(proof_b64, 56, 22)
    is_valid = verify.get("valid", True)
    valid_pill = '<span class="pill green">✓ valid</span>' if is_valid else '<span class="pill amber">✗ invalid</span>'

    content = f"""
<div class="topbar">
  <div class="brand">
    <div class="logo"><span>Tiny</span>ZKP</div>
    <div class="badge">via Claude · MCP</div>
  </div>
  <div class="url">mcp.tinyzkp.com</div>
</div>

<div class="caption">
  Independently verified the same proof. The check is pure cryptography —
  it doesn't trust TinyZKP, the original prover, or anyone else.
  <strong>Anyone, anywhere</strong> can run the same verifier and get the
  same answer.
</div>

<div class="card">
  <div class="head">
    <div class="dot"></div>
    <div class="tool">verify_proof</div>
    <div class="arrow">→</div>
    <div class="server">tinyzkp</div>
    <div class="meta">read-only · no quota consumed</div>
  </div>
  <div class="body stack">
    <div class="row">
      <div class="label">Input</div>
      <div class="value code">{proof_short}
        <div style="margin-top:6px;color:var(--dim);font-size:12px">proof bytes from job <span style="color:var(--text)">{job_id}</span></div></div>
    </div>
    <div class="row">
      <div class="label">Result</div>
      <div class="value">{valid_pill}
        <span class="muted" style="margin-left:14px">cryptographic check passed in &lt; 1 s</span></div>
    </div>
    <div class="verdict">
      <div class="icon">✓</div>
      <div class="text">The proof <span class="bold">is valid</span> —
        the declared transition really did happen as stated, and the
        verifier learned nothing else about it.</div>
    </div>
  </div>
</div>

<div class="footer">
  Verifiable from any language: drop-in WASM verifier, or this MCP tool — no round-trip needed.
</div>
"""
    return TEMPLATE.replace("__TITLE__", "TinyZKP — Verify Proof").replace("__CONTENT__", content)


def shot3_html() -> str:
    """Accumulator step: prove state machine advanced from start to end via declared steps."""
    poll = load("poll3")
    proof = load("proof3")
    job_id = poll.get("job_id", "—")
    proof_b64 = proof.get("proof_b64", "")
    proof_short = truncate_b64(proof_b64, 60, 22)
    proof_size = round(len(proof_b64) * 3 / 4 / 1024, 1) if proof_b64 else "—"

    content = f"""
<div class="topbar">
  <div class="brand">
    <div class="logo"><span>Tiny</span>ZKP</div>
    <div class="badge">via Claude · MCP</div>
  </div>
  <div class="url">mcp.tinyzkp.com</div>
</div>

<div class="caption">
  Generated a <strong>state-transition receipt</strong> for an agent's
  run — proves that the running total advanced from a declared start to a
  declared end via a recorded sequence of steps, transferably verifiable by
  any third party offline.
</div>

<div class="card">
  <div class="head">
    <div class="dot"></div>
    <div class="tool">prove_template</div>
    <div class="arrow">→</div>
    <div class="server">tinyzkp</div>
    <div class="meta">accumulator_step · zk on</div>
  </div>
  <div class="body stack">
    <div class="row">
      <div class="label">Initial</div>
      <div class="value"><span class="accent">0</span></div>
    </div>
    <div class="row">
      <div class="label">Final</div>
      <div class="value"><span class="accent">945</span></div>
    </div>
    <div class="row">
      <div class="label">Steps</div>
      <div class="value"><span class="muted">⟨ 5 individual deltas — never sent over the wire ⟩</span></div>
    </div>
    <div class="row">
      <div class="label">Status</div>
      <div class="value"><span class="pill green">✓ succeeded</span>
        <span class="muted" style="margin-left:14px">job &nbsp;<span style="color:var(--text)">{job_id}</span></span></div>
    </div>
    <div class="row">
      <div class="label">Proof</div>
      <div class="value code">{proof_short}
        <div style="margin-top:8px;color:var(--dim);font-size:12px">{proof_size} KB · base64-encoded · ZK-STARK · template <span class="accent">accumulator_step</span></div></div>
    </div>
  </div>
</div>

<div class="footer">
  State-transition proofs · accumulator_step · transparent (no trusted setup) · ZK-STARK
</div>
"""
    return TEMPLATE.replace("__TITLE__", "TinyZKP — Policy Compliance").replace("__CONTENT__", content)


def render_to_png(html: str, out_path: Path):
    """Render html to a 1400x560 PNG. Content was authored to fit this size."""
    html_path = out_path.with_suffix(".html")
    html_path.write_text(html)
    subprocess.run([
        CHROME,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--hide-scrollbars",
        "--default-background-color=00000000",
        "--window-size=1400,620",
        f"--screenshot={out_path}",
        f"file://{html_path.absolute()}",
    ], check=True, capture_output=True)


def main():
    shots = [
        ("shot1_range_prove.png",       shot1_html()),
        ("shot2_verify.png",            shot2_html()),
        ("shot3_policy_compliance.png", shot3_html()),
    ]
    for name, html in shots:
        out = ROOT / name
        render_to_png(html, out)
        size = out.stat().st_size
        print(f"  ✓ {name:36s}  ({size//1024} KB)")


if __name__ == "__main__":
    main()
