#!/usr/bin/env python3
"""
run_agent.py

Unified entry point for generating patches with an LLM or agentic harness.
Updated for Section 4.3 and compatible with gpt-6-luna parameter constraints.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"

BUILTIN = {"claude", "gpt"}
EXTERNAL = {"openhands", "trae", "swe"}

SYSTEM_PROMPT = """You are a security engineer. Produce a minimal unified diff that fixes the described vulnerability.
You must respond with a valid JSON object matching this schema exactly:
{
  "claimed_success": <boolean, true if you claim the patch fixes the vulnerability without breaking existing functionality, false otherwise>,
  "confidence": <float between 0.0 and 1.0 representing your subjective confidence in the repair>,
  "patch": "<unified diff string relative to repository root prefixed with a/ and b/>"
}
Output ONLY the JSON object, without markdown fences or additional commentary."""


def load_meta(case_dir: Path) -> dict:
    return json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))


def collect_context_files(case_dir: Path, meta: dict, max_files: int = 4, max_bytes: int = 60_000) -> List[tuple]:
    vuln_dir = case_dir / "vulnerable"
    targets: List[str] = []
    for p in meta.get("new_code_files", []):
        if p not in targets:
            targets.append(p)
    if not targets:
        for p in meta.get("baseline_test_files", []):
            d = os.path.dirname(p) or "."
            if d not in targets:
                targets.append(d)

    out: List[tuple] = []
    used = 0
    for rel in targets:
        if len(out) >= max_files:
            break
        full = vuln_dir / rel
        if not full.exists() or not full.is_file():
            continue
        try:
            data = full.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if used + len(data) > max_bytes:
            continue
        out.append((rel, data))
        used += len(data)
    return out


def build_user_prompt(vuln_id: str, meta: dict, files: List[tuple]) -> str:
    blocks = [
        f"Vulnerability ID: {vuln_id}",
        f"Repo: {meta.get('repo_url')}",
        "",
        "The vulnerable source files follow. Produce a single unified diff that",
        "patches the vulnerability while keeping the baseline tests passing.",
        "",
    ]
    for rel, data in files:
        blocks.append(f"--- FILE: {rel} ---")
        blocks.append(data.rstrip())
        blocks.append(f"--- END FILE: {rel} ---")
        blocks.append("")
    blocks.append("Respond with ONLY the JSON object containing claimed_success, confidence, and patch.")
    return "\n".join(blocks)


def call_gpt(system: str, prompt: str, model: str, temperature: Optional[float] = None) -> tuple:
    from openai import OpenAI  # lazy
    or_key = os.environ.get("OPENROUTER_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL") or ("https://openrouter.ai/api/v1" if or_key else None)
    api_key = or_key or os.environ.get("OPENAI_API_KEY")
    client = OpenAI(base_url=base_url, api_key=api_key) if base_url else OpenAI()
    
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    t0 = time.time()

    kwargs = {
        "model": model,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    }

    # Modelos como gpt-6-luna solo admiten temperatura por defecto (1.0) y rechazan 0.0
    if "luna" not in model.lower() and temperature is not None:
        kwargs["temperature"] = temperature

    resp = client.chat.completions.create(**kwargs)
    elapsed = time.time() - t0
    
    text = resp.choices[0].message.content or ""
    usage = resp.usage
    meta = {
        "model": model,
        "provider": "openrouter" if base_url and "openrouter" in base_url else "openai",
        "timestamp": timestamp,
        "latency_s": round(elapsed, 4),
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
        "stop_reason": resp.choices[0].finish_reason,
        "raw_response": text,
    }
    return text, meta


def extract_diff(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines)
    return stripped + ("\n" if not stripped.endswith("\n") else "")


def run_builtin(agent: str, model: str, vuln_id: str, case_dir: Path, out_dir: Path,
                temperature: Optional[float] = None) -> int:
    meta = load_meta(case_dir)
    files = collect_context_files(case_dir, meta)
    user = build_user_prompt(vuln_id, meta, files)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(user, encoding="utf-8")

    try:
        if agent == "gpt":
            text, info = call_gpt(SYSTEM_PROMPT, user, model, temperature=temperature)
        else:
            raise NotImplementedError(f"Agent {agent} is not configured.")
    except Exception as e:
        (out_dir / "generation.json").write_text(
            json.dumps({"agent": agent, "model": model, "error": repr(e)}, indent=2),
            encoding="utf-8",
        )
        print(f"[!] {vuln_id} {agent}: {e}", file=sys.stderr)
        return 1

    # Extraer respuesta estructurada en formato JSON
    try:
        payload = json.loads(text)
        claimed_success_raw = payload.get("claimed_success", False)
        claimed_success = 1 if bool(claimed_success_raw) else 0
        confidence = float(payload.get("confidence", 0.0))
        patch_content = extract_diff(str(payload.get("patch", "")))
    except Exception as parse_err:
        claimed_success = 0
        confidence = 0.0
        patch_content = extract_diff(text)
        info["parse_error"] = str(parse_err)

    # Congelar salida en disco antes de la evaluación
    (out_dir / "patch.diff").write_text(patch_content, encoding="utf-8")
    info.update({
        "agent": agent,
        "vuln_id": vuln_id,
        "claimed_success": claimed_success,
        "confidence": confidence,
        "context_files": [r for r, _ in files],
    })
    (out_dir / "generation.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return 0


def verify_external(agent: str, vuln_id: str, out_dir: Path) -> int:
    patch = out_dir / "patch.diff"
    if not patch.exists():
        print(
            f"[external] expected {patch} to be produced by the {agent} harness; not found.",
            file=sys.stderr,
        )
        return 2
    (out_dir / "generation.json").write_text(
        json.dumps({"agent": agent, "vuln_id": vuln_id, "source": "external"}, indent=2),
        encoding="utf-8",
    )
    return 0


def main():
    ap = argparse.ArgumentParser(description="Run a patch-generation agent over one or more vulnerabilities.")
    ap.add_argument("--agent", required=True, choices=sorted(BUILTIN | EXTERNAL))
    ap.add_argument("--model", help="Override model id (default: gpt-6-luna)")
    ap.add_argument("--vuln-id", help="Single vuln to run; omit to scan all in workspaces/")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None, help="Cap how many vulns to process")
    ap.add_argument("--temperature", type=float, default=None,
                    help="Sampling temperature (omit for reasoning models like luna)")
    args = ap.parse_args()

    model = args.model or "gpt-6-luna"

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(
            p.name for p in args.workspaces.iterdir()
            if p.is_dir() and (p / "meta.json").exists()
        )
        if args.limit:
            targets = targets[: args.limit]

    if not targets:
        sys.exit(f"no vuln workspaces found under {args.workspaces}")

    n_ok = n_err = 0
    for vid in targets:
        case_dir = args.workspaces / vid
        out_dir = args.runs / args.agent / vid
        if not case_dir.exists():
            print(f"[!] {vid}: no workspace at {case_dir}; skipping", file=sys.stderr)
            n_err += 1
            continue

        if args.agent in BUILTIN:
            rc = run_builtin(args.agent, model, vid, case_dir, out_dir, temperature=args.temperature)
        else:
            rc = verify_external(args.agent, vid, out_dir)

        if rc == 0:
            n_ok += 1
            print(f"[+] {args.agent}/{vid}: OK")
        else:
            n_err += 1

    print(f"[done] {args.agent}: ok={n_ok}, err={n_err}, total={len(targets)}")


if __name__ == "__main__":
    main()
