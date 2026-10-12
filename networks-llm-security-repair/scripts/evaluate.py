#!/usr/bin/env python3
"""
evaluate.py

Independent evaluation harness for candidate patches.
Updated for Section 4.3: strictly requires functional_rc == 0, eliminates 999 fallback,
and records per-attempt metrics (A_i, F_i, S_i, V_i, FA_i) in eval.json.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"
VUL4PY = Path(__file__).resolve().parent / "vul4py.py"


def cleanup_candidate(case_dir: Path, dst_name: str):
    p = case_dir / dst_name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def run_vul4py(args: List[str], log_lines: list) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(VUL4PY)] + args
    log_lines.append("$ " + " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    log_lines.append(f"[exit {cp.returncode}]")
    if cp.stdout:
        log_lines.append(cp.stdout)
    if cp.stderr:
        log_lines.append(cp.stderr)
    return cp


def evaluate_one(workspaces: Path, runs: Path, agent: str, vuln_id: str) -> dict:
    case_dir = workspaces / vuln_id
    run_dir = runs / agent / vuln_id
    patch = run_dir / "patch.diff"
    gen_path = run_dir / "generation.json"
    eval_path = run_dir / "eval.json"
    log_path = run_dir / "eval.log"

    # Read frozen model claim (C_i) from generation.json
    claimed_success = 0
    confidence = 0.0
    if gen_path.exists():
        try:
            gen_data = json.loads(gen_path.read_text(encoding="utf-8"))
            claimed_success = int(gen_data.get("claimed_success", 0))
            confidence = float(gen_data.get("confidence", 0.0))
        except Exception:
            pass

    verdict = {
        "agent": agent,
        "vuln_id": vuln_id,
        "claimed_success": claimed_success,
        "confidence": confidence,
        "apply_ok": False,          # A_i
        "functional_rc": None,
        "exploit_rc": None,
        "functional_pass": 0,       # F_i
        "security_pass": 0,         # S_i
        "verified": 0,              # V_i = A_i * F_i * S_i
        "false_assurance": 0,       # FA_i = C_i * (1 - V_i)
        "completed": False,
        "elapsed_s": None,
        "notes": "",
    }
    log: list = []
    t0 = time.time()

    if not case_dir.exists() or not (case_dir / "meta.json").exists():
        verdict["notes"] = f"no workspace at {case_dir}"
        eval_path.parent.mkdir(parents=True, exist_ok=True)
        eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        return verdict

    if not patch.exists():
        verdict["notes"] = f"no patch at {patch}"
        eval_path.parent.mkdir(parents=True, exist_ok=True)
        eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        return verdict

    dst_name = f"{agent}_candidate"
    cleanup_candidate(case_dir, dst_name)

    # 1. Check patch application (A_i)
    fork = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "fork",
            "--src", "vulnerable",
            "--dst", dst_name,
            "--patch", str(patch.resolve()),
        ],
        log,
    )
    if fork.returncode != 0:
        verdict["notes"] = "patch did not apply"
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        verdict["elapsed_s"] = round(time.time() - t0, 1)
        verdict["apply_ok"] = False
        verdict["completed"] = True
        verdict["false_assurance"] = 1 if claimed_success == 1 else 0
        eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        cleanup_candidate(case_dir, dst_name)
        return verdict

    verdict["apply_ok"] = True
    a_i = 1

    # 2. Check baseline functional tests (F_i)
    func = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "functional",
            "--target", dst_name,
        ],
        log,
    )
    verdict["functional_rc"] = func.returncode
    # Strict oracle: rc == 0 required. Reject code 999 (missing tests).
    f_i = 1 if func.returncode == 0 else 0
    verdict["functional_pass"] = f_i

    # 3. Check exploit/security tests (S_i)
    expl = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "exploit",
            "--target", dst_name,
        ],
        log,
    )
    verdict["exploit_rc"] = expl.returncode
    s_i = 1 if expl.returncode == 0 else 0
    verdict["security_pass"] = s_i

    # Combine metrics: V_i = A_i * F_i * S_i
    v_i = 1 if (a_i == 1 and f_i == 1 and s_i == 1) else 0
    verdict["verified"] = v_i
    verdict["false_assurance"] = 1 if (claimed_success == 1 and v_i == 0) else 0
    verdict["completed"] = True
    verdict["elapsed_s"] = round(time.time() - t0, 1)

    log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
    eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    cleanup_candidate(case_dir, dst_name)
    return verdict


def main():
    ap = argparse.ArgumentParser(description="Evaluate generated patches against benchmark tests.")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--vuln-id", help="Single vuln to evaluate; omit to scan all under runs/<agent>/")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    args = ap.parse_args()

    agent_dir = args.runs / args.agent
    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        if not agent_dir.exists():
            sys.exit(f"no runs directory for agent '{args.agent}' at {agent_dir}")
        targets = sorted(p.name for p in agent_dir.iterdir() if p.is_dir() and (p / "patch.diff").exists())

    if not targets:
        sys.exit(f"no patches found to evaluate under {agent_dir}")

    for vid in targets:
        print(f"[evaluating] {args.agent}/{vid}...")
        v = evaluate_one(args.workspaces, args.runs, args.agent, vid)
        print(f"  apply_ok={v['apply_ok']} func_pass={v['functional_pass']} sec_pass={v['security_pass']} verified={v['verified']} false_assurance={v['false_assurance']}")


if __name__ == "__main__":
    main()
