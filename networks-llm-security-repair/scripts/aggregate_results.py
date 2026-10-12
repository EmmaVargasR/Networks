#!/usr/bin/env python3
"""
aggregate_results.py

Aggregates per-attempt repair evaluation records and computes
Verified Repair Rate (VRR) and False Assurance Rate (FAR)
strictly as defined in Section 3 of the lab specification.
Generates results.csv and summary statistics.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RUNS = HERE / "runs"
RESULTS_CSV = HERE / "results.csv"


def aggregate(runs_dir: Path, agent: str, output_csv: Path) -> dict:
    agent_dir = runs_dir / agent
    if not agent_dir.exists():
        sys.exit(f"Directory not found for agent '{agent}': {agent_dir}")

    records = []
    cases = sorted([p for p in agent_dir.iterdir() if p.is_dir()])

    for case in cases:
        vuln_id = case.name
        gen_file = case / "generation.json"
        eval_file = case / "eval.json"

        # Defaults for missing/unrun files
        gen_data = {}
        eval_data = {}

        if gen_file.exists():
            try:
                gen_data = json.loads(gen_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        if eval_file.exists():
            try:
                eval_data = json.loads(eval_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        claimed_success = int(eval_data.get("claimed_success", gen_data.get("claimed_success", 0)))
        confidence = float(eval_data.get("confidence", gen_data.get("confidence", 0.0)))
        apply_ok = int(bool(eval_data.get("apply_ok", False)))
        func_pass = int(eval_data.get("functional_pass", 0))
        sec_pass = int(eval_data.get("security_pass", 0))
        verified = int(eval_data.get("verified", 0))
        false_assurance = int(eval_data.get("false_assurance", 0))
        latency_s = gen_data.get("latency_s", None)
        model = gen_data.get("model", "unknown")
        total_tokens = gen_data.get("total_tokens", None)
        timestamp = gen_data.get("timestamp", "")
        completed = eval_data.get("completed", False)

        records.append({
            "vuln_id": vuln_id,
            "agent": agent,
            "model": model,
            "timestamp": timestamp,
            "claimed_success": claimed_success,
            "confidence": confidence,
            "apply_ok": apply_ok,
            "functional_pass": func_pass,
            "security_pass": sec_pass,
            "verified": verified,
            "false_assurance": false_assurance,
            "latency_s": latency_s,
            "total_tokens": total_tokens,
            "completed": completed,
            "notes": eval_data.get("notes", ""),
        })

    # Write results.csv
    fieldnames = [
        "vuln_id", "agent", "model", "timestamp",
        "claimed_success", "confidence", "apply_ok",
        "functional_pass", "security_pass", "verified",
        "false_assurance", "latency_s", "total_tokens",
        "completed", "notes"
    ]
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    # Compute metrics strictly for completed attempts
    completed_records = [r for r in records if r["completed"]]
    n_completed = len(completed_records)
    n_total = len(records)

    sum_v = sum(r["verified"] for r in completed_records)
    sum_c = sum(r["claimed_success"] for r in completed_records)
    sum_fa = sum(r["false_assurance"] for r in completed_records)

    vrr = (sum_v / n_completed) if n_completed > 0 else 0.0

    if sum_c == 0:
        far_str = "undefined (no positive repair claims)"
        far_val = None
    else:
        far_val = sum_fa / sum_c
        far_str = f"{far_val:.4f} ({sum_fa}/{sum_c})"

    stats = {
        "agent": agent,
        "total_attempts": n_total,
        "completed_observations": n_completed,
        "sum_verified": sum_v,
        "sum_claimed": sum_c,
        "sum_false_assurance": sum_fa,
        "vrr": vrr,
        "far_display": far_str,
        "far_numeric": far_val,
        "csv_path": str(output_csv),
    }

    print("\n" + "="*50)
    print("EXPERIMENTAL METRICS SUMMARY (Section 3)")
    print("="*50)
    print(f"Agent:                  {agent}")
    print(f"Total attempts:         {n_total}")
    print(f"Completed observations: {n_completed}")
    print(f"Positive claims (C):    {sum_c}")
    print(f"Verified repairs (V):   {sum_v}")
    print(f"False assurances (FA):  {sum_fa}")
    print(f"VRR (Verified Rate):    {vrr:.4f} ({sum_v}/{n_completed})")
    print(f"FAR (False Assurance):  {far_str}")
    print(f"Report written to:      {output_csv}")
    print("="*50 + "\n")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Aggregate evaluation results and compute VRR / FAR.")
    parser.add_argument("--agent", default="gpt", help="Target agent directory under runs/ (default: gpt)")
    parser.add_argument("--runs", type=Path, default=RUNS, help="Directory containing run outputs")
    parser.add_argument("--output", type=Path, default=RESULTS_CSV, help="Destination CSV file path")
    args = parser.parse_args()

    aggregate(args.runs, args.agent, args.output)


if __name__ == "__main__":
    main()
