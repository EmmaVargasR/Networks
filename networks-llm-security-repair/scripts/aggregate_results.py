#!/usr/bin/env python3
"""Audit records and compute metrics only for internally consistent observations."""
import argparse
import csv
import json
from pathlib import Path
import sys

from repair_common import sha256, validate_generation, write_json

HERE = Path(__file__).resolve().parent.parent


def observation(directory, agent):
    row = dict(vuln_id=directory.name, agent=agent, model=None, timestamp=None,
               claimed_success=None, confidence=None, apply_ok=None, functional_pass=None,
               security_pass=None, verified=None, false_assurance=None, latency_ms=None,
               input_tokens=None, output_tokens=None, total_tokens=None,
               completed=False, notes='')
    gen, error = validate_generation(directory)
    if gen is None:
        row['notes'] = error
        return row
    for key in ('model', 'timestamp', 'claimed_success', 'confidence', 'input_tokens', 'output_tokens', 'total_tokens'):
        row[key] = gen.get(key)
    row['latency_ms'] = round(gen['latency_s'] * 1000, 3) if isinstance(gen.get('latency_s'), (int, float)) else None
    try:
        ev = json.loads((directory / 'eval.json').read_text(encoding='utf-8'))
        if ev.get('schema_version') != 2 or ev.get('completed') is not True or ev.get('status') != 'complete':
            raise ValueError(ev.get('notes') or 'Evaluation incomplete or legacy format')
        if ev.get('generation_sha256') != sha256(directory / 'generation.json') or ev.get('patch_sha256') != sha256(directory / 'patch.diff'):
            raise ValueError('Evaluation belongs to a different generation/patch')
        if ev.get('claimed_success') != gen['claimed_success'] or ev.get('confidence') != gen['confidence']:
            raise ValueError('Evaluation claim/confidence mismatch')
        hashes = ev.get('evidence_hashes', {})
        if not hashes:
            raise ValueError('Evaluation evidence is missing')
        for name, expected in hashes.items():
            if Path(name).name != name or sha256(directory / 'evaluation_evidence' / name) != expected:
                raise ValueError('Evaluation evidence missing or changed')
        values = [ev.get(k) for k in ('apply_ok', 'functional_pass', 'security_pass')]
        if any(type(v) is not int or v not in (0, 1) for v in values):
            raise ValueError('Invalid verification indicators')
        a, f, s = values
        if not a and (f or s):
            raise ValueError('Tests cannot pass when patch was not applied')
        if a:
            checks = ev.get('checks', {})
            for kind, indicator in (('functional', f), ('exploit', s)):
                check = checks.get(kind, {})
                if check.get('status') not in ('pass', 'fail') or int(check['status'] == 'pass') != indicator:
                    raise ValueError('Missing or inconsistent completed test check')
        v = a * f * s
        fa = gen['claimed_success'] * (1 - v)
        if ev.get('verified') != v or ev.get('false_assurance') != fa:
            raise ValueError('Stored metrics disagree with recomputed metrics')
        row.update(apply_ok=a, functional_pass=f, security_pass=s, verified=v,
                   false_assurance=fa, completed=True, notes=ev.get('notes', ''))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        row['notes'] = str(exc)
    return row


def aggregate(runs_dir, agent, output_csv):
    output_csv = Path(output_csv)
    summary_path = output_csv.with_suffix('.summary.json')
    if output_csv.exists() or summary_path.exists():
        raise FileExistsError('Report exists; choose a new --output path')
    base = Path(runs_dir) / agent
    records = [observation(p, agent) for p in sorted(base.iterdir()) if p.is_dir()]
    good = [r for r in records if r['completed']]
    def metrics(rows):
        n = len(rows)
        claims = sum(r['claimed_success'] for r in rows)
        return dict(completed=n, positive_claims=claims,
                    verified_repairs=sum(r['verified'] for r in rows),
                    false_assurances=sum(r['false_assurance'] for r in rows),
                    VRR=sum(r['verified'] for r in rows) / n if n else None,
                    FAR=sum(r['false_assurance'] for r in rows) / claims if claims else None)
    summary = dict(total_records=len(records), incomplete=len(records) - len(good),
                   **metrics(good), by_model={m: metrics([r for r in good if r['model'] == m])
                                             for m in sorted({r['model'] for r in good})})
    # Global metrics are descriptive; model comparisons use by_model.
    if not records:
        raise ValueError('No attempt directories found')
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open('x', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    write_json(summary_path, summary)
    print(json.dumps(summary, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=Path, required=True)
    parser.add_argument('--agent', default='gpt')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        aggregate(args.runs, args.agent, args.output)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
