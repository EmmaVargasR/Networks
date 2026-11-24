#!/usr/bin/env python3
"""Freeze an eligible extension baseline and update its prospective selection log."""
import argparse
import csv
import datetime
import json
from pathlib import Path
import re
import shutil
import subprocess

from repair_common import benchmark_reference, sha256
from run_agent import collect_context_files, load_meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'CVE-\d{4}-\d+', args.case):
        raise SystemExit('Unexpected case identifier')
    root = Path(__file__).resolve().parents[2]
    plan = root / 'ampliacion-diez-2026-11-23'
    selection = plan / 'seleccion.tsv'
    with selection.open(newline='') as stream:
        reader = csv.DictReader(stream, delimiter='\t')
        fields = reader.fieldnames
        rows = list(reader)
    matching = [row for row in rows if row['case_id'] == args.case]
    if len(matching) != 1:
        raise SystemExit('Case is not uniquely present in the registered plan')
    case = root / 'pilot-workspaces' / args.case
    references = {kind: benchmark_reference(case / 'logs', kind)
                  for kind in ('functional', 'exploit')}
    meta = load_meta(case)
    context = collect_context_files(case, meta)
    if not context:
        raise SystemExit('No eligible source context under the unchanged generation limits')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    snapshot = root / 'evidencias/ampliacion' / args.case / ('validado-' + stamp)
    snapshot.mkdir(parents=True, exist_ok=False)
    shutil.copy2(case / 'meta.json', snapshot / 'meta.json')
    shutil.copytree(case / 'logs', snapshot / 'logs')
    shutil.copy2(root / 'pilot-workspaces/scan_report.tsv', snapshot / 'scan_report.tsv')
    shutil.copy2(selection, snapshot / 'seleccion-anterior.tsv')
    for side in ('vulnerable', 'fixed'):
        result = subprocess.run([str(case / side / '.venv/bin/python'), '-m', 'pip', 'freeze'],
                                capture_output=True, text=True, check=True, timeout=30)
        (snapshot / f'{side}-requirements.freeze.txt').write_text(result.stdout)
    record = {
        'case': args.case, 'decision': 'ELIGIBLE', 'created_utc': stamp,
        'context': [{'path': name, 'characters': len(text)} for name, text in context],
        'reference_counts': {kind: {key: value[key] for key in ('passed', 'failed', 'errors', 'skipped')}
                             for kind, value in references.items()},
        'meta_sha256': sha256(case / 'meta.json'), 'model_calls': 0,
    }
    (snapshot / 'eligibility.json').write_text(json.dumps(record, indent=2) + '\n')
    matching[0].update(baseline_status='VALIDATED', decision='ELIGIBLE',
                       reason='Strict references validated; source context eligible; evidence and dependencies frozen')
    with selection.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t')
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(record, indent=2))
    print('Snapshot:', snapshot)


if __name__ == '__main__':
    main()
