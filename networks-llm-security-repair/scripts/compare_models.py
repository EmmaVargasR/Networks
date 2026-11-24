#!/usr/bin/env python3
"""Audit two campaigns on the same cases without changing either campaign."""
import csv
import json
from pathlib import Path
import statistics

from aggregate_results import observation
from repair_common import sha256, write_json


def summarize(rows):
    complete = [row for row in rows if row['completed']]
    claims = sum(row['claimed_success'] for row in complete)
    verified = sum(row['verified'] for row in complete)
    false = sum(row['false_assurance'] for row in complete)
    latencies = [row['latency_ms'] for row in complete if row['latency_ms'] is not None]
    return dict(total_records=len(rows), completed=len(complete),
                incomplete=len(rows) - len(complete), positive_claims=claims,
                applied=sum(row['apply_ok'] for row in complete),
                functional_pass=sum(row['functional_pass'] for row in complete),
                security_pass=sum(row['security_pass'] for row in complete),
                verified_repairs=verified, false_assurances=false,
                VRR=verified / len(complete) if complete else None,
                FAR=false / claims if claims else None,
                median_latency_ms=statistics.median(latencies) if latencies else None)


def pair_rows(cases, left, right):
    if len(cases) != len(set(cases)):
        raise ValueError('Duplicate selected case')
    indexes = []
    for rows in (left, right):
        index = {row['vuln_id']: row for row in rows}
        if len(index) != len(rows) or set(index) != set(cases):
            raise ValueError('Campaign cases do not match the declared paired sample')
        indexes.append(index)
    return [(case, indexes[0][case], indexes[1][case]) for case in cases]


def compare(cases, luna, sol, output):
    luna, sol, output = Path(luna), Path(sol), Path(output)
    left = [observation(luna / 'gpt' / case, 'gpt') for case in cases]
    right = [observation(sol / 'gpt' / case, 'gpt') for case in cases]
    paired = pair_rows(cases, left, right)
    output.mkdir(parents=True, exist_ok=False)
    source_hashes = {}
    for label, source, rows in [('luna', luna, left), ('sol62', sol, right)]:
        with (output / (label + '.csv')).open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        source_hashes[label] = {case: {str(path.relative_to(source / 'gpt' / case)): sha256(path)
                                      for path in (source / 'gpt' / case).rglob('*') if path.is_file()}
                                for case in cases}
    with (output / 'results.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['campaign', *left[0]])
        writer.writeheader()
        for label, rows in [('luna', left), ('sol62', right)]:
            writer.writerows(dict(campaign=label, **row) for row in rows)
    columns = ['vuln_id']
    measurements = ('completed', 'claimed_success', 'confidence', 'apply_ok',
                    'functional_pass', 'security_pass', 'verified', 'false_assurance', 'notes')
    columns += [label + '_' + key for label in ('luna', 'sol62') for key in measurements]
    with (output / 'paired_cases.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for case, a, b in paired:
            row = {'vuln_id': case}
            row.update({'luna_' + key: a[key] for key in measurements})
            row.update({'sol62_' + key: b[key] for key in measurements})
            writer.writerow(row)
    summary = {'note': 'Descriptive paired comparison; one response per model and case. No pooled model-performance claim.',
               'distinct_cases': len(cases), 'total_records': len(left) + len(right),
               'by_campaign': {'gpt-6-luna': summarize(left), 'gpt-6.2-sol': summarize(right)},
               'both_complete': sum(a['completed'] and b['completed'] for _, a, b in paired)}
    write_json(output / 'summary.json', summary)
    write_json(output / 'source_hashes.json', source_hashes)
    print(json.dumps(summary, indent=2), flush=True)
    print('REPORT_DIRECTORY:', output, flush=True)
    return summary
