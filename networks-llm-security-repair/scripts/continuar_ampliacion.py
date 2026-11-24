#!/usr/bin/env python3
"""Run the closed five-case extension once and audit its pooled ten-case results."""
import argparse
import csv
import datetime
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from repair_common import benchmark_reference, sha256, validate_generation
from run_agent import SYSTEM_PROMPT, collect_context_files, load_meta

CAMPAIGN = 'luna-ampliacion-cinco-2026-11-23-r1'
PILOT = 'luna-cinco-2026-11-23-r2-audit-v3'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    scripts = root / 'experimento/scripts'
    plan = root / 'ampliacion-diez-2026-11-23'
    closed = json.loads((plan / 'seleccion-cerrada.json').read_text())
    original = json.loads((plan / 'protocolo.json').read_text())
    cases = closed['selected_new_cases']
    old_cases = closed['preserved_pilot_cases']
    assert len(cases) == len(set(cases)) == 5
    assert len(old_cases) == 5 and not set(cases).intersection(old_cases)
    for name, expected in closed['csv_sha256'].items():
        assert Path(name).name == name and sha256(plan / name) == expected
    with (plan / 'cinco-nuevos.csv').open(newline='') as stream:
        assert [row['vuln_id'] for row in csv.DictReader(stream)] == cases
    pilot = root / 'experimento/runs' / PILOT
    runs = root / 'experimento/runs' / CAMPAIGN
    for case in old_cases:
        for name, expected in original['pilot_artifact_hashes'][case].items():
            assert sha256(pilot / 'gpt' / case / name) == expected, (case, name)
        request = json.loads((pilot / 'gpt' / case / 'request.json').read_text())
        assert request['system'] == SYSTEM_PROMPT
    pending = []
    for case in cases:
        workspace = root / 'pilot-workspaces' / case
        assert sha256(workspace / 'meta.json') == closed['references'][case]['meta_sha256']
        for kind in ('functional', 'exploit'):
            benchmark_reference(workspace / 'logs', kind)
        assert collect_context_files(workspace, load_meta(workspace))
        if not (runs / 'gpt' / case).exists():
            pending.append(case)
    print('Closed selection verified; original pilot unchanged. Pending requests:', len(pending), flush=True)
    if args.check:
        print('Offline check complete; no API request made.')
        return 0
    env = os.environ.copy()
    env.pop('OPENROUTER_API_KEY', None)
    env.update(OPENAI_BASE_URL='https://api.openai.com/v1', MAKEFLAGS='-j1',
               CMAKE_BUILD_PARALLEL_LEVEL='1', OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1')
    if pending:
        from openai import OpenAI
        try:
            OpenAI(api_key=env.get('OPENAI_API_KEY'), base_url=env['OPENAI_BASE_URL'],
                   max_retries=0, timeout=30).models.retrieve('gpt-6-luna')
        except Exception as exc:
            print('Access check failed:', type(exc).__name__, 'HTTP', getattr(exc, 'status_code', None), flush=True)
            print('No generations started. Load your personal key privately in this terminal.')
            return 2
    runs.mkdir(parents=True, exist_ok=True)
    with (runs / '.execution.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        policy = dict(model='gpt-6-luna', cases=cases, preserved_pilot=PILOT,
                      max_completion_tokens=4096, reasoning_effort='low', service_tier='default',
                      automatic_generation_retries=0,
                      selection_sha256=sha256(plan / 'seleccion-cerrada.json'),
                      code_sha256={name: sha256(scripts / name) for name in
                                   ('run_agent.py', 'evaluate.py', 'repair_common.py', 'aggregate_results.py', 'continuar_ampliacion.py')})
        policy_path = runs / 'campaign_protocol.json'
        if policy_path.exists():
            assert json.loads(policy_path.read_text()) == policy, 'Campaign code/settings changed'
        else:
            with policy_path.open('x') as stream:
                json.dump(policy, stream, indent=2)
                stream.write('\n')
        for case in cases:
            folder = runs / 'gpt' / case
            if not folder.exists():
                print('GENERATING ONCE:', case, flush=True)
                subprocess.run(['nice', '-n', '10', sys.executable, str(scripts / 'run_agent.py'),
                                '--agent', 'gpt', '--model', 'gpt-6-luna', '--vuln-id', case,
                                '--workspaces', str(root / 'pilot-workspaces'), '--runs', str(runs)],
                               cwd=root, env=env, check=False)
            generation, error = validate_generation(folder)
            if generation is None:
                print('Incomplete generation retained; no retry:', case, error, flush=True)
                continue
            request = json.loads((folder / 'request.json').read_text())
            assert all(request.get(k) == v for k, v in
                       dict(model='gpt-6-luna', max_completion_tokens=4096,
                            reasoning_effort='low', service_tier='default', system=SYSTEM_PROMPT).items())
            alias = folder / 'llm_response.json'
            if not alias.exists():
                with alias.open('xb') as stream:
                    stream.write((folder / 'llm_response.txt').read_bytes())
            assert sha256(alias) == sha256(folder / 'llm_response.txt')
            if not (folder / 'eval.json').exists():
                if (folder / 'evaluation_evidence').exists():
                    print('Partial evaluation retained; needs review:', case, flush=True)
                    continue
                print('EVALUATING:', case, flush=True)
                subprocess.run(['nice', '-n', '10', sys.executable, str(scripts / 'evaluate.py'),
                                '--agent', 'gpt', '--vuln-id', case,
                                '--workspaces', str(root / 'pilot-workspaces'),
                                '--vul4py-root', str(root / 'benchmark'), '--runs', str(runs),
                                '--timeout', '1800'], cwd=root, env=env, check=False)
            if (folder / 'eval.json').exists():
                result = json.loads((folder / 'eval.json').read_text())
                print(json.dumps({k: result.get(k) for k in
                                  ('vuln_id', 'completed', 'claimed_success', 'confidence',
                                   'apply_ok', 'functional_pass', 'security_pass', 'verified', 'false_assurance', 'notes')}), flush=True)
        from aggregate_results import aggregate
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        reports = root / 'experimento/reports' / ('ampliacion-diez-' + stamp)
        reports.mkdir(parents=True, exist_ok=False)
        aggregate(runs, 'gpt', reports / 'cinco-nuevos.csv')
        aggregate(pilot, 'gpt', reports / 'cinco-originales.csv')
        pooled = root / 'experimento/runs' / ('diez-consolidados-' + stamp)
        (pooled / 'gpt').mkdir(parents=True, exist_ok=False)
        origins = {}
        for group, source, selected in [('original', pilot, old_cases), ('extension', runs, cases)]:
            for case in selected:
                source_case = source / 'gpt' / case
                if not source_case.exists():
                    raise RuntimeError('Missing attempt: ' + case)
                shutil.copytree(source_case, pooled / 'gpt' / case)
                origins[case] = dict(group=group, source=str(source_case),
                                     files={str(p.relative_to(source_case)): sha256(p)
                                            for p in source_case.rglob('*') if p.is_file()})
        for case in old_cases:
            for name, expected in original['pilot_artifact_hashes'][case].items():
                assert sha256(pilot / 'gpt' / case / name) == expected
        with (pooled / 'provenance.json').open('x') as stream:
            json.dump(dict(note='Byte-identical copies of ten distinct attempts; no new repetitions.', cases=origins), stream, indent=2)
        aggregate(pooled, 'gpt', reports / 'results.csv')
        print('REPORT_DIRECTORY:', reports, flush=True)
        print('POOLED_CAMPAIGN:', pooled, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
