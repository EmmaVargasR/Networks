#!/usr/bin/env python3
"""Resume the five-case campaign once, using an existing key from the terminal."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from repair_common import benchmark_reference, validate_generation

CASES = (
    'CVE-2021-32839', 'CVE-2022-29217', 'CVE-2023-26302',
    'CVE-2023-32681', 'CVE-2023-37271',
)
CAMPAIGN = 'luna-cinco-2026-11-23-r2-audit-v3'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Offline checks only; no API requests')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    scripts = root / 'experimento/scripts'
    runs = root / 'experimento/runs' / CAMPAIGN
    workspaces = root / 'pilot-workspaces'
    manifest = root / 'lotes/piloto-cinco.csv'
    with manifest.open(newline='') as stream:
        selected = tuple(row['vuln_id'] for row in csv.DictReader(stream))
    if selected != CASES:
        raise SystemExit('Unexpected case manifest; no requests made.')

    pending = []
    for case in CASES:
        for kind in ('functional', 'exploit'):
            benchmark_reference(workspaces / case / 'logs', kind)
        folder = runs / 'gpt' / case
        if folder.exists():
            generation, error = validate_generation(folder)
            if generation is None:
                raise SystemExit(f'Frozen attempt needs review: {case}: {error}. No retry.')
            request = json.loads((folder / 'request.json').read_text())
            if (request.get('model') != 'gpt-6-luna'
                    or request.get('max_completion_tokens') != 4096
                    or request.get('reasoning_effort') != 'low'):
                raise SystemExit(f'Unexpected frozen generation settings: {case}')
            print(case, 'frozen generation retained', flush=True)
        else:
            pending.append(case)
            print(case, 'pending generation', flush=True)
    print('Offline references valid: 5. Pending paid requests:', len(pending), flush=True)
    if args.check:
        print('Offline check complete. No API requests made.')
        return 0

    env = os.environ.copy()
    env.pop('OPENROUTER_API_KEY', None)
    env['OPENAI_BASE_URL'] = 'https://api.openai.com/v1'
    env.update(MAKEFLAGS='-j1', CMAKE_BUILD_PARALLEL_LEVEL='1',
               OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1')
    if pending:
        key = env.get('OPENAI_API_KEY', '')
        if not key or any(char.isspace() for char in key):
            raise SystemExit('Load your existing personal OPENAI_API_KEY privately in this terminal first.')
        from openai import OpenAI, APIStatusError
        try:
            client = OpenAI(api_key=key, base_url=env['OPENAI_BASE_URL'],
                            max_retries=0, timeout=30)
            client.models.retrieve('gpt-6-luna')
        except APIStatusError as exc:
            raise SystemExit(f'Authentication/access check failed: {type(exc).__name__}, HTTP {exc.status_code}. No generations started.')
        except Exception as exc:
            raise SystemExit(f'Connection check failed: {type(exc).__name__}. No generations started.')

    policy = {
        'model': 'gpt-6-luna', 'max_completion_tokens': 4096,
        'reasoning_effort': 'low', 'service_tier': 'default',
        'automatic_generation_retries': 0, 'cases': list(CASES),
        'manifest_sha256': digest(manifest),
        'generator_sha256': digest(scripts / 'run_agent.py'),
        'evaluator_sha256': digest(scripts / 'evaluate.py'),
        'evaluation_protocol': 'v3-pristine-relative-identities',
    }
    policy_path = runs / 'campaign_protocol.json'
    if policy_path.exists():
        if json.loads(policy_path.read_text()) != policy:
            raise SystemExit('Campaign configuration changed; inspect before continuing.')
    else:
        with policy_path.open('x') as stream:
            json.dump(policy, stream, indent=2)
            stream.write('\n')

    for case in CASES:
        folder = runs / 'gpt' / case
        if not folder.exists():
            print('\nGENERATING ONCE:', case, flush=True)
            command = [sys.executable, str(scripts / 'run_agent.py'), '--agent', 'gpt',
                       '--model', 'gpt-6-luna', '--vuln-id', case,
                       '--workspaces', str(workspaces), '--runs', str(runs)]
            result = subprocess.run(['nice', '-n', '10', *command], cwd=root, env=env)
            if result.returncode:
                raise SystemExit(f'{case}: generation failed and was retained. Do not regenerate.')
        generation, error = validate_generation(folder)
        if generation is None:
            raise SystemExit(f'{case}: invalid frozen generation: {error}. No retry.')
        out = folder / 'eval.json'
        if out.exists():
            print('Existing evaluation retained:', case, flush=True)
        else:
            if (folder / 'evaluation_evidence').exists():
                raise SystemExit(f'{case}: unfinished evaluation evidence exists; inspect before continuing.')
            print('EVALUATING:', case, flush=True)
            command = [sys.executable, str(scripts / 'evaluate.py'), '--agent', 'gpt',
                       '--vuln-id', case, '--workspaces', str(workspaces),
                       '--vul4py-root', str(root / 'benchmark'), '--runs', str(runs),
                       '--timeout', '1800']
            result = subprocess.run(['nice', '-n', '10', *command], cwd=root, env=env)
            if result.returncode:
                raise SystemExit(f'{case}: evaluation incomplete; evidence retained. Inspect before continuing.')
        verdict = json.loads(out.read_text())
        print(json.dumps({key: verdict.get(key) for key in (
            'vuln_id', 'completed', 'claimed_success', 'confidence',
            'functional_pass', 'security_pass', 'verified', 'false_assurance',
        )}), flush=True)
        if not verdict.get('completed'):
            raise SystemExit(f'{case}: incomplete evaluation, not counted as a repair failure.')

    report = root / 'experimento/reports/piloto-cinco-audit-v3.csv'
    if report.exists():
        print('Existing report retained:', report)
    else:
        subprocess.run([sys.executable, str(scripts / 'aggregate_results.py'),
                        '--agent', 'gpt', '--runs', str(runs), '--output', str(report)],
                       cwd=root, env=env, check=True)
    print('Campaign finished:', runs)
    print('Report:', report)
    return 0


if __name__ == '__main__':
    sys.exit(main())
