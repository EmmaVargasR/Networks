#!/usr/bin/env python3
"""Execute the declared ten-case Sol comparison while preserving all Luna files."""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from aggregate_results import observation
from compare_models import compare
from repair_common import benchmark_reference, sha256, validate_generation, write_json
from run_agent import SYSTEM_PROMPT, build_user_prompt, collect_context_files, load_meta

PLAN = 'comparacion-luna-sol62-2026-11-24'
MODEL = 'gpt-6.2-sol'


def inventory(folder):
    return {str(path.relative_to(folder)): sha256(path)
            for path in folder.rglob('*') if path.is_file()}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_inputs(root, plan, luna):
    cases = plan['cases_in_order']
    require(len(cases) == len(set(cases)) == 10, 'Expected ten distinct cases')
    require(plan['model'] == MODEL and plan['runs_per_model_case'] == 1, 'Unexpected model or repetition policy')
    require(subprocess.check_output(['git', '-C', str(root / 'benchmark'), 'rev-parse', 'HEAD'], text=True).strip()
            == plan['benchmark_commit'], 'Benchmark commit changed')
    for case in cases:
        folder, workspace = luna / 'gpt' / case, root / 'pilot-workspaces' / case
        record = plan['records'][case]
        for name, expected in record['frozen_luna_files'].items():
            require(sha256(folder / name) == expected, 'Luna artifact changed: ' + case + '/' + name)
        require(observation(folder, 'gpt')['completed'], 'Luna evidence invalid: ' + case)
        require(sha256(workspace / 'meta.json') == record['meta_sha256'], 'Case configuration changed: ' + case)
        request = json.loads((folder / 'request.json').read_text())
        require(request['system'] == SYSTEM_PROMPT, 'System prompt changed')
        require(request['user'] == build_user_prompt(case, load_meta(workspace),
                                                    collect_context_files(workspace, load_meta(workspace))),
                'Source context or user prompt changed: ' + case)
        for kind in ('functional', 'exploit'):
            benchmark_reference(workspace / 'logs', kind)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Offline checks only')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    plan_file = root / PLAN / 'protocolo.json'
    plan = json.loads(plan_file.read_text())
    scripts, workspaces = root / 'experimento/scripts', root / 'pilot-workspaces'
    luna = root / plan['existing_luna_campaign']
    runs = root / 'experimento/runs' / plan['campaign_name']
    cases = check_inputs(root, plan, luna)
    require(runs.resolve() != luna.resolve(), 'Campaigns must be separate')
    pending = [case for case in cases if not (runs / 'gpt' / case).exists()]
    print('Ten cases and identical prompts validated. Frozen Luna artifacts unchanged.', flush=True)
    print('Pending Sol generations:', len(pending), flush=True)
    print('Sol output directory:', runs, flush=True)
    if args.check:
        print('Offline check complete; no API calls or generation writes.')
        return 0
    require(shutil.disk_usage(root).free >= 4 * 1024**3, 'Less than 4 GiB disk space available')
    env = os.environ.copy()
    env.pop('OPENROUTER_API_KEY', None)
    env.update(OPENAI_BASE_URL='https://api.openai.com/v1', MAKEFLAGS='-j1',
               CMAKE_BUILD_PARALLEL_LEVEL='1', OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1')
    if pending:
        key = env.get('OPENAI_API_KEY', '')
        require(bool(key) and not any(c.isspace() for c in key), 'Load your personal key privately in this terminal')
        from openai import OpenAI
        try:
            OpenAI(api_key=key, base_url=env['OPENAI_BASE_URL'], max_retries=0,
                   timeout=30).models.retrieve(MODEL)
        except Exception as exc:
            print('Model-access check failed:', type(exc).__name__, 'HTTP', getattr(exc, 'status_code', None), flush=True)
            return 2
    runs.mkdir(parents=True, exist_ok=True)
    with (runs / '.execution.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        policy = dict(model=MODEL, cases=cases, max_completion_tokens=4096,
                      reasoning_effort='low', service_tier='default', automatic_retries=0,
                      protocol_sha256=sha256(plan_file),
                      code_sha256={name: sha256(scripts / name) for name in
                                   ('run_agent.py', 'evaluate.py', 'repair_common.py', 'aggregate_results.py',
                                    'compare_models.py', 'continuar_comparacion_sol.py')})
        policy_file = runs / 'execution_policy.json'
        if policy_file.exists():
            require(json.loads(policy_file.read_text()) == policy, 'Campaign code or settings changed')
        else:
            write_json(policy_file, policy)
        frozen_file = runs / 'luna_integrity_before.json'
        if frozen_file.exists():
            frozen = json.loads(frozen_file.read_text())
        else:
            frozen = inventory(luna)
            write_json(frozen_file, frozen)
        require(inventory(luna) == frozen, 'Luna inventory changed before execution')
        for case in cases:
            require(inventory(luna) == frozen, 'Luna inventory changed during execution')
            folder = runs / 'gpt' / case
            if not folder.exists():
                print('\nGENERATING ONCE:', case, MODEL, flush=True)
                subprocess.run(['nice', '-n', '10', sys.executable, str(scripts / 'run_agent.py'),
                                '--agent', 'gpt', '--model', MODEL, '--vuln-id', case,
                                '--workspaces', str(workspaces), '--runs', str(runs)],
                               cwd=root, env=env, check=False)
            generation, error = validate_generation(folder)
            if generation is None:
                print('Incomplete attempt retained; no regeneration:', case, error, flush=True)
                if (folder / 'generation.json').exists():
                    failure = json.loads((folder / 'generation.json').read_text())
                    if failure.get('status') == 'generation_error':
                        print('API failure: campaign stopped for review. Earlier attempts remain frozen.', flush=True)
                        return 3
                continue
            request = json.loads((folder / 'request.json').read_text())
            old = json.loads((luna / 'gpt' / case / 'request.json').read_text())
            require(all(request[k] == old[k] for k in
                        ('system', 'user', 'temperature', 'max_completion_tokens', 'reasoning_effort', 'service_tier', 'endpoint')),
                    'Comparison settings differ from Luna: ' + case)
            require(request['model'] == MODEL, 'Unexpected requested model')
            alias = folder / 'llm_response.json'
            if not alias.exists():
                with alias.open('xb') as stream:
                    stream.write((folder / 'llm_response.txt').read_bytes())
            require(sha256(alias) == sha256(folder / 'llm_response.txt'), 'Response alias mismatch')
            if not (folder / 'eval.json').exists():
                if (folder / 'evaluation_evidence').exists():
                    print('Partial evaluation retained; review required:', case, flush=True)
                    continue
                print('EVALUATING:', case, flush=True)
                subprocess.run(['nice', '-n', '10', sys.executable, str(scripts / 'evaluate.py'),
                                '--agent', 'gpt', '--vuln-id', case, '--workspaces', str(workspaces),
                                '--vul4py-root', str(root / 'benchmark'), '--runs', str(runs),
                                '--timeout', '1800'], cwd=root, env=env, check=False)
            result = observation(folder, 'gpt')
            print(json.dumps({key: result.get(key) for key in
                              ('vuln_id', 'completed', 'claimed_success', 'confidence', 'apply_ok',
                               'functional_pass', 'security_pass', 'verified', 'false_assurance', 'notes')}), flush=True)
        require(inventory(luna) == frozen, 'Luna artifacts changed after evaluation')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        reports = root / 'experimento/reports' / ('luna-vs-sol62-' + stamp)
        compare(cases, luna, runs, reports)
        write_json(reports / 'integrity_audit.json', dict(luna_all_files_unchanged=True,
                   original_luna_files=len(frozen), protocol_sha256=sha256(plan_file),
                   execution_policy_sha256=sha256(policy_file)))
        print('Comparison finished. All original Luna files unchanged.', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
