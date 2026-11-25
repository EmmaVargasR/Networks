#!/usr/bin/env python3
"""Declare and execute two additional paired rounds; never replace prior attempts."""
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

from aggregate_results import observation
from compare_models import summarize
from continuar_comparacion_sol import check_inputs, inventory, require
from repair_common import sha256, validate_generation, write_json

DIRECTORY = 'repeticiones-luna-sol62-2026-11-24'
MODELS = ('gpt-6-luna', 'gpt-6.2-sol')
REFERENCE_PLAN = 'comparacion-luna-sol62-2026-11-24/protocolo.json'
CODE = ('run_agent.py', 'evaluate.py', 'repair_common.py', 'aggregate_results.py',
        'compare_models.py', 'continuar_comparacion_sol.py', 'repetir_comparacion.py')


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def campaign(model, repetition):
    prefix = 'luna' if model == MODELS[0] else 'sol62'
    require(model in MODELS and repetition in (2, 3), 'Invalid model/repetition')
    return f'{prefix}-diez-2026-11-24-rep{repetition}'


def schedule(cases):
    require(len(cases) == len(set(cases)) == 10, 'Expected ten distinct cases')
    return [dict(case=case, model=model, repetition=rep, campaign=campaign(model, rep))
            for rep in (2, 3) for index, case in enumerate(cases)
            for model in (MODELS if (index + rep) % 2 == 0 else MODELS[::-1])]


def snapshot(path):
    return inventory(path) if path.is_dir() else {'file_sha256': sha256(path)}


def protect(root, plan):
    for relative, expected in plan['protected_existing_artifacts'].items():
        require(snapshot(root / relative) == expected, 'Existing artifacts changed: ' + relative)


def resources():
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemAvailable', 'SwapFree'):
            memory[key + '_kib'] = int(value.split()[0])
    return dict(timestamp=timestamp(), load_average=list(os.getloadavg()), **memory)


def prepare(root):
    directory = root / DIRECTORY
    require(not directory.exists(), 'Repetition protocol already exists; use --check')
    reference_path = root / REFERENCE_PLAN
    reference = json.loads(reference_path.read_text())
    luna = root / reference['existing_luna_campaign']
    sol = root / 'experimento/runs' / reference['campaign_name']
    cases = check_inputs(root, reference, luna)
    original = {MODELS[0]: str(luna.relative_to(root)), MODELS[1]: str(sol.relative_to(root))}
    token_inputs = {}
    for case in cases:
        left = json.loads((luna / 'gpt' / case / 'request.json').read_text())
        for model, folder in ((MODELS[0], luna), (MODELS[1], sol)):
            attempt = folder / 'gpt' / case
            require(observation(attempt, 'gpt')['completed'], 'Historical evidence incomplete: ' + case)
            request = json.loads((attempt / 'request.json').read_text())
            require({k: v for k, v in request.items() if k != 'model'} ==
                    {k: v for k, v in left.items() if k != 'model'}, 'Historical prompt/settings mismatch')
            gen, error = validate_generation(attempt)
            require(gen is not None, str(error))
            token_inputs[model + '/' + case] = gen['input_tokens']
    jobs = schedule(cases)
    for job in jobs:
        require(not (root / 'experimento/runs' / job['campaign']).exists(), 'New campaign already exists')
    protected = {str(p.relative_to(root)): snapshot(p)
                 for parent in ('experimento/runs', 'experimento/reports')
                 for p in sorted((root / parent).iterdir()) if p.is_dir() or p.is_file()}
    prices = {MODELS[0]: {'input': 0.1, 'output': 0.5}, MODELS[1]: {'input': 2.0, 'output': 10.0}}
    conservative = sum(((token_inputs[j['model'] + '/' + j['case']] * 1.25 + 1024)
                        * prices[j['model']]['input'] + 4096 * prices[j['model']]['output']) / 1e6 for j in jobs)
    require(conservative < 2, 'Conservative token estimate exceeds the USD 2 API reserve')
    directory.mkdir(exist_ok=False)
    protocol = dict(created_utc=timestamp(), status='Prospective rounds 2 and 3, declared after historical round 1',
                    models=list(MODELS), cases_in_order=cases, existing_round_one=original,
                    total_rounds=3, additional_rounds=[2, 3], additional_generations=40,
                    planned_total_model_case_round_observations=60, distinct_vulnerabilities=10,
                    same_prompts_source_and_evaluator=True, max_completion_tokens=4096,
                    reasoning_effort='low', service_tier='default', automatic_retries=0,
                    manual_patch_edits=False, verification_feedback_to_model=False,
                    workers=1, threads=1, minimum_free_disk_gib=4,
                    schedule=jobs, reference_protocol=REFERENCE_PLAN,
                    reference_protocol_sha256=sha256(reference_path),
                    script_sha256={n: sha256(root / 'experimento/scripts' / n) for n in CODE},
                    protected_existing_artifacts=protected,
                    standard_prices_usd_per_million_tokens=prices,
                    price_sources=['https://developers.openai.com/api/docs/models/gpt-6-luna',
                                   'https://developers.openai.com/api/docs/models/gpt-6.2-sol'],
                    estimated_conservative_new_api_cost_usd=conservative, suggested_api_reserve_usd=2,
                    cost_note='Estimate with 25% plus 1024 input-token margin and full output caps; not a billing guarantee; excludes AWS.',
                    analysis=['Keep all attempts, including failures and incomplete verification.',
                              'Report metrics separately by model and round, then across three rounds.',
                              'FAR denominator is positive claims in completed observations.',
                              'Historical round 1 is exploratory; rounds 2 and 3 are prospectively scheduled.',
                              'Ten vulnerabilities remain ten distinct cases, not sixty independent cases.',
                              'No best-of-three selection and no stopping after successful repairs.'])
    write_json(directory / 'protocolo.json', protocol)
    with (directory / 'schedule.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(jobs[0]))
        writer.writeheader()
        writer.writerows(jobs)
    print('Prospective protocol saved:', directory, flush=True)
    print('40 new generations; 60 total observations; conservative API estimate USD', round(conservative, 4), flush=True)


def repetition_summary(records, cases):
    expected = {(model, case, rep) for model in MODELS for case in cases for rep in (1, 2, 3)}
    identities = [(r['requested_model'], r['vuln_id'], r['repetition']) for r in records]
    require(len(identities) == len(set(identities)) and set(identities) == expected,
            'Missing, duplicated or undeclared model/case/round observation')
    return dict(distinct_cases=len(cases), total_observations=len(records),
                note='Descriptive repeated paired sample; do not treat repeated cases as independent vulnerabilities.',
                by_model={m: summarize([r for r in records if r['requested_model'] == m]) for m in MODELS},
                by_round={str(rep): {m: summarize([r for r in records if r['requested_model'] == m
                                                           and r['repetition'] == rep]) for m in MODELS}
                          for rep in (1, 2, 3)})


def reports(root, plan, protocol_file):
    records, hashes = [], {}
    for rep in (1, 2, 3):
        for model in MODELS:
            relative = plan['existing_round_one'][model] if rep == 1 else 'experimento/runs/' + campaign(model, rep)
            folder = root / relative
            for case in plan['cases_in_order']:
                attempt = folder / 'gpt' / case
                require(attempt.exists(), 'Attempt not started; no final 60-observation report: ' + str(attempt))
                row = observation(attempt, 'gpt')
                records.append(dict(requested_model=model, repetition=rep, source_campaign=relative, **row))
                hashes[f'{model}/{rep}/{case}'] = inventory(attempt)
    summary = repetition_summary(records, plan['cases_in_order'])
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = root / 'experimento/reports' / ('repeticiones-luna-sol62-' + stamp)
    out.mkdir(exist_ok=False)
    with (out / 'results.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    with (out / 'case_stability.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['model', 'vuln_id', 'planned_rounds', 'completed', 'incomplete',
                                                    'positive_claims', 'verified_repairs', 'false_assurances', 'VRR', 'FAR'])
        writer.writeheader()
        for model in MODELS:
            for case in plan['cases_in_order']:
                result = summarize([r for r in records if r['requested_model'] == model and r['vuln_id'] == case])
                row = dict(model=model, vuln_id=case, planned_rounds=3)
                row.update({k: result[k] for k in ('completed', 'incomplete', 'positive_claims', 'verified_repairs',
                                                   'false_assurances', 'VRR', 'FAR')})
                writer.writerow(row)
    write_json(out / 'summary.json', summary)
    write_json(out / 'source_hashes.json', hashes)
    write_json(out / 'integrity_audit.json', dict(protocol_sha256=sha256(protocol_file),
               all_preexisting_campaigns_and_reports_unchanged=True,
               protected_entries=len(plan['protected_existing_artifacts'])))
    print(json.dumps(summary, indent=2), flush=True)
    print('REPORT_DIRECTORY:', out, flush=True)


def execute(root, args):
    protocol_file = root / DIRECTORY / 'protocolo.json'
    plan = json.loads(protocol_file.read_text())
    reference = json.loads((root / plan['reference_protocol']).read_text())
    require(sha256(root / plan['reference_protocol']) == plan['reference_protocol_sha256'], 'Reference protocol changed')
    for name, expected in plan['script_sha256'].items():
        require(sha256(root / 'experimento/scripts' / name) == expected, 'Code changed after declaration: ' + name)
    require(schedule(plan['cases_in_order']) == plan['schedule'], 'Schedule changed')
    check_inputs(root, reference, root / plan['existing_round_one'][MODELS[0]])
    protect(root, plan)
    pending = [j for j in plan['schedule'] if not (root / 'experimento/runs' / j['campaign'] / 'gpt' / j['case']).exists()]
    print('Original campaigns/reports unchanged. Ten references and fixed prompts valid.', flush=True)
    print('New generation requests pending:', len(pending), flush=True)
    if args.check:
        print('Offline check complete; no API requests made.')
        return 0
    if args.report_only:
        reports(root, plan, protocol_file)
        return 0
    env = os.environ.copy()
    env.pop('OPENROUTER_API_KEY', None)
    env.update(OPENAI_BASE_URL='https://api.openai.com/v1', MAKEFLAGS='-j1',
               CMAKE_BUILD_PARALLEL_LEVEL='1', OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1')
    eval_env = env.copy()
    eval_env.pop('OPENAI_API_KEY', None)
    if pending:
        key = env.get('OPENAI_API_KEY', '')
        require(bool(key) and not any(c.isspace() for c in key), 'Load your personal key privately in this terminal')
        from openai import OpenAI
        client = OpenAI(api_key=key, base_url=env['OPENAI_BASE_URL'], max_retries=0, timeout=30)
        try:
            for model in MODELS:
                client.models.retrieve(model)
        except Exception as exc:
            print('Access check failed:', type(exc).__name__, 'HTTP', getattr(exc, 'status_code', None), flush=True)
            return 2
    with (root / DIRECTORY / '.execution.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for index, job in enumerate(plan['schedule'], 1):
            protect(root, plan)
            require(shutil.disk_usage(root).free >= plan['minimum_free_disk_gib'] * 1024**3, 'Insufficient disk space')
            case, model = job['case'], job['model']
            run = root / 'experimento/runs' / job['campaign']
            attempt = run / 'gpt' / case
            print(f"\n[{index}/40] round={job['repetition']} model={model} case={case}", flush=True)
            run.mkdir(exist_ok=True)
            policy_file = run / 'repetition_protocol.json'
            policy = dict(protocol_sha256=sha256(protocol_file), model=model, repetition=job['repetition'])
            if policy_file.exists():
                require(json.loads(policy_file.read_text()) == policy, 'Campaign policy mismatch')
            else:
                write_json(policy_file, policy)
            started_now = not attempt.exists()
            if started_now:
                resource_file = run / 'resources' / (case + '.before.json')
                resource_file.parent.mkdir(exist_ok=True)
                if not resource_file.exists():
                    write_json(resource_file, resources())
                print('GENERATING ONCE', flush=True)
                subprocess.run(['nice', '-n', '10', sys.executable, str(root / 'experimento/scripts/run_agent.py'),
                                '--agent', 'gpt', '--model', model, '--vuln-id', case,
                                '--workspaces', str(root / 'pilot-workspaces'), '--runs', str(run)],
                               cwd=root, env=env, check=False)
            gen, error = validate_generation(attempt)
            if gen is None:
                print('Incomplete generation retained; no retry:', error, flush=True)
                if started_now and (attempt / 'generation.json').exists():
                    failure = json.loads((attempt / 'generation.json').read_text())
                    if failure.get('status') == 'generation_error':
                        print('Stopped after API error. Fix access before resuming; this attempt will not be regenerated.', flush=True)
                        return 3
                continue
            old = json.loads((root / plan['existing_round_one'][model] / 'gpt' / case / 'request.json').read_text())
            request = json.loads((attempt / 'request.json').read_text())
            require(request == old, 'Prompt, model or settings differ from historical attempt')
            alias = attempt / 'llm_response.json'
            if not alias.exists():
                with alias.open('xb') as stream:
                    stream.write((attempt / 'llm_response.txt').read_bytes())
            require(sha256(alias) == sha256(attempt / 'llm_response.txt'), 'Response alias mismatch')
            if not (attempt / 'eval.json').exists():
                if (attempt / 'evaluation_evidence').exists():
                    print('Partial evaluation retained; requires review. No overwrite.', flush=True)
                    continue
                print('EVALUATING', flush=True)
                subprocess.run(['nice', '-n', '10', sys.executable, str(root / 'experimento/scripts/evaluate.py'),
                                '--agent', 'gpt', '--vuln-id', case,
                                '--workspaces', str(root / 'pilot-workspaces'), '--vul4py-root', str(root / 'benchmark'),
                                '--runs', str(run), '--timeout', '1800'], cwd=root, env=eval_env, check=False)
            result = observation(attempt, 'gpt')
            print(json.dumps({k: result.get(k) for k in ('vuln_id', 'completed', 'claimed_success', 'confidence',
                  'apply_ok', 'functional_pass', 'security_pass', 'verified', 'false_assurance', 'notes')}), flush=True)
        protect(root, plan)
        reports(root, plan, protocol_file)
    print('Finished. All preexisting campaigns and reports remain unchanged.', flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--report-only', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if args.prepare:
        prepare(root)
        return 0
    return execute(root, args)


if __name__ == '__main__':
    sys.exit(main())
