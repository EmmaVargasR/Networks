#!/usr/bin/env python3
"""Evaluate one frozen generation against an explicitly selected Vul4Py checkout."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

from repair_common import benchmark_reference, junit_result, sha256, validate_generation, write_json

HERE = Path(__file__).resolve().parent.parent


def command(argv, log, timeout, cwd=None):
    with log.open('w', encoding='utf-8') as out:
        out.write('$ ' + ' '.join(map(str, argv)) + '\n')
        out.flush()
        process = None
        try:
            process = subprocess.Popen(list(map(str, argv)), cwd=cwd, stdout=out,
                                       stderr=subprocess.STDOUT, start_new_session=os.name != 'nt')
            rc = process.wait(timeout=timeout)
            out.write(f'\n[process exit {rc}]\n')
            return rc
        except (OSError, subprocess.TimeoutExpired) as exc:
            if process is not None and process.poll() is None:
                if os.name != 'nt':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
            out.write('\n[infrastructure error] ' + str(exc) + '\n')
            return None


@contextmanager
def case_lock(case):
    lock = case / '.repair-evaluation.lock'
    lock.mkdir()  # Concurrent evaluators must not share benchmark log files.
    try:
        yield
    finally:
        lock.rmdir()


def pristine_candidate(source, candidate, ref, evidence, timeout):
    """Create from committed objects, never from the scan's modified test tree."""
    if not isinstance(ref, str) or not re.fullmatch(r'[0-9a-fA-F]{40,64}', ref):
        raise ValueError('A full vulnerable commit hash is required')
    if command(['git', 'clone', '--no-hardlinks', '--no-checkout',
                str(source), str(candidate)], evidence / 'candidate_clone.log', timeout) != 0:
        return False
    return command(['git', 'checkout', '--detach', ref],
                   evidence / 'candidate_checkout.log', timeout, candidate) == 0


def evaluate_one(workspaces, runs, agent, vuln_id, vul4py_root, timeout=900):
    case = Path(workspaces).resolve() / vuln_id
    run = Path(runs).resolve() / agent / vuln_id
    out = run / 'eval.json'
    if out.exists() or (run / 'evaluation_evidence').exists():
        raise FileExistsError('Evaluation already exists; preserve it: ' + str(run))
    run.mkdir(parents=True, exist_ok=True)
    evidence = run / 'evaluation_evidence'
    evidence.mkdir()
    started = time.monotonic()
    verdict = dict(schema_version=2, evaluation_protocol='v3-pristine-relative-identities',
                   agent=agent, vuln_id=vuln_id,
                   status='incomplete', completed=False, claimed_success=None,
                   confidence=None, apply_ok=None, functional_pass=None,
                   security_pass=None, verified=None, false_assurance=None, notes='')
    candidate = None
    candidate_created = False
    try:
        gen, error = validate_generation(run)
        if gen is None:
            verdict['notes'] = error
            return verdict
        verdict.update(claimed_success=gen['claimed_success'], confidence=gen['confidence'],
                       generation_sha256=sha256(run / 'generation.json'),
                       patch_sha256=sha256(run / 'patch.diff'))
        root = Path(vul4py_root).resolve()
        harness = root / 'scripts' / 'vul4py.py'
        required = ('git', 'patch')
        missing = [name for name in required if shutil.which(name) is None]
        if missing:
            verdict['notes'] = 'Missing tools: ' + ', '.join(missing)
            return verdict
        if not harness.is_file() or not (case / 'meta.json').is_file() or not (case / 'vulnerable').is_dir():
            verdict['notes'] = 'Missing Vul4Py harness, prepared workspace or meta.json'
            return verdict
        benchmark_ref = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                       capture_output=True, text=True, timeout=30)
        if benchmark_ref.returncode:
            verdict['notes'] = 'Vul4Py root must be a Git checkout with a recorded commit'
            return verdict
        verdict['benchmark_commit'] = benchmark_ref.stdout.strip()
        dirty = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=no'],
                               capture_output=True, text=True, timeout=30)
        verdict['benchmark_tracked_changes'] = dirty.stdout.strip()
        if dirty.returncode or dirty.stdout.strip():
            verdict['notes'] = 'Use a clean, separate Vul4Py checkout for reproducibility'
            return verdict
        write_json(evidence / 'benchmark.json', {'commit': verdict['benchmark_commit'],
                   'harness_sha256': sha256(harness), 'meta_sha256': sha256(case / 'meta.json'),
                   'evaluator_sha256': sha256(Path(__file__))})
        shutil.copy2(case / 'meta.json', evidence / 'case_meta.json')
        case_meta = json.loads((case / 'meta.json').read_text(encoding='utf-8'))
        name = 'repair_' + hashlib.sha256(str(run).encode()).hexdigest()[:12]
        candidate = case / name
        write_json(evidence / 'source_roots.json', {
            'vulnerable': str(case / 'vulnerable'), 'fixed': str(case / 'fixed'),
            'candidate': str(candidate),
            'identity_normalization': 'Replace only the declared checkout prefix with <CHECKOUT>/',
        })
        with case_lock(case):
            if candidate.exists():
                candidate = None
                verdict['notes'] = 'Candidate already exists; inspect it before evaluating'
                return verdict
            references = {kind: benchmark_reference(case / 'logs', kind)
                          for kind in ('functional', 'exploit')}
            write_json(evidence / 'baseline.json', references)
            for kind in ('functional', 'exploit'):
                for version in ('vulnerable', 'fixed'):
                    source = case / 'logs' / f'{kind}_{version}.junit.xml'
                    shutil.copy2(source, evidence / source.name)
            candidate_created = True
            if not pristine_candidate(case / 'vulnerable', candidate,
                                      case_meta.get('vulnerable_ref'), evidence, timeout):
                verdict['notes'] = 'Could not create a pristine vulnerable checkout'
                return verdict
            patch = run / 'patch.diff'
            check_log = evidence / 'patch_check.log'
            if not patch.read_bytes().strip():
                rc = 1
                check_log.write_text('No patch supplied\n', encoding='utf-8')
            else:
                rc = command(['git', 'apply', '--check', str(patch)], check_log, timeout, candidate)
            if rc != 0:
                detail = check_log.read_text(encoding='utf-8', errors='replace')
                rejected = rc is not None and (not patch.read_bytes().strip() or re.search(
                    r'corrupt patch|patch failed|does not apply|No valid patches|no valid patches|'
                    r'No such file|already exists|unrecognized input|invalid path', detail))
                if rejected:
                    verdict.update(status='complete', completed=True, apply_ok=0,
                                   functional_pass=0, security_pass=0, verified=0,
                                   false_assurance=gen['claimed_success'], notes='Patch rejected by git apply --check')
                else:
                    verdict['notes'] = 'Patch application check could not complete; inspect evidence'
                return verdict
            rc = command(['git', 'apply', str(patch)], evidence / 'patch_apply.log', timeout, candidate)
            if rc != 0:
                verdict['notes'] = 'Patch application interrupted after successful check'
                return verdict
            verdict['apply_ok'] = 1
            checks = {}
            for kind in ('functional', 'exploit'):
                benchmark_logs = case / 'logs'
                xml = benchmark_logs / f'{kind}_{name}.junit.xml'
                if xml.exists():
                    xml.unlink()  # Never reuse evidence from an earlier test invocation.
                argv = [sys.executable, harness, '--workspace-root', case.parent,
                        '--cve-id', vuln_id, kind, '--target' if kind == 'functional' else '--targets', name]
                rc = command(argv, evidence / f'{kind}_command.log', timeout, cwd=root)
                result = junit_result(xml, reference=references[kind], checkout_root=candidate)
                if rc != 0:
                    result['status'] = 'incomplete'
                    result['reason'] = 'Benchmark command raised an error or timed out'
                result['process_exit'] = rc
                checks[kind] = result
                if benchmark_logs.exists():
                    for source in benchmark_logs.glob(f'{kind}_{name}*'):
                        if source.is_file():
                            shutil.copy2(source, evidence / source.name)
            verdict['checks'] = checks
            if any(c['status'] == 'incomplete' for c in checks.values()):
                verdict['notes'] = 'Verification incomplete; consult JUnit and command logs'
                return verdict
            f = int(checks['functional']['status'] == 'pass')
            s = int(checks['exploit']['status'] == 'pass')
            v = f * s
            verdict.update(status='complete', completed=True, functional_pass=f,
                           security_pass=s, verified=v,
                           false_assurance=gen['claimed_success'] * (1 - v))
            # Ensure generation files were not changed during evaluation.
            if validate_generation(run)[0] is None or sha256(run / 'generation.json') != verdict['generation_sha256']:
                verdict.update(status='incomplete', completed=False, verified=None,
                               false_assurance=None, notes='Generation changed during evaluation')
            return verdict
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        verdict['notes'] = type(exc).__name__ + ': ' + str(exc)
        return verdict
    finally:
        # Candidate paths are constructed only beneath the selected benchmark case.
        if candidate_created and candidate is not None and candidate.exists() and candidate.parent == case:
            try:
                shutil.rmtree(candidate)
            except OSError as exc:
                verdict['cleanup_error'] = str(exc)
        verdict['elapsed_s'] = round(time.monotonic() - started, 3)
        verdict['evidence_hashes'] = {p.name: sha256(p) for p in evidence.iterdir() if p.is_file()}
        write_json(out, verdict)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', default='gpt')
    parser.add_argument('--vuln-id')
    parser.add_argument('--runs', type=Path, default=HERE / 'runs')
    parser.add_argument('--workspaces', type=Path, required=True)
    parser.add_argument('--vul4py-root', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    base = args.runs / args.agent
    ids = [args.vuln_id] if args.vuln_id else sorted(p.name for p in base.iterdir() if p.is_dir())
    failed = False
    for vid in ids:
        try:
            v = evaluate_one(args.workspaces, args.runs, args.agent, vid, args.vul4py_root, args.timeout)
            print(vid, v['status'], v['notes'])
            failed |= not v['completed']
        except FileExistsError as exc:
            print(str(exc), file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
