#!/usr/bin/env python3
"""Reclassify frozen v2 JUnit with declared checkout-relative identities. No API."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil

from repair_common import benchmark_reference, junit_result, sha256, validate_generation, write_json


def main():
    root = Path(__file__).resolve().parents[2]
    source = root / 'experimento/runs/luna-cinco-2026-11-23-r2-audit-v2'
    target = root / 'experimento/runs/luna-cinco-2026-11-23-r2-audit-v3'
    target.mkdir(exist_ok=False)
    records = []
    for old_folder in sorted((source / 'gpt').iterdir()):
        if not old_folder.is_dir():
            continue
        generation, error = validate_generation(old_folder)
        if generation is None:
            raise ValueError(f'Invalid frozen generation: {old_folder.name}: {error}')
        old = json.loads((old_folder / 'eval.json').read_text())
        if old.get('evaluation_protocol') != 'v2-pristine-candidate' or old.get('apply_ok') != 1:
            raise ValueError('Only already-pristine v2 candidate executions can be reclassified')
        original_evidence = old_folder / 'evaluation_evidence'
        for name, expected in old['evidence_hashes'].items():
            if sha256(original_evidence / name) != expected:
                raise ValueError(f'Original evidence changed: {old_folder.name}/{name}')
        folder = target / 'gpt' / old_folder.name
        folder.mkdir(parents=True)
        for name in ('prompt.txt', 'request.json', 'llm_response.txt', 'patch.diff', 'generation.json'):
            shutil.copy2(old_folder / name, folder / name)
            assert sha256(old_folder / name) == sha256(folder / name)
        evidence = folder / 'evaluation_evidence'
        shutil.copytree(original_evidence, evidence,
                        ignore=shutil.ignore_patterns('baseline.json', 'source_roots.json'))
        shutil.copy2(original_evidence / 'baseline.json', evidence / 'baseline_v2_original.json')
        if (original_evidence / 'source_roots.json').exists():
            shutil.copy2(original_evidence / 'source_roots.json', evidence / 'source_roots_v2_original.json')
        case = root / 'pilot-workspaces' / old_folder.name
        candidate = case / ('repair_' + hashlib.sha256(str(old_folder.resolve()).encode()).hexdigest()[:12])
        references = {kind: benchmark_reference(evidence, kind, case_root=case)
                      for kind in ('functional', 'exploit')}
        write_json(evidence / 'baseline.json', references)
        write_json(evidence / 'source_roots.json', {
            'vulnerable': str(case / 'vulnerable'), 'fixed': str(case / 'fixed'),
            'candidate': str(candidate),
            'identity_normalization': 'Replace only the declared checkout prefix with <CHECKOUT>/',
        })
        checks = {}
        for kind in ('functional', 'exploit'):
            xml = evidence / f'{kind}_{candidate.name}.junit.xml'
            result = junit_result(xml, reference=references[kind], checkout_root=candidate)
            result['process_exit'] = old['checks'][kind]['process_exit']
            if result['process_exit'] != 0:
                result['status'] = 'incomplete'
                result['reason'] = 'Original command did not complete successfully'
            checks[kind] = result
        verdict = dict(old)
        verdict.update(
            evaluation_protocol='v3-pristine-relative-identities', checks=checks,
            audit_type='reclassification_of_frozen_junit_no_new_test_execution',
            original_evaluation=str(old_folder / 'eval.json'),
            original_evaluation_sha256=sha256(old_folder / 'eval.json'),
            reviewed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            audit_evaluator_sha256=sha256(root / 'experimento/scripts/evaluate.py'),
            audit_common_sha256=sha256(root / 'experimento/scripts/repair_common.py'),
        )
        if any(result['status'] == 'incomplete' for result in checks.values()):
            verdict.update(status='incomplete', completed=False, functional_pass=None,
                           security_pass=None, verified=None, false_assurance=None,
                           notes='Frozen JUnit audit still incomplete')
        else:
            functional = int(checks['functional']['status'] == 'pass')
            security = int(checks['exploit']['status'] == 'pass')
            verified = functional * security
            verdict.update(status='complete', completed=True, functional_pass=functional,
                           security_pass=security, verified=verified,
                           false_assurance=generation['claimed_success'] * (1 - verified), notes='')
        verdict['evidence_hashes'] = {p.name: sha256(p) for p in evidence.iterdir() if p.is_file()}
        write_json(folder / 'eval.json', verdict)
        records.append({
            'case': old_folder.name, 'original_run': str(old_folder), 'audit_run': str(folder),
            'generation_sha256': sha256(folder / 'generation.json'),
            'patch_sha256': sha256(folder / 'patch.diff'),
            'completed': verdict['completed'], 'verified': verdict['verified'],
        })
        print(old_folder.name, 'functional=', verdict['functional_pass'],
              'security=', verdict['security_pass'], 'verified=', verdict['verified'], flush=True)
    write_json(target / 'audit_manifest.json', {
        'reason': 'Normalize only declared checkout roots in test identities and skip reasons',
        'original_results_preserved': True, 'new_generation_requests': 0,
        'new_test_executions': 0, 'generations': records,
    })
    print('Audit campaign:', target)


if __name__ == '__main__':
    main()
