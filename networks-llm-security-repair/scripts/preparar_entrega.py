#!/usr/bin/env python3
"""Prepare a separate, verified GitHub submission. Never call an API or edit runs."""
import argparse
import ast
import csv
import datetime
import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import subprocess

from aggregate_results import observation
from repair_common import parse_payload, sha256, validate_generation

CASES = ('CVE-2021-32839', 'CVE-2022-29217', 'CVE-2023-26302',
         'CVE-2023-32681', 'CVE-2023-37271')
CAMPAIGN = 'luna-cinco-2026-11-23-r2-audit-v3'
SCRIPTS = ('run_agent.py', 'evaluate.py', 'repair_common.py',
           'aggregate_results.py', 'preflight.py', 'continuar_piloto.py',
           'auditar_resultados_v3.py', 'preparar_entrega.py')


def inspect_campaign(root):
    experiment = root / 'experimento'
    campaign = experiment / 'runs' / CAMPAIGN
    actual = sorted(p.name for p in (campaign / 'gpt').iterdir() if p.is_dir())
    if actual != sorted(CASES):
        raise ValueError('Campaign must contain exactly the five selected cases')
    records = []
    for case in CASES:
        folder = campaign / 'gpt' / case
        generation, error = validate_generation(folder)
        if generation is None:
            raise ValueError(f'{case}: {error}')
        row = observation(folder, 'gpt')
        if not row['completed']:
            raise ValueError(f'{case}: {row["notes"]}')
        parse_payload((folder / 'llm_response.txt').read_text())
        records.append(row)
    report = experiment / 'reports/piloto-cinco-audit-v3.csv'
    with report.open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    expected = {row['vuln_id']: row for row in records}
    if len(rows) != 5 or {r['vuln_id'] for r in rows} != set(CASES):
        raise ValueError('CSV case set does not match the campaign')
    for row in rows:
        record = expected[row['vuln_id']]
        for key in ('claimed_success', 'apply_ok', 'functional_pass', 'security_pass',
                    'verified', 'false_assurance', 'input_tokens', 'output_tokens', 'total_tokens'):
            if int(row[key]) != record[key]:
                raise ValueError(f'CSV mismatch: {row["vuln_id"]}/{key}')
        if float(row['confidence']) != record['confidence'] or row['completed'] != 'True':
            raise ValueError('CSV confidence/completion mismatch')
    summary = json.loads(report.with_suffix('.summary.json').read_text())
    positive = sum(row['claimed_success'] for row in records)
    verified = sum(row['verified'] for row in records)
    false = sum(row['false_assurance'] for row in records)
    if (summary['completed'] != 5 or summary['incomplete'] != 0
            or summary['verified_repairs'] != verified or summary['positive_claims'] != positive
            or summary['false_assurances'] != false
            or summary['VRR'] != verified / 5 or summary['FAR'] != false / positive):
        raise ValueError('Summary disagrees with audited observations')
    print(f'Validated: 5 cases; VRR={summary["VRR"]}; FAR={summary["FAR"]}')
    return records, summary, report, campaign


def check_publishable(folder):
    patterns = (
        (b'OpenAI credential', rb'sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}'),
        (b'AWS access key', rb'(?:AKIA|ASIA)[A-Z0-9]{16}'),
        (b'Private key block', rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{80,}'),
    )
    files = [p for p in folder.rglob('*') if p.is_file()]
    for path in files:
        if path.is_symlink() or path.name.startswith('.env') or path.suffix in ('.pem', '.key'):
            raise ValueError(f'Forbidden submission file: {path.relative_to(folder)}')
        data = path.read_bytes()
        for label, pattern in patterns:
            if re.search(pattern, data):
                raise ValueError(f'Possible secret ({label.decode()}) in {path.relative_to(folder)}; value not printed')
        if path.suffix == '.py':
            ast.parse(data.decode('utf-8'), filename=str(path))
    return files


def build(root, destination):
    records, summary, report, campaign = inspect_campaign(root)
    experiment = root / 'experimento'
    destination.mkdir(parents=True, exist_ok=False)
    for name in SCRIPTS:
        (destination / 'scripts').mkdir(exist_ok=True)
        shutil.copy2(experiment / 'scripts' / name, destination / 'scripts' / name)
    (destination / 'tests').mkdir()
    shutil.copy2(experiment / 'tests/test_integrity.py', destination / 'tests/test_integrity.py')
    (destination / 'docs').mkdir()
    shutil.copy2(experiment / 'docs/README-entrega.template.md', destination / 'docs/README-entrega.template.md')
    shutil.copytree(campaign, destination / 'runs' / CAMPAIGN)
    aliases = {}
    for case in CASES:
        folder = destination / 'runs' / CAMPAIGN / 'gpt' / case
        original = campaign / 'gpt' / case
        raw = (original / 'llm_response.txt').read_bytes()
        with (folder / 'llm_response.json').open('xb') as stream:
            stream.write(raw)
        assert sha256(folder / 'llm_response.json') == sha256(original / 'llm_response.txt')
        for name in ('patch.diff', 'generation.json', 'request.json', 'eval.json', 'llm_response.txt'):
            assert sha256(folder / name) == sha256(original / name)
        if not observation(folder, 'gpt')['completed']:
            raise ValueError(f'Copied evidence invalid: {case}')
        aliases[case] = {'original_llm_response_txt_sha256': sha256(original / 'llm_response.txt'),
                         'llm_response_json_sha256': sha256(folder / 'llm_response.json')}
        config = destination / 'configs' / case
        config.mkdir(parents=True)
        evidence_meta = original / 'evaluation_evidence/case_meta.json'
        shutil.copy2(evidence_meta, config / 'meta.json')
        frozen = root / 'evidencias/piloto-cinco-20261123T150626017127Z' / case
        for side in ('vulnerable', 'fixed'):
            name = f'{side}-requirements.freeze.txt'
            if (frozen / name).exists():
                shutil.copy2(frozen / name, config / name)
    shutil.copy2(report, destination / 'results.csv')
    shutil.copy2(report.with_suffix('.summary.json'), destination / 'results.summary.json')
    (destination / 'dataset').mkdir()
    shutil.copy2(root / 'lotes/piloto-cinco.csv', destination / 'dataset/selected_cases.csv')
    shutil.copy2(experiment / 'requirements.txt', destination / 'requirements.txt')
    locked = sorted({f'{d.metadata["Name"]}=={d.version}' for d in importlib.metadata.distributions()})
    (destination / 'requirements-lock.txt').write_text('\n'.join(locked) + '\n')
    benchmark = subprocess.run(['git', '-C', str(root / 'benchmark'), 'rev-parse', 'HEAD'],
                               text=True, capture_output=True, check=True).stdout.strip()
    table = ['| Caso | Confianza | Funcionalidad | Seguridad | Reparacion valida |',
             '|---|---:|---|---|---|']
    for row in records:
        table.append(f'| {row["vuln_id"]} | {row["confidence"]:.2f} | '
                     f'{"Pasa" if row["functional_pass"] else "Falla"} | '
                     f'{"Pasa" if row["security_pass"] else "Falla"} | '
                     f'{"Si" if row["verified"] else "No"} |')
    readme = (experiment / 'docs/README-entrega.template.md').read_text()
    replacements = {
        '@@TABLE@@': '\n'.join(table), '@@VRR@@': f'{100 * summary["VRR"]:.0f} %',
        '@@FAR@@': f'{100 * summary["FAR"]:.0f} %', '@@BENCHMARK@@': benchmark,
        '@@INPUT@@': str(sum(row['input_tokens'] for row in records)),
        '@@OUTPUT@@': str(sum(row['output_tokens'] for row in records)),
    }
    for token, value in replacements.items():
        readme = readme.replace(token, value)
    (destination / 'README.md').write_text(readme)
    (destination / '.gitignore').write_text(
        '.venv/\n.env\n.env.*\n*.pem\n*.key\n__pycache__/\n*.py[cod]\n'
        '.pytest_cache/\nbenchmark/\nworkspaces/\npilot-workspaces/\nrepro-workspaces/\n')
    (destination / '.gitattributes').write_text('* -text\n*.py text eol=lf\n*.md text eol=lf\n')
    write = {
        'prepared_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_campaign': str(campaign), 'benchmark_commit': benchmark,
        'original_runs_modified': False, 'new_api_requests': 0,
        'llm_response_aliases': aliases, 'results_csv_source_sha256': sha256(report),
    }
    files = check_publishable(destination)
    write['sha256'] = {str(p.relative_to(destination)): sha256(p) for p in files}
    with (destination / 'submission_manifest.json').open('x') as stream:
        json.dump(write, stream, indent=2)
        stream.write('\n')
    print('Delivery prepared:', destination)
    print('Secret-pattern check passed; manual Git review is still required.')
    print('Original generations and evaluations unchanged. No API requests made.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.check:
        inspect_campaign(root)
        print('Read-only check completed. No files modified; no API requests made.')
        return
    destination = (args.output or root / 'entrega-github/networks-llm-security-repair').resolve()
    if root not in destination.parents:
        raise SystemExit('Submission destination must be inside redes-final')
    build(root, destination)


if __name__ == '__main__':
    main()
