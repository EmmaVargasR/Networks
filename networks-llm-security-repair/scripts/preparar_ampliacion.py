#!/usr/bin/env python3
"""Freeze prospective baseline-candidate selection. No API calls or test execution."""
import argparse
import csv
import datetime
import json
from pathlib import Path
import subprocess

from aggregate_results import observation
from repair_common import sha256, write_json

PILOT = ('CVE-2021-32839', 'CVE-2022-29217', 'CVE-2023-26302',
         'CVE-2023-32681', 'CVE-2023-37271')
PRIMARY = ('CVE-2025-43859', 'CVE-2024-6844', 'CVE-2025-46656',
           'CVE-2023-47163', 'CVE-2023-32309')
RESERVE = ('CVE-2023-34457', 'CVE-2022-3102', 'CVE-2025-24359')


def save_csv(path, rows):
    with path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['vuln_id', 'repo_url', 'fix_commit'])
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    dataset = root / 'benchmark/dataset/vul4py.csv'
    with dataset.open(newline='') as stream:
        rows = {row['vuln_id']: row for row in csv.DictReader(stream)}
    for case in PRIMARY + RESERVE:
        if case not in rows:
            raise ValueError(f'Case absent from pinned benchmark: {case}')
    campaign = root / 'experimento/runs/luna-cinco-2026-11-23-r2-audit-v3/gpt'
    frozen = {}
    for case in PILOT:
        if not observation(campaign / case, 'gpt')['completed']:
            raise ValueError(f'Pilot evidence is not valid: {case}')
        frozen[case] = {name: sha256(campaign / case / name)
                        for name in ('generation.json', 'patch.diff', 'request.json', 'eval.json')}
    print('Pilot: 5 audited observations retained.')
    for case in PRIMARY:
        print('PRIMARY', case, rows[case]['repo_url'])
    for case in RESERVE:
        print('RESERVE', case, rows[case]['repo_url'])
    if args.check:
        print('Read-only check passed. No API calls, test runs or file changes.')
        return
    out = root / 'ampliacion-diez-2026-11-23'
    out.mkdir(exist_ok=False)
    commit = subprocess.run(['git', '-C', str(root / 'benchmark'), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=True).stdout.strip()
    plan = {
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'status': 'prospective plan; new candidates not yet validated',
        'target_total_distinct_cases': 10, 'preserved_pilot_cases': list(PILOT),
        'primary_candidates_in_order': list(PRIMARY), 'reserve_candidates_in_order': list(RESERVE),
        'model': 'gpt-6-luna', 'valid_generations_per_case': 1,
        'automatic_generation_retries': 0, 'reasoning_effort': 'low',
        'max_completion_tokens': 4096, 'service_tier': 'default',
        'max_context_files': 4, 'max_context_characters': 60000,
        'benchmark_commit': commit, 'dataset_sha256': sha256(dataset),
        'pilot_artifact_hashes': frozen,
        'inclusion': [
            'Select by reproducible benchmark baseline and available source context, before model generation.',
            'Functional tests must pass in vulnerable and fixed; security tests must fail in vulnerable and pass in fixed.',
            'No errors or missing required tests; accept only matching documented baseline skips.',
            'Preserve original application and tests; document environment and harness adjustments.',
            'Five new projects, distinct from pilot projects, in the declared candidate order.',
            'Choose first five eligible candidates; if fewer than five qualify, stop and amend the candidate plan before API calls.',
        ],
        'exclusion_log_required': True,
        'exclude_for': ['unresolved baseline failure', 'infrastructure failure or timeout',
                        'insufficient available source context under unchanged limits', 'resource constraints'],
        'never_exclude_for': ['model refusal', 'low confidence', 'patch rejection', 'failed generated repair'],
        'operational_limits': {'workers': 1, 'threads': 1, 'minimum_free_disk_gib_before_preparation': 4},
        'analysis': ['Report original five and new five separately; pooled ten is descriptive.',
                     'Count preserved pilot attempts once; copied artifacts are not new repetitions.',
                     'Report incomplete attempts and denominators; FAR is undefined without positive claims.',
                     'No model comparison, confidence threshold, or statistical superiority claim in this extension.'],
        'semgrep': 'Mentioned in Notion header; role needs clarification or a separately labelled post-hoc analysis. Not part of V/FA.',
    }
    write_json(out / 'protocolo.json', plan)
    save_csv(out / 'candidatos.csv', [rows[case] for case in PRIMARY])
    save_csv(out / 'reservas.csv', [rows[case] for case in RESERVE])
    save_csv(out / 'primer-caso.csv', [rows[PRIMARY[0]]])
    save_csv(out / 'piloto-conservado.csv', [rows[case] for case in PILOT])
    (out / 'seleccion.tsv').write_text(
        'case_id\trole\tbaseline_status\tdecision\treason\n'
        + ''.join(f'{case}\t{role}\tPENDING\tPENDING\t\n'
                  for role, cases in (('primary', PRIMARY), ('reserve', RESERVE)) for case in cases))
    (out / 'PROTOCOLO.md').write_text(
        '# Ampliacion prospectiva a diez casos\n\n'
        'Se conservan los cinco intentos del piloto sin regenerar ni editar sus parches. '
        'La ampliacion busca cinco proyectos nuevos, con GPT-6 Luna, el mismo prompt y limites. '
        'Los candidatos se aceptan por sus referencias y contexto disponible antes de consultar al modelo. '
        'Se registra cada exclusion y su motivo. No se descartan reparaciones por fallar.\n\n'
        'La lista primaria y las reservas estan ordenadas en protocolo.json y los CSV. '
        'Una referencia OK del scan debe pasar tambien benchmark_reference y los controles de contexto. '
        'Las omisiones conocidas no se cuentan como aprobaciones. '
        'Solo un trabajador y un hilo; comprobar disco antes de preparar.\n\n'
        'Se informan por separado los cinco casos iniciales, los cinco nuevos y el total descriptivo de diez. '
        'No se convierten copias de respuestas anteriores en nuevas observaciones. '
        'No se afirma representatividad de todo Vul4Py ni generalizacion a otros modelos.\n\n'
        'Estado: PLAN. Aun no hay cinco nuevas referencias validadas ni resultados de ampliacion. '
        'El historial previo y las correcciones del evaluador se conservan. '
        'Semgrep no se ha ejecutado; su rol se aclara antes de presentarlo como requisito cumplido.\n')
    print('Plan written:', out)
    print('Next step: commit this plan, then prepare ONLY the first candidate.')


if __name__ == '__main__':
    main()
