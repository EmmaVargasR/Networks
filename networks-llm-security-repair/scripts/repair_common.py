"""Shared validation. No network calls; invalid observations stay incomplete."""
import hashlib
import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    # Exclusive creation is intentional: never replace an experimental record.
    with Path(path).open('x', encoding='utf-8', newline='\n') as out:
        json.dump(value, out, indent=2, ensure_ascii=False, allow_nan=False)
        out.write('\n')


def parse_payload(text):
    value = json.loads(text)
    if not isinstance(value, dict) or set(value) != {'claimed_success', 'confidence', 'patch'}:
        raise ValueError('Response must contain exactly claimed_success, confidence and patch')
    if type(value['claimed_success']) is not bool:
        raise ValueError('claimed_success must be a JSON boolean')
    confidence = value['confidence']
    if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError('confidence must be a finite number between 0 and 1')
    if not isinstance(value['patch'], str):
        raise ValueError('patch must be a string')
    return value


def validate_generation(directory):
    directory = Path(directory)
    try:
        record = json.loads((directory / 'generation.json').read_text(encoding='utf-8'))
        if record.get('status') != 'generated' or record.get('error') or record.get('parse_error'):
            raise ValueError('No valid frozen generation (legacy/error record)')
        for name in ('llm_response.txt', 'patch.diff', 'request.json'):
            if record.get('hashes', {}).get(name) != sha256(directory / name):
                raise ValueError('Missing or changed generation artifact: ' + name)
        payload = parse_payload((directory / 'llm_response.txt').read_text(encoding='utf-8'))
        if int(payload['claimed_success']) != record.get('claimed_success') or payload['confidence'] != record.get('confidence'):
            raise ValueError('Claim/confidence differs from original response')
        if (directory / 'patch.diff').read_bytes() != payload['patch'].encode('utf-8'):
            raise ValueError('Patch differs from original response')
        return record, ''
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return None, str(exc)


def checkout_relative(value, checkout_root):
    """Normalize only a declared checkout prefix, not arbitrary test parameters."""
    if checkout_root is None:
        return value
    root = Path(checkout_root)
    if not root.is_absolute():
        raise ValueError('Checkout normalization requires an absolute root')
    for prefix in (str(root), root.as_posix()):
        prefix = prefix.rstrip('/\\')
        for separator in ('/', '\\'):
            value = value.replace(prefix + separator, '<CHECKOUT>/')
    return value


def junit_result(path, reference=None, checkout_root=None):
    """Count actual testcase nodes, not the wrapper process return code."""
    path = Path(path)
    result = {'status': 'incomplete', 'tests': 0, 'passed': 0, 'failed': 0, 'errors': 0, 'skipped': 0}
    try:
        root = ET.parse(path).getroot()
        if root.tag not in ('testsuites', 'testsuite'):
            raise ValueError('Unexpected JUnit root')
        cases = list(root.iter('testcase'))
        details = {}
        for case in cases:
            identity = checkout_relative(
                case.get('classname', '') + '::' + case.get('name', ''), checkout_root)
            if identity in details:
                raise ValueError('Duplicate testcase identity')
            skipped = case.find('skipped')
            status = ('error' if case.find('error') is not None else
                      'fail' if case.find('failure') is not None else
                      'skip' if skipped is not None else 'pass')
            reason = (skipped.get('message') or (skipped.text or '').strip()) if skipped is not None else ''
            details[identity] = {'status': status,
                                 'reason': checkout_relative(reason, checkout_root)}
        result['cases'] = details
        result['tests'] = len(cases)
        result['errors'] = sum(c.find('error') is not None for c in cases)
        result['failed'] = sum(c.find('failure') is not None for c in cases)
        result['skipped'] = sum(c.find('skipped') is not None for c in cases)
        result['passed'] = sum(all(c.find(t) is None for t in ('error', 'failure', 'skipped')) for c in cases)
        # Suite-level setup errors also invalidate the check.
        declared_errors = sum(int(s.get('errors', 0)) for s in root.iter('testsuite'))
        result['suite_errors'] = declared_errors
        if result['errors'] or declared_errors or not cases or result['passed'] + result['failed'] == 0:
            result['reason'] = 'Missing, skipped or errored tests'
        elif reference is not None:
            prior = reference['cases']
            prior_skips = {k: v['reason'] for k, v in prior.items() if v['status'] == 'skip'}
            current_skips = {k: v['reason'] for k, v in details.items() if v['status'] == 'skip'}
            required = {k for k, v in prior.items() if v['status'] != 'skip'}
            executed = {k for k, v in details.items() if v['status'] != 'skip'}
            if prior_skips != current_skips or not required.issubset(executed):
                result['reason'] = 'New/changed skipped tests or missing baseline testcases'
            else:
                result['status'] = 'fail' if result['failed'] else 'pass'
        elif result['skipped']:
            result['reason'] = 'Skipped tests need a verified baseline'
        else:
            result['status'] = 'fail' if result['failed'] else 'pass'
    except (OSError, ValueError, ET.ParseError) as exc:
        result['reason'] = str(exc)
    return result


def benchmark_reference(logs, kind, case_root=None):
    """Accept only a reproduced vulnerability and a working reference fix."""
    logs = Path(logs)
    case_root = Path(case_root).resolve() if case_root is not None else logs.parent.resolve()
    vulnerable = junit_result(logs / f'{kind}_vulnerable.junit.xml',
                              checkout_root=case_root / 'vulnerable')
    fixed = junit_result(logs / f'{kind}_fixed.junit.xml',
                         checkout_root=case_root / 'fixed')
    for result in (vulnerable, fixed):
        if (result.get('errors') or result.get('suite_errors') or not result.get('cases')
                or result['passed'] + result['failed'] < 1):
            raise ValueError('Baseline is missing tests, has errors or has no executed tests')
    if fixed['failed'] or (kind == 'functional' and vulnerable['failed']):
        raise ValueError('Baseline functional/reference-fix tests failed')
    skips = lambda r: {k: v['reason'] for k, v in r['cases'].items() if v['status'] == 'skip'}
    if skips(vulnerable) != skips(fixed):
        raise ValueError('Baseline skipped tests differ between vulnerable and fixed')
    if kind == 'exploit':
        failing = {k for k, v in vulnerable['cases'].items() if v['status'] == 'fail'}
        passing = {k for k, v in fixed['cases'].items() if v['status'] == 'pass'}
        if not failing or not failing.issubset(passing):
            raise ValueError('Security test must fail on vulnerable and pass on fixed')
    return vulnerable if kind == 'functional' else fixed
