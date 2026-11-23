"""Regression checks with synthetic fixtures. Never call an external API."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import aggregate_results as aggregate
import evaluate
import run_agent
from repair_common import benchmark_reference, junit_result, parse_payload, sha256, validate_generation


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = self.root / 'workspaces' / 'CASE'
        (self.case / 'vulnerable').mkdir(parents=True)
        (self.case / 'vulnerable' / 'app.py').write_text('value = 1\n', encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(self.case / 'vulnerable')], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(self.case / 'vulnerable'), 'add', '.'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(self.case / 'vulnerable'), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false',
                        'commit', '-qm', 'vulnerable fixture'], check=True, capture_output=True)
        self.vulnerable_ref = subprocess.run(
            ['git', '-C', str(self.case / 'vulnerable'), 'rev-parse', 'HEAD'],
            check=True, capture_output=True, text=True).stdout.strip()
        (self.case / 'meta.json').write_text(json.dumps({
            'new_code_files': ['app.py'], 'vulnerable_ref': self.vulnerable_ref,
        }), encoding='utf-8')
        self.runs = self.root / 'runs'
        self.run = self.runs / 'gpt' / 'CASE'
        self.diff = '--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n'

    def tearDown(self):
        self.temp.cleanup()

    def generate(self, claim=True):
        text = json.dumps(dict(claimed_success=claim, confidence=.8, patch=self.diff))
        info = dict(model='test-model', timestamp='2026-11-11T00:00:00Z', latency_s=1,
                    input_tokens=10, output_tokens=10, total_tokens=20,
                    raw_response=text, stop_reason='stop')
        with patch.object(run_agent, 'call_gpt', return_value=(text, info)):
            self.assertEqual(run_agent.run_builtin('gpt', 'test-model', 'CASE', self.case, self.run), 0)

    def harness(self, mode):
        root = self.root / 'benchmark'
        (root / 'scripts').mkdir(parents=True)
        # The wrapper always exits zero, even when its JUnit has failures.
        script = '''import argparse, json
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--workspace-root',type=Path)
p.add_argument('--cve-id')
p.add_argument('kind')
p.add_argument('--target')
p.add_argument('--targets', nargs='+')
a=p.parse_args()
if a.targets: a.target=a.targets[0]
logs=a.workspace_root/a.cve_id/'logs'
logs.mkdir(exist_ok=True)
mode=MODE
body='<testcase name="actual_test"/>'
if mode=='fail' and a.kind=='exploit':
    body='<testcase name="actual_test"><failure message="vulnerable"/></testcase>'
if mode=='error' and a.kind=='exploit':
    body='<testcase name="actual_test"><error message="missing dependency"/></testcase>'
if mode=='known_skip':
    body+='<testcase name="known_omission"><skipped message="upstream issue"/></testcase>'
if mode!='missing':
    (logs/(a.kind+'_'+a.target+'.junit.xml')).write_text('<testsuite>'+body+'</testsuite>')
print('rc=1' if mode=='fail' else 'rc=0')
'''.replace('MODE', repr(mode))
        (root / 'scripts' / 'vul4py.py').write_text(script, encoding='utf-8')
        logs = self.case / 'logs'
        logs.mkdir(exist_ok=True)
        omission = '<testcase name="known_omission"><skipped message="upstream issue"/></testcase>' if mode == 'known_skip' else ''
        for kind in ('functional', 'exploit'):
            for version in ('vulnerable', 'fixed'):
                body = ('<testcase name="actual_test"><failure/></testcase>'
                        if kind == 'exploit' and version == 'vulnerable'
                        else '<testcase name="actual_test"/>')
                (logs / f'{kind}_{version}.junit.xml').write_text('<testsuite>' + body + omission + '</testsuite>', encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'], check=True, capture_output=True)
        return root

    def evaluate(self, mode):
        self.generate()
        benchmark = self.harness(mode)
        original_which = evaluate.shutil.which
        # The fixture does not use the system patch binary; production preflight does.
        with patch.object(evaluate.shutil, 'which', side_effect=lambda n: 'fixture-patch' if n == 'patch' else original_which(n)):
            return evaluate.evaluate_one(self.case.parent, self.runs, 'gpt', 'CASE', benchmark)

    def test_strict_claim_and_confidence(self):
        for value in ('false', 0, None):
            with self.assertRaises(ValueError):
                parse_payload(json.dumps(dict(claimed_success=value, confidence=.8, patch='')))
        for value in (-.1, 1.1, True, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                parse_payload(json.dumps(dict(claimed_success=True, confidence=value, patch='')))

    def test_candidate_does_not_inherit_backported_tests_or_dirty_source(self):
        source = self.case / 'vulnerable'
        (source / 'app.py').write_text('value = 99\n', encoding='utf-8')
        (source / 'new_security_test.py').write_text('assert False\n', encoding='utf-8')
        candidate = self.case / 'candidate'
        evidence = self.root / 'evidence'
        evidence.mkdir()
        self.assertTrue(evaluate.pristine_candidate(
            source, candidate, self.vulnerable_ref, evidence, 30))
        self.assertEqual((candidate / 'app.py').read_text(), 'value = 1\n')
        self.assertFalse((candidate / 'new_security_test.py').exists())
        self.assertEqual((source / 'app.py').read_text(), 'value = 99\n')
        self.assertTrue((source / 'new_security_test.py').exists())

    def test_candidate_rejects_unrecorded_commit_before_cloning(self):
        candidate = self.case / 'candidate'
        with self.assertRaises(ValueError):
            evaluate.pristine_candidate(
                self.case / 'vulnerable', candidate, None, self.root, 30)
        self.assertFalse(candidate.exists())

    def test_checkout_path_parameters_match_only_declared_roots(self):
        old_root = self.root / 'vulnerable'
        new_root = self.root / 'candidate'
        old = self.root / 'old.xml'
        new = self.root / 'new.xml'
        for path, base in ((old, old_root), (new, new_root)):
            path.write_text(
                f'<testsuite><testcase classname="suite" '
                f'name="test_path[{base}/tests/input.py]"/></testsuite>', encoding='utf-8')
        reference = junit_result(old, checkout_root=old_root)
        self.assertEqual(junit_result(new, reference=reference)['status'], 'incomplete')
        result = junit_result(new, reference=reference, checkout_root=new_root)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['passed'], 1)

    def test_checkout_normalization_does_not_hide_missing_or_changed_parameters(self):
        old_root = self.root / 'vulnerable'
        new_root = self.root / 'candidate'
        old = self.root / 'old.xml'
        new = self.root / 'new.xml'
        old.write_text(
            f'<testsuite><testcase classname="suite" '
            f'name="test_path[{old_root}/tests/input.py]"/></testsuite>', encoding='utf-8')
        new.write_text(
            f'<testsuite><testcase classname="suite" '
            f'name="test_path[{new_root}/tests/different.py]"/></testsuite>', encoding='utf-8')
        reference = junit_result(old, checkout_root=old_root)
        result = junit_result(new, reference=reference, checkout_root=new_root)
        self.assertEqual(result['status'], 'incomplete')

    def test_freeze_preserves_exact_patch(self):
        self.generate()
        self.assertEqual((self.run / 'patch.diff').read_bytes(), self.diff.encode())
        self.assertIsNotNone(validate_generation(self.run)[0])
        with patch.object(run_agent, 'call_gpt') as api:
            with self.assertRaises(FileExistsError):
                run_agent.run_builtin('gpt', 'test-model', 'CASE', self.case, self.run)
            api.assert_not_called()

    def test_modified_artifact_rejected(self):
        self.generate()
        (self.run / 'patch.diff').write_text('changed', encoding='utf-8')
        self.assertIsNone(validate_generation(self.run)[0])

    def test_api_error_does_not_create_a_patch(self):
        with patch.object(run_agent, 'call_gpt', side_effect=ConnectionError('synthetic')):
            self.assertEqual(run_agent.run_builtin('gpt', 'test', 'CASE', self.case, self.run), 1)
        self.assertFalse((self.run / 'patch.diff').exists())
        self.assertIsNone(validate_generation(self.run)[0])

    def test_invalid_response_saved_without_fake_claim(self):
        with patch.object(run_agent, 'call_gpt', return_value=('not-json', {'stop_reason': 'stop'})):
            self.assertEqual(run_agent.run_builtin('gpt', 'test', 'CASE', self.case, self.run), 1)
        self.assertEqual((self.run / 'llm_response.txt').read_text(), 'not-json')
        self.assertFalse((self.run / 'patch.diff').exists())

    def test_no_test_source_or_outside_files_in_prompt(self):
        meta = {'new_code_files': ['../outside.py', 'tests/test_app.py']}
        self.assertEqual(run_agent.collect_context_files(self.case, meta), [])

    def test_junit_missing_empty_skipped_and_setup_errors(self):
        target = self.root / 'tests.xml'
        self.assertEqual(junit_result(target)['status'], 'incomplete')
        for xml in ('<testsuite/>', '<testsuite><testcase><skipped/></testcase></testsuite>',
                    '<testsuite errors="1"><testcase/></testsuite>', '<broken'):
            target.write_text(xml, encoding='utf-8')
            self.assertEqual(junit_result(target)['status'], 'incomplete')

    def test_actual_failure_despite_successful_wrapper(self):
        result = self.evaluate('fail')
        self.assertTrue(result['completed'])
        self.assertEqual((result['functional_pass'], result['security_pass'], result['false_assurance']), (1, 0, 1))
        summary = aggregate.aggregate(self.runs, 'gpt', self.root / 'report.csv')
        self.assertEqual((summary['VRR'], summary['FAR']), (0, 1))

    def test_successful_repair(self):
        result = self.evaluate('pass')
        self.assertEqual((result['verified'], result['false_assurance']), (1, 0))

    def test_known_baseline_skips_are_reported_not_counted_as_passes(self):
        result = self.evaluate('known_skip')
        self.assertTrue(result['completed'], result)
        self.assertEqual(result['verified'], 1)
        self.assertEqual(result['checks']['exploit']['skipped'], 1)
        self.assertEqual(result['checks']['exploit']['passed'], 1)

    def test_new_skips_are_incomplete(self):
        path = self.root / 'suite.xml'
        path.write_text('<testsuite><testcase name="required"/></testsuite>')
        reference = junit_result(path)
        path.write_text('<testsuite><testcase name="required"/><testcase name="new"><skipped/></testcase></testsuite>')
        self.assertEqual(junit_result(path, reference)['status'], 'incomplete')

    def test_required_test_cannot_be_replaced_with_skip(self):
        path = self.root / 'suite.xml'
        path.write_text('<testsuite><testcase name="required"/><testcase name="other"/></testsuite>')
        reference = junit_result(path)
        path.write_text('<testsuite><testcase name="required"><skipped/></testcase><testcase name="other"/></testsuite>')
        self.assertEqual(junit_result(path, reference)['status'], 'incomplete')

    def test_required_test_cannot_disappear(self):
        path = self.root / 'suite.xml'
        path.write_text('<testsuite><testcase name="required"/><testcase name="other"/></testsuite>')
        reference = junit_result(path)
        path.write_text('<testsuite><testcase name="other"/></testsuite>')
        self.assertEqual(junit_result(path, reference)['status'], 'incomplete')

    def test_baseline_requires_security_failure_reproduced_and_fixed(self):
        self.harness('pass')
        path = self.case / 'logs' / 'exploit_vulnerable.junit.xml'
        path.write_text('<testsuite><testcase name="actual_test"/></testsuite>')
        with self.assertRaises(ValueError):
            benchmark_reference(path.parent, 'exploit')

    def test_rejected_patch_is_completed_failure(self):
        self.diff = 'not a unified diff\n'
        result = self.evaluate('pass')
        self.assertTrue(result['completed'], result)
        self.assertEqual((result['apply_ok'], result['verified'], result['false_assurance']), (0, 0, 1))

    def test_missing_system_patch_is_incomplete(self):
        self.generate()
        benchmark = self.harness('pass')
        original_which = evaluate.shutil.which
        with patch.object(evaluate.shutil, 'which', side_effect=lambda n: None if n == 'patch' else original_which(n)):
            result = evaluate.evaluate_one(self.case.parent, self.runs, 'gpt', 'CASE', benchmark)
        self.assertFalse(result['completed'])
        self.assertIn('patch', result['notes'])

    def test_case_lock_never_deletes_existing_candidate(self):
        self.generate()
        benchmark = self.harness('pass')
        name = 'repair_' + hashlib.sha256(str(self.run.resolve()).encode()).hexdigest()[:12]
        candidate = self.case / name
        candidate.mkdir()
        (candidate / 'keep.txt').write_text('existing', encoding='utf-8')
        (self.case / '.repair-evaluation.lock').mkdir()
        original_which = evaluate.shutil.which
        with patch.object(evaluate.shutil, 'which', side_effect=lambda n: 'fixture-patch' if n == 'patch' else original_which(n)):
            result = evaluate.evaluate_one(self.case.parent, self.runs, 'gpt', 'CASE', benchmark)
        self.assertFalse(result['completed'])
        self.assertTrue((candidate / 'keep.txt').exists())

    def test_no_positive_claims_far_is_undefined(self):
        self.generate(claim=False)
        benchmark = self.harness('pass')
        original_which = evaluate.shutil.which
        with patch.object(evaluate.shutil, 'which', side_effect=lambda n: 'fixture-patch' if n == 'patch' else original_which(n)):
            result = evaluate.evaluate_one(self.case.parent, self.runs, 'gpt', 'CASE', benchmark)
        self.assertTrue(result['completed'])
        summary = aggregate.aggregate(self.runs, 'gpt', self.root / 'report.csv')
        self.assertIsNone(summary['FAR'])

    def test_infrastructure_error_is_incomplete(self):
        result = self.evaluate('error')
        self.assertFalse(result['completed'])
        self.assertIsNone(result['false_assurance'])

    def test_absent_junit_is_incomplete(self):
        result = self.evaluate('missing')
        self.assertFalse(result['completed'])

    def test_evidence_tampering_is_excluded(self):
        self.evaluate('pass')
        (self.run / 'evaluation_evidence' / 'functional_command.log').write_text('modified', encoding='utf-8')
        self.assertFalse(aggregate.observation(self.run, 'gpt')['completed'])

    def test_legacy_errors_are_not_zero_claim_observations(self):
        self.run.mkdir(parents=True)
        (self.run / 'generation.json').write_text('{"error":"APIConnectionError"}', encoding='utf-8')
        summary = aggregate.aggregate(self.runs, 'gpt', self.root / 'audit.csv')
        self.assertEqual(summary['completed'], 0)
        self.assertIsNone(summary['VRR'])
        self.assertIsNone(summary['FAR'])
        with self.assertRaises(FileExistsError):
            aggregate.aggregate(self.runs, 'gpt', self.root / 'audit.csv')


if __name__ == '__main__':
    unittest.main()
