import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from repetir_comparacion import MODELS, repetition_summary, schedule


class RepetitionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.cases = ['C' + str(i) for i in range(10)]

    def test_exactly_one_new_attempt_per_model_case_and_round(self):
        jobs = schedule(self.cases)
        identities = {(j['model'], j['case'], j['repetition']) for j in jobs}
        self.assertEqual(len(jobs), 40)
        self.assertEqual(len(identities), 40)
        self.assertEqual({j['repetition'] for j in jobs}, {2, 3})
        first_two = [j for j in jobs if j['case'] == 'C0']
        self.assertEqual([j['model'] for j in first_two[:2]], list(MODELS))
        self.assertEqual([j['model'] for j in first_two[2:]], list(MODELS[::-1]))

    def records(self):
        return [dict(requested_model=m, vuln_id=c, repetition=n, completed=True,
                     claimed_success=1, apply_ok=1, functional_pass=1, security_pass=0,
                     verified=0, false_assurance=1, latency_ms=10)
                for m in MODELS for c in self.cases for n in (1, 2, 3)]

    def test_repeated_cases_are_not_counted_as_sixty_distinct_cases(self):
        result = repetition_summary(self.records(), self.cases)
        self.assertEqual(result['distinct_cases'], 10)
        self.assertEqual(result['total_observations'], 60)
        self.assertEqual(result['by_model'][MODELS[0]]['completed'], 30)
        self.assertEqual(result['by_round']['2'][MODELS[1]]['completed'], 10)

    def test_missing_or_duplicated_observation_is_rejected(self):
        records = self.records()
        for changed in [records[:-1], records[:-1] + [records[0]]]:
            with self.assertRaises(ValueError):
                repetition_summary(changed, self.cases)

    def test_incomplete_round_is_not_a_demonstrated_repair_failure(self):
        records = self.records()
        records[0].update(completed=False, verified=None, false_assurance=None)
        result = repetition_summary(records, self.cases)['by_model'][MODELS[0]]
        self.assertEqual(result['completed'], 29)
        self.assertEqual(result['incomplete'], 1)
        self.assertEqual(result['positive_claims'], 29)
