import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from compare_models import pair_rows, summarize


def record(case, *, complete=True, claim=1, verified=0):
    return dict(vuln_id=case, completed=complete, claimed_success=claim,
                verified=verified, false_assurance=claim * (1 - verified),
                apply_ok=1, functional_pass=1, security_pass=verified, latency_ms=5.0)


class PairedComparisonTests(unittest.TestCase):
    def test_incomplete_record_does_not_change_completed_denominators(self):
        result = summarize([record('A', verified=1), record('B'), record('C', claim=0),
                            record('D', complete=False)])
        self.assertEqual(result['completed'], 3)
        self.assertEqual(result['incomplete'], 1)
        self.assertEqual(result['VRR'], 1 / 3)
        self.assertEqual(result['FAR'], 0.5)

    def test_no_positive_claims_has_undefined_far(self):
        self.assertIsNone(summarize([record('A', claim=0)])['FAR'])

    def test_pairs_match_ids_despite_different_directory_order(self):
        pairs = pair_rows(['A', 'B'], [record('B'), record('A')],
                          [record('A', verified=1), record('B')])
        self.assertEqual([a['vuln_id'] for _, a, _ in pairs], ['A', 'B'])
        self.assertEqual(pairs[0][2]['verified'], 1)

    def test_duplicate_or_different_cases_are_rejected(self):
        for cases, rows in [(['A', 'A'], [record('A'), record('A')]),
                            (['A', 'B'], [record('A'), record('C')])]:
            with self.assertRaises(ValueError):
                pair_rows(cases, rows, rows)
