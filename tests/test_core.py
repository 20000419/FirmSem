from __future__ import annotations

import unittest

from firmsem.guard_ir_utils import extract_guard_ir
from firmsem.metrics_utils import classification_metrics_from_counts
from firmsem.obligation_utils import parse_structured_detection_fields


class GuardIRTests(unittest.TestCase):
    def test_direct_null_guard_precedes_hazard(self) -> None:
        record = extract_guard_ir(
            "test %rdi, %rdi\nje .Lfail\nmov (%rdi), %eax\nret"
        )
        self.assertFalse(record.unguarded_arg_access)
        self.assertEqual(record.first_hazard_kind, "arg_memory_access")

    def test_straight_line_dereference_is_unprotected(self) -> None:
        record = extract_guard_ir("mov (%rdi), %eax\nret")
        self.assertFalse(record.equivalent_guard_match)
        self.assertTrue(record.unguarded_arg_access)


class UtilityTests(unittest.TestCase):
    def test_structured_output_parser(self) -> None:
        parsed = parse_structured_detection_fields(
            "VERDICT: CHECK_PRESENT\nEXPECTED_CHECK: p != NULL\nEVIDENCE: guarded"
        )
        self.assertEqual(parsed["verdict"], "CHECK_PRESENT")

    def test_metrics(self) -> None:
        metrics = classification_metrics_from_counts(9, 1, 0, 6)
        self.assertEqual(metrics["precision"], 0.9)
        self.assertEqual(metrics["recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
