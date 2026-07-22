#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from .obligation_utils import (
    classify_obligation_match,
    normalize_guard_class,
    should_apply_debug_assert_special_case,
    should_apply_validate_macro_special_case,
)


def guardir_rules_verdict(guard_ir: dict[str, Any]) -> str:
    if guard_ir["observed_guard_class"] in {"none", "overflow_like", "zero_test_only"}:
        return "CHECK_ELIMINATED"
    if guard_ir.get("validate_macro_like") and guard_ir.get("macro_expands_noop") and guard_ir.get("first_hazard_kind") != "none":
        return "CHECK_ELIMINATED"
    return "CHECK_PRESENT"


def choose_unified_cascade_verdict(
    heuristic_verdict: str,
    guard_ir: dict[str, Any],
    backend_verdict: str | None,
    *,
    expected_guard_class: str | None = None,
    parsed_expected_check: str | None = None,
    unsupported_expected_check_gate: bool = False,
    unsupported_expected_check_reason: str | None = None,
    protected_entity: str | None = None,
    selection_reason: list[str] | None = None,
    source_row: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    rules_verdict = guardir_rules_verdict(guard_ir)
    bucket = guard_ir.get("confidence_bucket", "medium")
    obligation_match_status = classify_obligation_match(parsed_expected_check, expected_guard_class, backend_verdict)
    source_obligation_mode = expected_guard_class is not None

    enriched_row = source_row or {
        "expected_guard_class": expected_guard_class,
        "protected_entity": protected_entity,
        "selection_reason": selection_reason or [],
        "guard_ir": guard_ir,
    }

    if should_apply_validate_macro_special_case(enriched_row, guard_ir):
        return "CHECK_ELIMINATED", "validate_macro_noop_special_case", obligation_match_status

    if should_apply_debug_assert_special_case(enriched_row, guard_ir):
        return "CHECK_ELIMINATED", "debug_assert_stripped_special_case", obligation_match_status

    if unsupported_expected_check_gate:
        reason = unsupported_expected_check_reason or "unsupported_expected_check_gate"
        return "CHECK_PRESENT", reason, obligation_match_status

    if obligation_match_status == "invented_stronger_check":
        return "CHECK_PRESENT", "invented_expected_check_gate", obligation_match_status

    if obligation_match_status == "unrelated_preserved_check" and backend_verdict == "CHECK_PRESENT":
        return "CHECK_ELIMINATED", "unrelated_preserved_check_gate", obligation_match_status

    if source_obligation_mode and backend_verdict:
        return backend_verdict, "source_obligation_backend_final", obligation_match_status

    if heuristic_verdict == "CHECK_ELIMINATED" and guard_ir.get("easy_positive"):
        return "CHECK_ELIMINATED", "high_bucket_easy_positive", obligation_match_status
    if guard_ir["observed_guard_class"] == "zero_test_only":
        return "CHECK_ELIMINATED", "high_bucket_zero_test", obligation_match_status
    if bucket == "high":
        return rules_verdict, "high_bucket_guardir_final", obligation_match_status
    if (
        bucket == "medium"
        and guard_ir["observed_guard_class"] == "range_or_bound_like"
        and guard_ir.get("unguarded_arg_store")
        and guard_ir.get("first_store_index") is not None
        and (guard_ir.get("first_call_index") is None or guard_ir.get("first_store_index") < guard_ir.get("first_call_index"))
        and guard_ir.get("calls", 999) <= 1
        and obligation_match_status != "invented_stronger_check"
    ):
        return "CHECK_ELIMINATED", "medium_bucket_early_store_invariant_flip", obligation_match_status
    if bucket == "medium" and backend_verdict:
        if obligation_match_status == "invented_stronger_check":
            return "CHECK_PRESENT", "medium_bucket_invented_check_override", obligation_match_status
        if obligation_match_status == "matched_obligation" and guard_ir.get("validate_macro_like") and guard_ir.get("macro_expands_noop"):
            return "CHECK_ELIMINATED", "medium_bucket_validate_macro_override", obligation_match_status
        return backend_verdict, "medium_bucket_backend_tiebreak", obligation_match_status
    if bucket == "low":
        return heuristic_verdict, "low_bucket_heuristic_fallback", obligation_match_status
    if backend_verdict:
        return backend_verdict, "backend_fallback", obligation_match_status
    return heuristic_verdict, "heuristic_fallback", obligation_match_status
