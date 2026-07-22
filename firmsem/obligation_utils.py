from __future__ import annotations

import json
import re
from typing import Any

STRUCTURED_FIELDS = ("verdict", "source_predicate", "purpose", "expected_check", "evidence")


def normalize_guard_class(expected_guard_class: str | None) -> str:
    value = (expected_guard_class or "").strip().lower()
    mapping = {
        "nonnull_preconditions": "nonnull",
        "nonnull_wrapper_preconditions": "nonnull",
        "bounds_checks": "bounds",
        "range_and_bounds_preconditions": "bounds",
        "defensive_return_on_error": "defensive_return",
        "defensive_return_and_goto_fail": "defensive_return",
        "validate_macro_preconditions": "validate_macro",
        "assert_preconditions_and_postconditions": "assert",
        "assert_and_nonnull_preconditions": "assert_and_nonnull",
        "misc_source_level_checks": "misc",
        "parser_integrity_checks": "parser_integrity",
        "allocator_result_checks": "allocator_result",
    }
    return mapping.get(value, value or "unknown")


def normalize_expected_check_text(text: str | None) -> str:
    value = (text or "").strip().lower()
    if not value:
        return "unknown"
    if any(token in value for token in ("validate", "mpi_validate", "nonnull mpi", "nonnull mpi")):
        return "validate_macro"
    if any(token in value for token in ("assert", "invariant", "postcondition", "precondition")):
        return "assert"
    if any(token in value for token in ("null", "nonnull", "nullptr", "not null")):
        return "nonnull"
    if any(token in value for token in ("overflow", "underflow", "carry", "borrow", "wrap")):
        return "overflow"
    if any(token in value for token in ("alloc", "malloc", "calloc", "allocation", "out of memory", "oom")):
        return "allocator_result"
    if any(token in value for token in ("goto fail", "return error", "error path", "fail path", "defensive return")):
        return "defensive_return"
    if any(token in value for token in ("parser", "integrity", "utf", "decode", "format")):
        return "parser_integrity"
    if any(
        token in value
        for token in (
            "bound",
            "bounds",
            "range",
            "limit",
            "index",
            "length",
            "size",
            "base",
            "radix",
            "minimum size",
            "max limbs",
            "bit value",
        )
    ):
        return "bounds"
    return "misc"


def parse_structured_detection_fields(text: str) -> dict[str, str | None]:
    if not text:
        return {field: None for field in STRUCTURED_FIELDS}

    payload = {field: None for field in STRUCTURED_FIELDS}
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            for field in STRUCTURED_FIELDS:
                value = parsed.get(field)
                if isinstance(value, str) and value.strip():
                    payload[field] = value.strip()
            return payload

    patterns = {
        "verdict": re.compile(r"^\s*VERDICT:\s*(.+?)\s*$", flags=re.IGNORECASE | re.MULTILINE),
        "source_predicate": re.compile(r"^\s*SOURCE_PREDICATE:\s*(.+?)\s*$", flags=re.IGNORECASE | re.MULTILINE),
        "purpose": re.compile(r"^\s*PURPOSE:\s*(.+?)\s*$", flags=re.IGNORECASE | re.MULTILINE),
        "expected_check": re.compile(r"^\s*EXPECTED_CHECK:\s*(.+?)\s*$", flags=re.IGNORECASE | re.MULTILINE),
        "evidence": re.compile(r"^\s*EVIDENCE:\s*(.+?)\s*$", flags=re.IGNORECASE | re.MULTILINE),
    }
    for field, pattern in patterns.items():
        match = pattern.search(text)
        if match:
            payload[field] = match.group(1).strip()
    return payload


def classify_obligation_match(
    parsed_expected_check: str | None,
    expected_guard_class: str | None,
    verdict: str | None,
) -> str:
    source_category = normalize_guard_class(expected_guard_class)
    predicted_category = normalize_expected_check_text(parsed_expected_check)
    if source_category == "unknown" or predicted_category == "unknown":
        return "ambiguous_obligation"
    if source_category == predicted_category:
        return "matched_obligation"
    if source_category == "assert_and_nonnull" and predicted_category in {"assert", "nonnull"}:
        return "matched_obligation"
    if source_category == "validate_macro" and predicted_category in {"validate_macro", "nonnull"}:
        return "matched_obligation"
    if source_category == "nonnull" and predicted_category == "validate_macro":
        return "matched_obligation"
    if verdict == "CHECK_PRESENT":
        return "unrelated_preserved_check"
    if verdict == "CHECK_ELIMINATED":
        return "invented_stronger_check"
    return "ambiguous_obligation"


def compact_source_excerpt(source_code: str | None, expected_guard_class: str | None, max_lines: int = 8) -> str:
    code = (source_code or "").replace("\r\n", "\n")
    if not code.strip():
        return ""
    lines = code.splitlines()
    lowered = [line.lower() for line in lines]
    category = normalize_guard_class(expected_guard_class)
    keyword_map = {
        "nonnull": ["null", "nonnull", "validate", "assert", "return", "if ("],
        "validate_macro": ["validate", "internal_validate", "mpi_validate", "return", "if ("],
        "assert": ["assert", "__assert", "panic", "abort", "if ("],
        "bounds": ["bound", "range", "length", "size", "index", "limit", "base", "radix", "if ("],
        "defensive_return": ["return", "goto fail", "error", "invalid", "if ("],
        "allocator_result": ["alloc", "calloc", "malloc", "return", "if ("],
        "parser_integrity": ["parse", "utf", "decode", "invalid", "return", "if ("],
    }
    keywords = keyword_map.get(category, ["if (", "return", "assert", "validate"])
    hits = [idx for idx, line in enumerate(lowered) if any(keyword in line for keyword in keywords)]
    if not hits:
        start = 0
    else:
        start = max(0, hits[0] - 1)
    excerpt = lines[start : start + max_lines]
    return "\n".join(excerpt).strip()


def _source_lines(source_code: str | None) -> list[str]:
    return (source_code or "").replace("\r\n", "\n").splitlines()


def _first_matching_line(source_code: str | None, predicates: list[re.Pattern[str]]) -> str:
    for line in _source_lines(source_code):
        stripped = line.strip()
        if not stripped:
            continue
        for pattern in predicates:
            if pattern.search(stripped):
                return stripped
    return ""


def _collect_matching_lines(source_code: str | None, predicates: list[re.Pattern[str]], limit: int = 2) -> list[str]:
    matches: list[str] = []
    for line in _source_lines(source_code):
        stripped = line.strip()
        if not stripped:
            continue
        if any(pattern.search(stripped) for pattern in predicates):
            matches.append(stripped)
            if len(matches) >= limit:
                break
    return matches


def derive_source_predicate_exact(row: dict[str, Any]) -> str:
    source_code = row.get("source_code") or ""
    expected = normalize_guard_class(row.get("expected_guard_class"))
    function_name = (row.get("function_name") or "").lower()
    if expected == "validate_macro":
        line = _first_matching_line(
            source_code,
            [
                re.compile(r"\bVALIDATE(?:_RET)?\s*\(", re.IGNORECASE),
                re.compile(r"\bMPI_VALIDATE(?:_RET)?\s*\(", re.IGNORECASE),
                re.compile(r"\bMBEDTLS_.*VALIDATE(?:_RET)?\s*\(", re.IGNORECASE),
            ],
        )
        if line:
            return line
    if expected in {"assert", "assert_and_nonnull"}:
        lines = _collect_matching_lines(
            source_code,
            [
                re.compile(r"\bassert\s*\(", re.IGNORECASE),
                re.compile(r"__ASSERT", re.IGNORECASE),
                re.compile(r"FMT_ASSERT", re.IGNORECASE),
            ],
            limit=2,
        )
        if lines:
            return " | ".join(lines)
    if expected in {"nonnull", "bounds", "defensive_return", "allocator_result", "parser_integrity", "misc"}:
        line = _first_matching_line(
            source_code,
            [
                re.compile(r"\bif\s*\("),
                re.compile(r"\bCHECKIF\s*\(", re.IGNORECASE),
                re.compile(r"\breturn\b", re.IGNORECASE),
            ],
        )
        if line:
            return line
    protected_entity = (row.get("protected_entity") or "").strip()
    if expected in {"nonnull", "validate_macro"} and protected_entity:
        return protected_entity
    if "itoa" in function_name or "ltoa" in function_name:
        return "no explicit runtime size predicate in source signature"
    return ""


def derive_obligation_quality(row: dict[str, Any], source_predicate_exact: str) -> dict[str, Any]:
    source_code = row.get("source_code") or ""
    source_signals = (row.get("guard_ir") or {}).get("source_signals", {})
    expected = normalize_guard_class(row.get("expected_guard_class"))
    function_name = (row.get("function_name") or "").lower()
    reasons = set(row.get("selection_reason") or [])

    predicate_kind = "misc"
    if expected in {"validate_macro"}:
        predicate_kind = "macro_guard"
    elif expected in {"assert", "assert_and_nonnull"}:
        predicate_kind = "assert"
    elif expected == "nonnull":
        if any(token in source_predicate_exact.lower() for token in ("*p", "->", "[", "string terminator", "'\\0'")):
            predicate_kind = "pointee_value"
        else:
            predicate_kind = "ptr_null"
    elif expected == "bounds":
        predicate_kind = "range"
    elif expected == "defensive_return":
        predicate_kind = "helper_return"
    elif expected == "allocator_result":
        predicate_kind = "helper_return"
    elif expected == "parser_integrity":
        predicate_kind = "helper_return"

    macro_config_required = expected in {"validate_macro", "assert", "assert_and_nonnull"}
    helper_context_required = expected in {"defensive_return", "parser_integrity"} or normalize_guard_class(row.get("expected_guard_class")) == "nonnull" and "wrapper" in (row.get("expected_guard_class") or "")

    if "itoa" in function_name or "ltoa" in function_name:
        obligation_exactness = "api_contract"
        runtime_required = False
        label_audit_priority = "high"
    elif not source_predicate_exact:
        obligation_exactness = "ambiguous"
        runtime_required = False
        label_audit_priority = "high"
    elif helper_context_required and "(" in source_predicate_exact and "if" not in source_predicate_exact.lower():
        obligation_exactness = "helper_contract"
        runtime_required = True
        label_audit_priority = "medium"
    else:
        obligation_exactness = "exact_runtime_predicate"
        runtime_required = True
        label_audit_priority = "low"

    if predicate_kind == "pointee_value":
        label_audit_priority = "high"
    if macro_config_required and not (row.get("guard_ir") or {}).get("macro_definition_excerpt") and "mbedtls_validate_macro_noop" not in reasons:
        label_audit_priority = "high"
    if int(source_signals.get("assert_count", 0) or 0) > 0 and expected == "assert":
        macro_config_required = True

    return {
        "obligation_exactness": obligation_exactness,
        "predicate_kind": predicate_kind,
        "runtime_required": runtime_required,
        "macro_config_required": macro_config_required,
        "helper_context_required": helper_context_required,
        "label_audit_priority": label_audit_priority,
    }


def compact_hazard_excerpt(row: dict[str, Any], max_lines: int = 6) -> str:
    guard_ir = row.get("guard_ir") or {}
    if isinstance(guard_ir, dict):
        for key in ("hazard_excerpt", "asm_observation_excerpt"):
            value = guard_ir.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    source_code = (row.get("source_code") or "").replace("\r\n", "\n")
    if not source_code.strip():
        return ""
    lines = source_code.splitlines()
    lowered = [line.lower() for line in lines]
    hits = [
        idx
        for idx, line in enumerate(lowered)
        if any(token in line for token in ("->", "[", "*", "memcpy", "memmove", "strcpy", "calloc", "malloc", "free", "shift", "div"))
    ]
    if not hits:
        return "\n".join(lines[:max_lines]).strip()
    start = max(0, hits[0] - 1)
    return "\n".join(lines[start : start + max_lines]).strip()


def macro_config_evidence(row: dict[str, Any]) -> str:
    """Return only build provenance captured independently of the gold label.

    Auditor notes and positive-mining reasons are label-construction artifacts.
    Feeding them back to a classifier leaks the adjudicated outcome, so they
    must never be used as model evidence.
    """
    guard_ir = row.get("guard_ir") or {}
    if isinstance(guard_ir, dict):
        for key in ("macro_definition_excerpt",):
            value = guard_ir.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def build_source_obligation_fields(row: dict[str, Any]) -> dict[str, str]:
    source_predicate_exact = derive_source_predicate_exact(row)
    quality = derive_obligation_quality(row, source_predicate_exact)
    return {
        "source_obligation_category": normalize_guard_class(row.get("expected_guard_class")),
        "source_predicate_exact": source_predicate_exact,
        "source_guard_excerpt": compact_source_excerpt(row.get("source_code"), row.get("expected_guard_class")),
        "macro_config_evidence": macro_config_evidence(row),
        "first_hazard_excerpt": compact_hazard_excerpt(row),
        "obligation_exactness": quality["obligation_exactness"],
        "predicate_kind": quality["predicate_kind"],
        "runtime_required": "true" if quality["runtime_required"] else "false",
        "macro_config_required": "true" if quality["macro_config_required"] else "false",
        "helper_context_required": "true" if quality["helper_context_required"] else "false",
        "label_audit_priority": quality["label_audit_priority"],
    }


def classify_unsupported_expected_check(
    row: dict[str, Any],
    parsed_expected_check: str | None,
    source_predicate_exact: str | None,
) -> tuple[bool, str | None]:
    expected_text = (parsed_expected_check or "").lower()
    if not expected_text:
        return False, None
    predicate_kind = build_source_obligation_fields(row)["predicate_kind"]
    obligation_exactness = build_source_obligation_fields(row)["obligation_exactness"]
    source_predicate_exact = (source_predicate_exact or "").lower()
    function_name = (row.get("function_name") or "").lower()
    source_code = (row.get("source_code") or "").lower()

    if any(token in expected_text for token in ("null", "nonnull", "not null")) and predicate_kind in {"pointee_value", "range", "helper_return"}:
        return True, "direct_null_not_source_backed"
    if any(token in expected_text for token in ("buffer", "capacity", "length", "size")) and ("itoa" in function_name or "ltoa" in function_name):
        return True, "no_runtime_size_parameter"
    if "call" in expected_text and obligation_exactness in {"helper_contract", "ambiguous"}:
        return True, "helper_name_absence_not_sufficient"
    if any(token in expected_text for token in ("assert", "debug", "config")) and not build_source_obligation_fields(row)["macro_config_evidence"]:
        return True, "missing_macro_or_config_evidence"
    if source_predicate_exact and all(token not in source_predicate_exact for token in expected_text.split()[:2]):
        if any(token in expected_text for token in ("null", "buffer", "capacity", "helper", "call", "assert")):
            return True, "expected_check_not_supported_by_exact_predicate"
    if "size" in expected_text and "size_t" not in source_code and "len" not in source_code and "length" not in source_code:
        return True, "size_check_without_runtime_size_input"
    return False, None


def should_apply_validate_macro_special_case(row: dict[str, Any], guard_ir: dict[str, Any]) -> bool:
    reasons = set(row.get("selection_reason") or [])
    if {
        "mbedtls_validate_macro_noop",
        "objdump_confirms_no_equivalent_binary_guard",
    }.issubset(reasons):
        return True
    return (
        normalize_guard_class(row.get("expected_guard_class")) == "validate_macro"
        and "mbedtls_validate_macro_noop" in reasons
        and bool(guard_ir.get("first_hazard_kind"))
        and not guard_ir.get("equivalent_guard_match")
    )


def should_apply_debug_assert_special_case(row: dict[str, Any], guard_ir: dict[str, Any]) -> bool:
    expected = normalize_guard_class(row.get("expected_guard_class"))
    if expected not in {"assert", "assert_and_nonnull"}:
        return False
    source_signals = (row.get("guard_ir") or {}).get("source_signals", {})
    asm_signals = (row.get("guard_ir") or {}).get("asm_signals", {})
    assert_count = int(source_signals.get("assert_count", 0) or 0)
    fail_hits = int(asm_signals.get("fail_symbol_hits", 0) or 0)
    return assert_count > 0 and fail_hits == 0 and not guard_ir.get("equivalent_guard_match")


def compact_protected_entity(row: dict[str, Any]) -> str:
    entity = (row.get("protected_entity") or "").strip()
    return entity[:240]
