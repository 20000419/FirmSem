#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any


EQ_BRANCHES = {"je", "jne", "jz", "jnz"}
RANGE_BRANCHES = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
    "jng",
    "jnge",
    "jnl",
    "jnle",
}
ARITHMETIC_MNEMONICS = {"add", "sub", "imul", "mul", "idiv", "div", "sal", "sar", "shl", "shr", "xor", "or", "and", "lea"}
MEMORY_OPERAND_PATTERN = re.compile(r"\([^)]*\)|\[[^\]]*\]")
OBJdump_PATTERN = re.compile(r"^[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+([A-Za-z.][A-Za-z0-9.]*)\s*(.*)$")
REGISTER_PATTERN = re.compile(r"%([a-z0-9]+)")
ARG_REGISTERS = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}


@dataclass(frozen=True)
class GuardIRRecord:
    instructions: int
    cmp_test: int
    jcc: int
    calls: int
    loads_stores: int
    arith_ops: int
    indexed_memory_ops: int
    immediate_moves: int
    first_cmp_index: int | None
    first_call_index: int | None
    first_store_index: int | None
    post_call_test: bool
    post_store_test: bool
    branch_mnemonics: list[str]
    call_targets: list[str]
    indirect_calls: int
    early_indirect_calls: int
    unguarded_arg_access: bool
    unguarded_arg_store: bool
    paired_indirect_result_check: bool
    mixed_guarded_index_access: bool
    first_hazard_kind: str
    first_hazard_operand: str | None
    first_hazard_index: int | None
    normalized_guard_predicate: str
    equivalent_guard_match: bool
    debug_assert_like: bool
    validate_macro_like: bool
    macro_expands_noop: bool
    obligation_mismatch_gate: bool
    observed_guard_class: str
    confidence_bucket: str
    ambiguity_flags: list[str]
    easy_positive: bool
    route_to_verifier: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def instruction_lines(body: str) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.endswith(":") or line.startswith("."):
            continue
        match = OBJdump_PATTERN.match(line)
        if match:
            parsed.append((match.group(1), match.group(2).strip()))
            continue
        parts = re.split(r"\s+", line, maxsplit=1)
        mnemonic = parts[0]
        operands = parts[1].strip() if len(parts) > 1 else ""
        if re.match(r"^[A-Za-z.][A-Za-z0-9.]*$", mnemonic) and not mnemonic.startswith("."):
            parsed.append((mnemonic, operands))
    return parsed


def _memory_operands(operands: str) -> list[str]:
    return MEMORY_OPERAND_PATTERN.findall(operands)


def _count_load_store_operands(instructions: list[tuple[str, str]]) -> int:
    return sum(1 for _, operands in instructions if _memory_operands(operands))


def _count_indexed_memory_operands(instructions: list[tuple[str, str]]) -> int:
    total = 0
    for _, operands in instructions:
        for memory_operand in _memory_operands(operands):
            if "," in memory_operand:
                total += 1
    return total


def _count_immediate_moves(instructions: list[tuple[str, str]]) -> int:
    return sum(
        1
        for mnemonic, operands in instructions
        if mnemonic.startswith("mov") and ("$" in operands or re.search(r"\b0x[0-9a-fA-F]+\b", operands))
    )


def _first_index(matches: list[int]) -> int | None:
    return matches[0] if matches else None


def _split_operands(operands: str) -> list[str]:
    if not operands:
        return []
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in operands:
        if char == "(":
            depth += 1
        elif char == ")" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _normalize_register(register_name: str) -> str:
    register_name = register_name.lower()
    mapping = {
        "edi": "rdi",
        "di": "rdi",
        "dil": "rdi",
        "esi": "rsi",
        "si": "rsi",
        "sil": "rsi",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "r8d": "r8",
        "r8w": "r8",
        "r8b": "r8",
        "r9d": "r9",
        "r9w": "r9",
        "r9b": "r9",
        "eax": "rax",
        "ax": "rax",
        "al": "rax",
        "ebx": "rbx",
        "bx": "rbx",
        "bl": "rbx",
        "ebp": "rbp",
        "bp": "rbp",
        "bpl": "rbp",
        "esp": "rsp",
        "sp": "rsp",
        "spl": "rsp",
        "r10d": "r10",
        "r10w": "r10",
        "r10b": "r10",
        "r11d": "r11",
        "r11w": "r11",
        "r11b": "r11",
        "r12d": "r12",
        "r12w": "r12",
        "r12b": "r12",
        "r13d": "r13",
        "r13w": "r13",
        "r13b": "r13",
        "r14d": "r14",
        "r14w": "r14",
        "r14b": "r14",
        "r15d": "r15",
        "r15w": "r15",
        "r15b": "r15",
    }
    return mapping.get(register_name, register_name)


def _registers_in_operand(operand: str) -> list[str]:
    return [_normalize_register(match.group(1)) for match in REGISTER_PATTERN.finditer(operand)]


def _arg_family_for_register(register_name: str, aliases: dict[str, str]) -> str | None:
    normalized = _normalize_register(register_name)
    if normalized in aliases:
        return aliases[normalized]
    if normalized in ARG_REGISTERS:
        return normalized
    return None


def _is_self_null_test(mnemonic: str, operands: str, aliases: dict[str, str]) -> str | None:
    parts = _split_operands(operands)
    if mnemonic.startswith("test") and len(parts) == 2 and parts[0] == parts[1]:
        regs = _registers_in_operand(parts[0])
        if len(regs) == 1:
            return _arg_family_for_register(regs[0], aliases)
    if mnemonic.startswith("cmp") and len(parts) == 2:
        left, right = parts
        left_regs = _registers_in_operand(left)
        right_regs = _registers_in_operand(right)
        if left in {"$0x0", "$0", "0x0", "0"} and len(right_regs) == 1:
            return _arg_family_for_register(right_regs[0], aliases)
        if right in {"$0x0", "$0", "0x0", "0"} and len(left_regs) == 1:
            return _arg_family_for_register(left_regs[0], aliases)
    return None


def _analyze_arg_guard_flow(instructions: list[tuple[str, str]]) -> tuple[bool, bool, bool]:
    aliases: dict[str, str] = {}
    guarded_args: set[str] = set()
    pending_guard_arg: str | None = None
    unguarded_access = False
    unguarded_store = False
    mixed_guarded_index_access = False

    for index, (mnemonic, operands) in enumerate(instructions[:40]):
        parts = _split_operands(operands)
        if mnemonic.startswith("mov") and len(parts) == 2:
            src, dst = parts
            src_regs = _registers_in_operand(src)
            dst_regs = _registers_in_operand(dst)
            if len(src_regs) == 1 and len(dst_regs) == 1 and not _memory_operands(src) and not _memory_operands(dst):
                source_arg = _arg_family_for_register(src_regs[0], aliases)
                if source_arg is not None:
                    aliases[_normalize_register(dst_regs[0])] = source_arg
                else:
                    aliases.pop(_normalize_register(dst_regs[0]), None)
            elif len(dst_regs) == 1 and not _memory_operands(dst):
                aliases.pop(_normalize_register(dst_regs[0]), None)

        guarded_arg = _is_self_null_test(mnemonic, operands, aliases)
        if guarded_arg is not None:
            pending_guard_arg = guarded_arg

        if mnemonic.startswith("j") and mnemonic != "jmp" and pending_guard_arg is not None:
            guarded_args.add(pending_guard_arg)
            pending_guard_arg = None

        memory_operands = _memory_operands(operands)
        if memory_operands:
            touched_args = {
                arg_reg
                for memory_operand in memory_operands
                for register_name in _registers_in_operand(memory_operand)
                for arg_reg in [_arg_family_for_register(register_name, aliases)]
                if arg_reg is not None
            }
            if not mixed_guarded_index_access:
                for memory_operand in memory_operands:
                    arg_regs_in_memory = {
                        arg_reg
                        for register_name in _registers_in_operand(memory_operand)
                        for arg_reg in [_arg_family_for_register(register_name, aliases)]
                        if arg_reg is not None
                    }
                    if (
                        len(arg_regs_in_memory) >= 2
                        and guarded_args
                        and (arg_regs_in_memory & guarded_args)
                        and (arg_regs_in_memory - guarded_args)
                    ):
                        mixed_guarded_index_access = True
            unguarded_touched_args = touched_args.difference(guarded_args)
            if unguarded_touched_args:
                unguarded_access = True
                if len(parts) >= 2 and _memory_operands(parts[-1]) and mnemonic not in {"cmp", "test"}:
                    unguarded_store = True
        if index >= 20 and unguarded_access and unguarded_store:
            break

    return unguarded_access, unguarded_store, mixed_guarded_index_access


def _detect_paired_indirect_result_check(instructions: list[tuple[str, str]]) -> tuple[int, int, bool]:
    indirect_indices = [
        index
        for index, (mnemonic, operands) in enumerate(instructions)
        if mnemonic.startswith("call") and "*" in operands
    ]
    indirect_calls = len(indirect_indices)
    early_indirect_calls = sum(1 for index in indirect_indices if index < 24)
    early_window = instructions[:32]
    has_memory_zero_check = any(
        mnemonic.startswith("cmp") and _memory_operands(operands) and ("$0x0" in operands or "$0" in operands)
        for mnemonic, operands in early_window
    )
    has_result_test = any(
        mnemonic.startswith("test") and "%rax" in operands
        for mnemonic, operands in early_window
    )
    has_sete = any(mnemonic == "sete" for mnemonic, _ in early_window)
    paired_check = early_indirect_calls >= 2 and has_memory_zero_check and has_result_test and has_sete
    return indirect_calls, early_indirect_calls, paired_check


def _track_aliases(aliases: dict[str, str], mnemonic: str, operands: str) -> None:
    parts = _split_operands(operands)
    if mnemonic.startswith("mov") and len(parts) == 2:
        src, dst = parts
        src_regs = _registers_in_operand(src)
        dst_regs = _registers_in_operand(dst)
        if len(src_regs) == 1 and len(dst_regs) == 1 and not _memory_operands(src) and not _memory_operands(dst):
            source_arg = _arg_family_for_register(src_regs[0], aliases)
            if source_arg is not None:
                aliases[_normalize_register(dst_regs[0])] = source_arg
            else:
                aliases.pop(_normalize_register(dst_regs[0]), None)
        elif len(dst_regs) == 1 and not _memory_operands(dst):
            aliases.pop(_normalize_register(dst_regs[0]), None)


def _detect_first_hazard(instructions: list[tuple[str, str]]) -> tuple[str, str | None, int | None]:
    aliases: dict[str, str] = {}
    for index, (mnemonic, operands) in enumerate(instructions[:64]):
        _track_aliases(aliases, mnemonic, operands)
        if mnemonic.startswith("call") and "*" in operands:
            regs = _registers_in_operand(operands)
            arg_reg = next((_arg_family_for_register(reg, aliases) for reg in regs if _arg_family_for_register(reg, aliases) is not None), None)
            return "indirect_call", arg_reg, index
        memory_operands = _memory_operands(operands)
        if not memory_operands:
            continue
        touched_args = [
            arg_reg
            for memory_operand in memory_operands
            for register_name in _registers_in_operand(memory_operand)
            for arg_reg in [_arg_family_for_register(register_name, aliases)]
            if arg_reg is not None
        ]
        if not touched_args:
            continue
        if mnemonic in {"cmp", "test", "lea"}:
            continue
        parts = _split_operands(operands)
        if len(parts) >= 2 and _memory_operands(parts[-1]) and mnemonic.startswith("mov"):
            return "arg_store", touched_args[0], index
        return "arg_memory_access", touched_args[0], index
    return "none", None, None


def _detect_transformed_range_guard(instructions: list[tuple[str, str]]) -> bool:
    has_unsigned_range_branch = any(
        mnemonic in {"ja", "jae", "jb", "jbe", "jna", "jnae", "jnb", "jnbe"}
        for mnemonic, _ in instructions[:24]
    )
    has_lea_normalization = any(
        mnemonic == "lea" and re.search(r"-?(?:0x[0-9a-fA-F]+|\d+)", operands)
        for mnemonic, operands in instructions[:24]
    )
    has_subtract_compare = any(
        mnemonic.startswith("sub") for mnemonic, _ in instructions[:24]
    ) and any(mnemonic.startswith("cmp") for mnemonic, _ in instructions[:24])
    return has_unsigned_range_branch and (has_lea_normalization or has_subtract_compare)


def _detect_overflow_equivalent_guard(instructions: list[tuple[str, str]]) -> bool:
    early = instructions[:24]
    has_arith = any(mnemonic in {"add", "sub", "imul", "mul"} for mnemonic, _ in early)
    has_overflow_branch = any(mnemonic in {"jo", "jno", "jb", "jbe", "ja", "jae"} for mnemonic, _ in early)
    return has_arith and has_overflow_branch


def _detect_sign_test_guard(instructions: list[tuple[str, str]]) -> bool:
    early = instructions[:24]
    has_test = any(mnemonic.startswith("test") for mnemonic, _ in early)
    has_sign_branch = any(mnemonic in {"js", "jns"} for mnemonic, _ in early)
    return has_test and has_sign_branch


def _normalize_guard_predicate(observed_guard_class: str, instructions: list[tuple[str, str]]) -> tuple[str, bool]:
    transformed_range = _detect_transformed_range_guard(instructions)
    overflow_equiv = _detect_overflow_equivalent_guard(instructions)
    sign_guard = _detect_sign_test_guard(instructions)
    if observed_guard_class in {"zero_test_only", "null_check_like"}:
        return "nonnull_guard", True
    if transformed_range:
        return "normalized_range_guard", True
    if overflow_equiv:
        return "overflow_equivalent_guard", True
    if sign_guard:
        return "sign_test_guard", True
    if observed_guard_class == "range_or_bound_like":
        return "range_guard", False
    if observed_guard_class == "branch_without_bound":
        return "generic_branch", False
    if observed_guard_class == "none":
        return "no_guard", False
    if observed_guard_class == "overflow_like":
        return "overflow_like_without_explicit_check", False
    return observed_guard_class, False


def classify_confidence_bucket(
    observed_guard_class: str,
    *,
    instructions: int,
    calls: int,
    indirect_calls: int,
    indexed_memory_ops: int,
    route_to_verifier: bool,
    easy_positive: bool,
) -> str:
    if easy_positive or observed_guard_class == "zero_test_only":
        return "high"
    if observed_guard_class == "range_or_bound_like":
        if instructions <= 48 and calls <= 2 and indirect_calls == 0 and indexed_memory_ops <= 1:
            return "high"
        if instructions > 120 or calls >= 8 or indirect_calls >= 4 or indexed_memory_ops >= 4:
            return "low"
        return "medium"
    if observed_guard_class in {"branch_without_bound", "null_check_like"}:
        if instructions > 80 or calls >= 5 or indirect_calls >= 2:
            return "low"
        return "medium"
    if route_to_verifier:
        return "medium"
    return "high"


def extract_guard_ir(body: str) -> GuardIRRecord:
    instructions = instruction_lines(body)
    mnemonics = [mnemonic for mnemonic, _ in instructions]
    operands = [operand for _, operand in instructions]
    compare_indices = [index for index, mnemonic in enumerate(mnemonics) if mnemonic.startswith("cmp") or mnemonic.startswith("test")]
    branch_mnemonics = [mnemonic for mnemonic in mnemonics if mnemonic.startswith("j") and mnemonic != "jmp"]
    call_indices = [index for index, mnemonic in enumerate(mnemonics) if mnemonic.startswith("call")]
    call_targets = [
        operand.split(",", 1)[0].strip()
        for mnemonic, operand in instructions
        if mnemonic.startswith("call") and operand.strip()
    ]
    indirect_calls, early_indirect_calls, paired_indirect_result_check = _detect_paired_indirect_result_check(instructions)
    unguarded_arg_access, unguarded_arg_store, mixed_guarded_index_access = _analyze_arg_guard_flow(instructions)
    first_hazard_kind, first_hazard_operand, first_hazard_index = _detect_first_hazard(instructions)
    store_indices = [
        index
        for index, (mnemonic, operand) in enumerate(instructions)
        if mnemonic.startswith("mov") and ("$" in operand or re.search(r"\b0x[0-9a-fA-F]+\b", operand)) and _memory_operands(operand)
    ]

    first_cmp_index = _first_index(compare_indices)
    first_call_index = _first_index(call_indices)
    first_store_index = _first_index(store_indices)
    post_call_test = first_cmp_index is not None and first_call_index is not None and first_cmp_index > first_call_index
    post_store_test = first_cmp_index is not None and first_store_index is not None and first_cmp_index > first_store_index

    cmp_test = len(compare_indices)
    jcc = len(branch_mnemonics)
    calls = len(call_indices)
    loads_stores = _count_load_store_operands(instructions)
    indexed_memory_ops = _count_indexed_memory_operands(instructions)
    immediate_moves = _count_immediate_moves(instructions)
    arith_ops = sum(1 for mnemonic in mnemonics if mnemonic in ARITHMETIC_MNEMONICS)
    eq_only = set(branch_mnemonics).issubset(EQ_BRANCHES) if branch_mnemonics else False
    has_mul = any(mnemonic in {"imul", "mul", "idiv", "div"} for mnemonic in mnemonics)

    if cmp_test == 0 and jcc == 0:
        observed_guard_class = "overflow_like" if has_mul else "none"
    elif (
        cmp_test == 1
        and jcc == 1
        and eq_only
        and immediate_moves >= 2
        and indexed_memory_ops == 0
        and not post_call_test
        and not post_store_test
    ):
        observed_guard_class = "zero_test_only"
    elif cmp_test >= 2 or jcc >= 2 or any(branch in RANGE_BRANCHES for branch in branch_mnemonics):
        observed_guard_class = "range_or_bound_like"
    elif cmp_test >= 1 and jcc >= 1 and eq_only:
        observed_guard_class = "null_check_like" if indexed_memory_ops > 0 or post_call_test or post_store_test else "branch_without_bound"
    else:
        observed_guard_class = "branch_without_bound"

    ambiguity_flags: list[str] = []
    if observed_guard_class == "zero_test_only":
        ambiguity_flags.append("zero_test_only")
    if observed_guard_class == "branch_without_bound":
        ambiguity_flags.append("branch_without_bound")
    if indexed_memory_ops > 0 and observed_guard_class != "range_or_bound_like":
        ambiguity_flags.append("offset_access_without_range")
    if calls > 0 and cmp_test == 0 and jcc == 0:
        ambiguity_flags.append("call_result_used_without_guard")

    easy_positive = observed_guard_class in {"none", "overflow_like"}
    route_to_verifier = any(
        flag in {"zero_test_only", "branch_without_bound", "offset_access_without_range"}
        for flag in ambiguity_flags
    )
    normalized_guard_predicate, equivalent_guard_match = _normalize_guard_predicate(observed_guard_class, instructions)
    confidence_bucket = classify_confidence_bucket(
        observed_guard_class,
        instructions=len(instructions),
        calls=calls,
        indirect_calls=indirect_calls,
        indexed_memory_ops=indexed_memory_ops,
        route_to_verifier=route_to_verifier,
        easy_positive=easy_positive,
    )

    return GuardIRRecord(
        instructions=len(instructions),
        cmp_test=cmp_test,
        jcc=jcc,
        calls=calls,
        loads_stores=loads_stores,
        arith_ops=arith_ops,
        indexed_memory_ops=indexed_memory_ops,
        immediate_moves=immediate_moves,
        first_cmp_index=first_cmp_index,
        first_call_index=first_call_index,
        first_store_index=first_store_index,
        post_call_test=post_call_test,
        post_store_test=post_store_test,
        branch_mnemonics=branch_mnemonics,
        call_targets=call_targets,
        indirect_calls=indirect_calls,
        early_indirect_calls=early_indirect_calls,
        unguarded_arg_access=unguarded_arg_access,
        unguarded_arg_store=unguarded_arg_store,
        paired_indirect_result_check=paired_indirect_result_check,
        mixed_guarded_index_access=mixed_guarded_index_access,
        first_hazard_kind=first_hazard_kind,
        first_hazard_operand=first_hazard_operand,
        first_hazard_index=first_hazard_index,
        normalized_guard_predicate=normalized_guard_predicate,
        equivalent_guard_match=equivalent_guard_match,
        debug_assert_like=False,
        validate_macro_like=False,
        macro_expands_noop=False,
        obligation_mismatch_gate=False,
        observed_guard_class=observed_guard_class,
        confidence_bucket=confidence_bucket,
        ambiguity_flags=ambiguity_flags,
        easy_positive=easy_positive,
        route_to_verifier=route_to_verifier,
    )
