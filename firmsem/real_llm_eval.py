#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .obligation_utils import parse_structured_detection_fields
from .metrics_utils import (
    bootstrap_binary_metrics,
    bootstrap_macro_f1,
    classification_metrics_from_counts,
    confusion_counts_from_records,
    precision_recall_curve_points,
    round_ci,
    round4,
    wilson_interval,
)


ROOT = Path(__file__).resolve().parent
EXPERIMENT_JSON = ROOT / "expanded_experiment" / "results" / "experiment_results.json"
ASM_O3 = ROOT / "expanded_experiment" / "asm" / "phantom_O3.s"
PROMPT_DIR = ROOT / "expanded_experiment" / "prompts"
RESULTS_DIR = ROOT / "expanded_experiment" / "results"
RAW_RESULTS_JSON = RESULTS_DIR / "llm_eval_raw_results.json"
METRICS_JSON = RESULTS_DIR / "llm_eval_metrics.json"
SEMANTIC_AUDIT_JSON = ROOT / "expanded_experiment" / "results" / "phantombench_semantic_audit.json"

DEFAULT_OPENAI_MODEL = "gpt-5"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
DEFAULT_GEMINI_MODEL = "gemini-3.1-pro-preview"
DEFAULT_CODEX_CLI_MODEL = "gpt-5.4"
DEFAULT_CLAUDE_CLI_MODEL = "opus"
GEMINI_THINKING_REQUIRED_MODELS = {
    "gemini-3.1-pro-preview",
    "gemini-3.1-pro-preview-customtools",
}
CATEGORY_HINTS = {
    "A": "UB exploitation",
    "B": "dead-code elimination",
    "C": "memory-safety guard removal",
    "D": "timing / side-channel barrier removal",
    "E": "control-flow integrity and arithmetic guard removal",
}


def _get_windows_user_env(name: str) -> str | None:
    if os.name != "nt":
        return None
    try:
        import winreg  # type: ignore

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value) if value else None
    except Exception:  # noqa: BLE001
        return None


def getenv_with_user_fallback(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    user_value = _get_windows_user_env(name)
    if user_value:
        return user_value
    return default


def is_kimi_model(model: str) -> bool:
    normalized = (model or "").strip().lower()
    return normalized.startswith("kimi") or "moonshot" in normalized


@dataclass
class Sample:
    sample_id: int
    function_name: str
    category: str
    pattern_id: int
    pattern_name: str
    pattern_desc: str
    actual_label: str
    actual_group: str
    prompt_path: Path
    prompt_text: str
    asm_text: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate prompts and optionally run real LLM evaluation on PhantomBench O3 assembly."
    )
    parser.add_argument(
        "--provider",
        choices=["auto", "openai", "anthropic", "gemini", "codex_cli", "claude_cli"],
        default="auto",
        help="LLM provider to use. Default: auto-detect from environment variables.",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Override the provider default model.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate prompts and status files without calling any API.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process the first N eligible samples.",
    )
    parser.add_argument(
        "--sample-ids",
        default="",
        help="Comma-separated sample IDs to process.",
    )
    parser.add_argument(
        "--include-category-hint",
        action="store_true",
        help="Include the benchmark category as a Stage-1 semantic family hint in the prompt.",
    )
    parser.add_argument(
        "--task-mode",
        choices=["detection", "routing"],
        default="detection",
        help="Detection predicts missing-check labels; routing predicts Stage-1 semantic groups.",
    )
    parser.add_argument(
        "--prompt-variant",
        choices=["main", "conservative"],
        default="main",
        help="Prompt wording variant for sensitivity checks.",
    )
    parser.add_argument(
        "--prompt-format",
        choices=["structured", "json", "free_text"],
        default="structured",
        help="Requested response format for detection-mode prompts.",
    )
    parser.add_argument(
        "--label-source",
        choices=["marker", "semantic"],
        default="marker",
        help="Ground-truth source for benchmark labels.",
    )
    parser.add_argument(
        "--semantic-audit-json",
        default=str(SEMANTIC_AUDIT_JSON),
        help="Semantic audit artifact used when --label-source=semantic.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=500,
        help="Maximum output tokens for live API calls.",
    )
    parser.add_argument(
        "--thinking-level",
        default="",
        help="Provider-specific thinking level. Used for Gemini 3 models.",
    )
    parser.add_argument(
        "--codex-reasoning-effort",
        default="",
        help="Reasoning effort for codex exec, e.g. low/medium/high.",
    )
    parser.add_argument(
        "--claude-effort",
        default="",
        help="Effort level for claude CLI, e.g. low/medium/high/xhigh/max.",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.0,
        help="Delay between live API calls.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries per sample on transient API failures.",
    )
    parser.add_argument(
        "--run-tag",
        default="",
        help="Optional suffix for prompt/results files, e.g. gemini_flash.",
    )
    parser.add_argument(
        "--parallel-requests",
        type=int,
        default=1,
        help="Number of concurrent model requests to issue. Default: 1.",
    )
    parser.add_argument(
        "--experiment-json",
        default=str(EXPERIMENT_JSON),
        help="Path to experiment_results-style JSON.",
    )
    parser.add_argument(
        "--asm-o3",
        default=str(ASM_O3),
        help="Path to optimized assembly file used for prompts.",
    )
    return parser.parse_args()


def tagged_path(base: Path, run_tag: str) -> Path:
    if not run_tag:
        return base
    safe_tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", run_tag.strip()).strip("._")
    if not safe_tag:
        return base
    if base.suffix:
        return base.with_name(f"{base.stem}_{safe_tag}{base.suffix}")
    return base.with_name(f"{base.name}_{safe_tag}")


def load_experiment(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def extract_function(text: str, func_name: str) -> str:
    pattern = re.compile(
        rf"(?ms)^\s*{re.escape(func_name)}:[^\n]*\n(.*?)(?:^\s*\.(?:cfi_endproc|seh_endproc)\s*$|^\s*# -- End function\s*$)"
    )
    match = pattern.search(text)
    if match:
        return match.group(1).rstrip()

    fallback = re.compile(
        rf"(?ms)^\s*{re.escape(func_name)}:[^\n]*\n(.*?)(?=^\s*\.globl\b|^\s*\.def\b|\Z)"
    )
    match = fallback.search(text)
    return match.group(1).rstrip() if match else ""


def build_detection_prompt(
    sample: Sample,
    include_category_hint: bool,
    prompt_variant: str,
    prompt_format: str,
) -> str:
    lines = [
        "You are labeling one optimized x86-64 assembly function for missing security checks.",
        "Decide whether compiler optimization likely removed a source-level security check.",
    ]
    if prompt_variant == "conservative":
        lines.append(
            "Choose CHECK_ELIMINATED only when the assembly gives strong evidence that a source-level guard is missing."
        )
    if prompt_format == "structured":
        lines.extend(
            [
                "Do not provide chain-of-thought. Return only the four lines below.",
                "",
                "VERDICT: CHECK_ELIMINATED or CHECK_PRESENT",
                "PURPOSE: <at most 12 words>",
                "EXPECTED_CHECK: <at most 12 words>",
                "EVIDENCE: <at most 20 words>",
            ]
        )
    elif prompt_format == "json":
        lines.extend(
            [
                "Do not provide chain-of-thought.",
                "Return only one compact JSON object with the keys verdict, purpose, expected_check, and evidence.",
                'Use this exact shape: {"verdict":"CHECK_ELIMINATED or CHECK_PRESENT","purpose":"...","expected_check":"...","evidence":"..."}',
                "Keep purpose and expected_check short, and keep evidence under 20 words.",
            ]
        )
    else:
        lines.extend(
            [
                "Do not provide chain-of-thought.",
                "Return the verdict on the first line as:",
                "VERDICT: CHECK_ELIMINATED or CHECK_PRESENT",
                "Then write at most two short sentences explaining the likely purpose, expected check, and evidence in free text.",
            ]
        )

    if include_category_hint:
        lines.extend(
            [
                "",
                "Stage-1 semantic family hint:",
                f"- Category {sample.category}: {CATEGORY_HINTS[sample.category]}",
            ]
        )

    lines.extend(
        [
            "",
            f"Function ID: test_{sample.sample_id}",
            f"Pattern family: {sample.pattern_name}",
            "",
            "Assembly:",
            sample.asm_text,
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def build_routing_prompt(sample: Sample) -> str:
    lines = [
        "You are performing Stage-1 routing for one optimized x86-64 assembly function.",
        "Assign the function to the best matching optimization semantic group based on binary structure alone.",
        "Do not infer an exact compiler pass id. Choose only one group.",
        "",
        "A = UB-dominance simplification",
        "B = contradiction / constant-fold dead-branch elimination",
        "C = dominating-write / memory-state simplification",
        "D = barrier / timing / slow-path simplification",
        "E = arithmetic / control-flow guard canonicalization",
        "",
        "Return only the three lines below.",
        "GROUP: A or B or C or D or E",
        "SIGNAL: <at most 12 words>",
        "EVIDENCE: <at most 20 words>",
        "",
        f"Function ID: test_{sample.sample_id}",
        f"Pattern family: {sample.pattern_name}",
        "",
        "Assembly:",
        sample.asm_text,
    ]
    return "\n".join(lines).rstrip() + "\n"


def build_prompt(
    sample: Sample,
    include_category_hint: bool,
    prompt_variant: str,
    task_mode: str,
    prompt_format: str,
) -> str:
    if task_mode == "routing":
        return build_routing_prompt(sample)
    return build_detection_prompt(sample, include_category_hint, prompt_variant, prompt_format)


def selected_ids(sample_ids: str) -> set[int]:
    if not sample_ids.strip():
        return set()
    values = set()
    for part in sample_ids.split(","):
        part = part.strip()
        if not part:
            continue
        values.add(int(part))
    return values


def load_semantic_labels(path: Path, compiler_tag: str) -> dict[int, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    mapping: dict[int, str] = {}
    for row in payload.get("entries", []):
        if row.get("compiler_tag") != compiler_tag:
            continue
        mapping[int(row["sample_id"])] = row["semantic_actual_label"]
    return mapping


def collect_samples(args: argparse.Namespace) -> list[Sample]:
    experiment_json = Path(args.experiment_json).resolve()
    asm_o3_path = Path(args.asm_o3).resolve()
    experiment = load_experiment(experiment_json)
    asm_text = asm_o3_path.read_text(encoding="utf-8", errors="replace")
    selected = selected_ids(args.sample_ids)
    compiler_tag = experiment["metadata"].get("compiler_tag", "").strip()
    semantic_labels: dict[int, str] = {}
    if args.label_source == "semantic":
        semantic_labels = load_semantic_labels(Path(args.semantic_audit_json).resolve(), compiler_tag)
    prompt_dir = tagged_path(PROMPT_DIR, args.run_tag)
    prompt_dir.mkdir(parents=True, exist_ok=True)

    samples: list[Sample] = []
    for row in experiment["samples"]:
        if not row["markers"]["O0"]:
            continue
        if selected and row["id"] not in selected:
            continue

        sample_id = int(row["id"])
        function_name = f"test_{sample_id}"
        function_body = extract_function(asm_text, function_name)
        if not function_body:
            raise ValueError(f"Could not find {function_name} in {asm_o3_path}")

        pattern_info = experiment["metadata"]["pattern_info"][str(row["pattern_id"])]
        actual_label = "CHECK_ELIMINATED" if not row["markers"]["O3"] else "CHECK_PRESENT"
        if args.label_source == "semantic":
            actual_label = semantic_labels.get(sample_id, actual_label)
        prompt_path = prompt_dir / f"sample_{sample_id:03d}.txt"
        sample = Sample(
            sample_id=sample_id,
            function_name=function_name,
            category=row["category"],
            pattern_id=row["pattern_id"],
            pattern_name=pattern_info["name"],
            pattern_desc=pattern_info["desc"],
            actual_label=actual_label,
            actual_group=row["category"],
            prompt_path=prompt_path,
            prompt_text="",
            asm_text=function_body,
        )
        sample.prompt_text = build_prompt(
            sample,
            args.include_category_hint,
            args.prompt_variant,
            args.task_mode,
            args.prompt_format,
        )
        sample.prompt_path.write_text(sample.prompt_text, encoding="utf-8")
        samples.append(sample)

    samples.sort(key=lambda item: item.sample_id)
    if args.limit > 0:
        samples = samples[: args.limit]
    return samples


def detect_provider(provider: str) -> str:
    if provider != "auto":
        return provider
    if getenv_with_user_fallback("CODEX_CLI_MODEL") or getenv_with_user_fallback("CODEX_REASONING_EFFORT"):
        return "codex_cli"
    if getenv_with_user_fallback("CLAUDE_CLI_MODEL") or getenv_with_user_fallback("CLAUDE_CLI_EFFORT"):
        return "claude_cli"
    if getenv_with_user_fallback("ANTHROPIC_API_KEY") or getenv_with_user_fallback("ANTHROPIC_API_KEY_KIMI"):
        return "anthropic"
    if getenv_with_user_fallback("GEMINI_API_KEY"):
        return "gemini"
    if getenv_with_user_fallback("OPENAI_API_KEY") or getenv_with_user_fallback("GLM_API_KEY"):
        return "openai"
    return "none"


def resolve_model(provider: str, explicit_model: str) -> str:
    if explicit_model:
        return explicit_model
    if provider == "codex_cli":
        return getenv_with_user_fallback("CODEX_CLI_MODEL", DEFAULT_CODEX_CLI_MODEL) or DEFAULT_CODEX_CLI_MODEL
    if provider == "claude_cli":
        return getenv_with_user_fallback("CLAUDE_CLI_MODEL", DEFAULT_CLAUDE_CLI_MODEL) or DEFAULT_CLAUDE_CLI_MODEL
    if provider == "openai":
        return getenv_with_user_fallback("OPENAI_MODEL", DEFAULT_OPENAI_MODEL) or DEFAULT_OPENAI_MODEL
    if provider == "anthropic":
        return getenv_with_user_fallback("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL) or DEFAULT_ANTHROPIC_MODEL
    if provider == "gemini":
        return getenv_with_user_fallback("GEMINI_MODEL", DEFAULT_GEMINI_MODEL) or DEFAULT_GEMINI_MODEL
    return ""


def parse_verdict(text: str) -> str | None:
    parsed = parse_structured_detection_fields(text)
    if parsed.get("verdict"):
        verdict = str(parsed["verdict"]).upper()
        if "CHECK_ELIMINATED" in verdict or "CHECK_ELIMIN" in verdict:
            return "CHECK_ELIMINATED"
        if "CHECK_PRESENT" in verdict or "CHECK_PRES" in verdict:
            return "CHECK_PRESENT"
    upper = text.upper()
    if "VERDICT:" in upper:
        verdict_line = upper.split("VERDICT:", 1)[1].splitlines()[0].strip()
        if "CHECK_ELIMINATED" in verdict_line:
            return "CHECK_ELIMINATED"
        if "CHECK_PRESENT" in verdict_line:
            return "CHECK_PRESENT"
        if "CHECK_ELIMIN" in verdict_line:
            return "CHECK_ELIMINATED"
        if "CHECK_PRES" in verdict_line:
            return "CHECK_PRESENT"
    if "CHECK_ELIMINATED" in upper and "CHECK_PRESENT" not in upper:
        return "CHECK_ELIMINATED"
    if "CHECK_PRESENT" in upper and "CHECK_ELIMINATED" not in upper:
        return "CHECK_PRESENT"
    if "CHECK ELIMINATED" in upper and "CHECK PRESENT" not in upper:
        return "CHECK_ELIMINATED"
    if "CHECK PRESENT" in upper and "CHECK ELIMINATED" not in upper:
        return "CHECK_PRESENT"
    if "[VULNERABLE]" in upper and "[SAFE]" not in upper:
        return "CHECK_ELIMINATED"
    if "[SAFE]" in upper and "[VULNERABLE]" not in upper:
        return "CHECK_PRESENT"
    return None


def parse_detection_details(text: str) -> dict[str, str | None]:
    parsed = parse_structured_detection_fields(text)
    verdict = parse_verdict(text)
    return {
        "parsed_verdict": verdict,
        "parsed_source_predicate": parsed.get("source_predicate"),
        "parsed_purpose": parsed.get("purpose"),
        "parsed_expected_check": parsed.get("expected_check"),
        "parsed_evidence": parsed.get("evidence"),
    }


def parse_group(text: str) -> str | None:
    upper = text.upper()
    if "GROUP:" in upper:
        group_line = upper.split("GROUP:", 1)[1].splitlines()[0].strip()
        for label in ["A", "B", "C", "D", "E"]:
            if re.fullmatch(rf"{label}\b.*", group_line):
                return label
    for line in upper.splitlines():
        stripped = line.strip()
        if stripped in {"A", "B", "C", "D", "E"}:
            return stripped
    return None


def extract_openai_text(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("output_text"), str) and payload["output_text"].strip():
        return payload["output_text"].strip()

    chunks: list[str] = []
    for item in payload.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and content.get("text"):
                chunks.append(content["text"])
    if chunks:
        return "\n".join(chunks).strip()
    return json.dumps(payload, ensure_ascii=False)


def extract_chat_completions_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", [])
    if not choices:
        return json.dumps(payload, ensure_ascii=False)
    message = choices[0].get("message", {})
    content = message.get("content", "")
    if isinstance(content, str):
        stripped = content.strip()
        if stripped:
            return stripped
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("text"):
                parts.append(item["text"])
        if parts:
            return "\n".join(parts).strip()
    reasoning = message.get("reasoning_content", "")
    if isinstance(reasoning, str) and reasoning.strip():
        return reasoning.strip()
    return json.dumps(payload, ensure_ascii=False)


def _normalize_usage(payload: dict[str, Any]) -> dict[str, Any]:
    usage = payload.get("usage") or payload.get("usageMetadata") or {}
    if not isinstance(usage, dict):
        return {}
    normalized: dict[str, Any] = {"usage_raw": usage}
    for key in [
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "inputTokenCount",
        "outputTokenCount",
        "totalTokenCount",
        "promptTokenCount",
        "candidatesTokenCount",
    ]:
        if key in usage:
            normalized[key] = usage[key]
    return normalized


def call_openai(prompt: str, model: str, max_tokens: int) -> tuple[str, dict[str, Any]]:
    is_glm = model.upper().startswith("GLM-")
    if is_glm:
        api_key = getenv_with_user_fallback("GLM_API_KEY")
        base_url = getenv_with_user_fallback("GLM_BASE_URL", "https://open.bigmodel.cn/api/coding/paas/v4")
        api_format = (getenv_with_user_fallback("GLM_API_FORMAT", "chat_completions") or "chat_completions").strip().lower()
    else:
        api_key = getenv_with_user_fallback("OPENAI_API_KEY")
        base_url = getenv_with_user_fallback("OPENAI_BASE_URL", "https://api.openai.com/v1")
        api_format = (getenv_with_user_fallback("OPENAI_API_FORMAT", "responses") or "responses").strip().lower()
    if not api_key:
        if is_glm:
            raise RuntimeError("GLM_API_KEY is not set.")
        raise RuntimeError("OPENAI_API_KEY is not set.")
    base_url = (base_url or "").rstrip("/")
    system_prompt = getenv_with_user_fallback("OPENAI_SYSTEM_PROMPT", "") or ""
    response_format = (getenv_with_user_fallback("OPENAI_RESPONSE_FORMAT", "") or "").strip().lower()
    chat_template_kwargs_raw = (getenv_with_user_fallback("OPENAI_CHAT_TEMPLATE_KWARGS_JSON", "") or "").strip()
    disable_thinking = (getenv_with_user_fallback("OPENAI_DISABLE_THINKING", "") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if api_format == "chat_completions" and model.upper().startswith("GLM-"):
        # GLM-5's default reasoning mode often overwhelms the strict four-line
        # labeling format we need for evaluation; disabling it keeps outputs parseable.
        disable_thinking = True
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    chat_template_kwargs: dict[str, Any] = {}
    if chat_template_kwargs_raw:
        try:
            parsed = json.loads(chat_template_kwargs_raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "OPENAI_CHAT_TEMPLATE_KWARGS_JSON is not valid JSON."
            ) from exc
        if not isinstance(parsed, dict):
            raise RuntimeError("OPENAI_CHAT_TEMPLATE_KWARGS_JSON must decode to a JSON object.")
        chat_template_kwargs = parsed

    if api_format == "chat_completions":
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        if response_format == "json_object":
            payload["response_format"] = {"type": "json_object"}
        if disable_thinking:
            payload["thinking"] = {"type": "disabled"}
            if model.lower().startswith("qwen3"):
                chat_template_kwargs.setdefault("enable_thinking", False)
        if chat_template_kwargs:
            payload["chat_template_kwargs"] = chat_template_kwargs
        endpoint = (
            base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
        )
        response = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=180,
        )
        response.raise_for_status()
        payload_json = response.json()
        return extract_chat_completions_text(payload_json), _normalize_usage(payload_json)

    endpoint = base_url if base_url.endswith("/responses") else f"{base_url}/responses"
    response = requests.post(
        endpoint,
        headers=headers,
        json={
            "model": model,
            "input": prompt,
            "max_output_tokens": max_tokens,
        },
        timeout=180,
    )
    response.raise_for_status()
    payload_json = response.json()
    return extract_openai_text(payload_json), _normalize_usage(payload_json)


def call_anthropic(prompt: str, model: str, max_tokens: int) -> tuple[str, dict[str, Any]]:
    if is_kimi_model(model):
        api_key = getenv_with_user_fallback("ANTHROPIC_API_KEY_KIMI") or getenv_with_user_fallback("ANTHROPIC_API_KEY")
        base_url = getenv_with_user_fallback("ANTHROPIC_BASE_URL_KIMI") or getenv_with_user_fallback(
            "ANTHROPIC_BASE_URL",
            "https://api.anthropic.com",
        )
    else:
        api_key = getenv_with_user_fallback("ANTHROPIC_API_KEY")
        base_url = getenv_with_user_fallback("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    if not api_key:
        if is_kimi_model(model):
            raise RuntimeError("ANTHROPIC_API_KEY_KIMI (or fallback ANTHROPIC_API_KEY) is not set.")
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")
    base_url = (base_url or "https://api.anthropic.com").rstrip("/")
    endpoint = base_url if base_url.endswith("/v1/messages") else f"{base_url}/v1/messages"
    response = requests.post(
        endpoint,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=180,
    )
    response.raise_for_status()
    payload = response.json()
    text = "\n".join(
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ).strip()
    return text, _normalize_usage(payload)


def extract_gemini_text(payload: dict[str, Any]) -> str:
    candidates = payload.get("candidates", [])
    if not candidates:
        return json.dumps(payload, ensure_ascii=False)
    parts = candidates[0].get("content", {}).get("parts", [])
    text_parts = []
    for part in parts:
        if part.get("text"):
            text_parts.append(part["text"])
    if text_parts:
        return "\n".join(text_parts).strip()
    return json.dumps(payload, ensure_ascii=False)


def call_gemini(prompt: str, model: str, max_tokens: int, thinking_level: str) -> tuple[str, dict[str, Any]]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set.")
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    disable_thinking = os.getenv("GEMINI_DISABLE_THINKING", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    } or thinking_level.strip().lower() in {"0", "off", "none", "disabled"}
    model_requires_thinking = model in GEMINI_THINKING_REQUIRED_MODELS
    payload: dict[str, Any] = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0,
        },
    }
    if disable_thinking and not model_requires_thinking:
        # Gemini 3 Flash can spend most of the output budget on hidden thinking,
        # leaving only a truncated visible answer. For strict evaluation, force
        # the visible answer budget to go entirely to the returned text.
        payload["generationConfig"]["thinkingConfig"] = {
            "thinkingBudget": 0
        }
    elif thinking_level:
        payload["generationConfig"]["thinkingConfig"] = {
            "thinkingLevel": thinking_level
        }

    response = requests.post(
        endpoint,
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=180,
    )
    response.raise_for_status()
    payload_json = response.json()
    metadata = _normalize_usage(payload_json)
    if model_requires_thinking:
        metadata["model_requires_thinking"] = True
    return extract_gemini_text(payload_json), metadata


def extract_session_id(text: str) -> str | None:
    match = re.search(r"session id:\s*([0-9A-Fa-f-]+)", text)
    return match.group(1) if match else None


def extract_codex_total_tokens(text: str) -> int | None:
    match = re.search(r"tokens used\s+([\d,]+)", text, flags=re.IGNORECASE)
    return int(match.group(1).replace(",", "")) if match else None


def count_codex_tool_event_markers(text: str) -> int:
    patterns = (
        r"\bexec_command\b",
        r"\bshell_command\b",
        r"\bcommand_execution\b",
        r"\btool_call\b",
        r"\bweb_search\b",
        r"\bapply_patch\b",
    )
    return sum(len(re.findall(pattern, text, flags=re.IGNORECASE)) for pattern in patterns)


def cli_timeout_seconds(env_name: str, default: int) -> int:
    raw = getenv_with_user_fallback(env_name, str(default)) or str(default)
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def isolated_cli_workdir() -> Path:
    path = Path(tempfile.gettempdir()) / "firmsem_llm_cli_isolated"
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_codex_cli_command(
    codex_exe: str,
    model: str,
    effort: str,
    output_last_message: Path,
    workdir: Path,
) -> list[str]:
    return [
        codex_exe,
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "-s",
        "read-only",
        "--skip-git-repo-check",
        "-C",
        str(workdir),
        "-m",
        model,
        "-c",
        f'model_reasoning_effort="{effort}"',
        "-o",
        str(output_last_message),
        "-",
    ]


def build_claude_cli_command(claude_exe: str, model: str, effort: str) -> list[str]:
    return [
        claude_exe,
        "-p",
        "--safe-mode",
        "--tools",
        "",
        "--disable-slash-commands",
        "--no-session-persistence",
        "--no-chrome",
        "--model",
        model,
        "--effort",
        effort,
        "--output-format",
        "json",
    ]


def call_codex_cli(prompt: str, model: str, reasoning_effort: str) -> tuple[str, dict[str, Any]]:
    effort = reasoning_effort.strip() or os.getenv("CODEX_REASONING_EFFORT", "medium").strip() or "medium"
    codex_exe = shutil.which("codex.cmd") or shutil.which("codex")
    if not codex_exe:
        raise RuntimeError("codex CLI is not available on PATH.")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt") as handle:
        output_last_message = Path(handle.name)
    workdir = isolated_cli_workdir()
    command = build_codex_cli_command(codex_exe, model, effort, output_last_message, workdir)
    timeout_seconds = cli_timeout_seconds("CODEX_CLI_TIMEOUT_SECONDS", 600)
    try:
        result = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            cwd=workdir,
            timeout=timeout_seconds,
            check=False,
        )
        raw_text = ""
        if output_last_message.exists():
            raw_text = output_last_message.read_text(encoding="utf-8", errors="replace").strip()
        if result.returncode != 0 and not raw_text:
            raise RuntimeError(
                f"codex exec failed with exit code {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        transcript = (result.stderr or "") + "\n" + (result.stdout or "")
        metadata = {
            "cli_command": " ".join(command),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "session_id": extract_session_id(result.stdout or ""),
            "reasoning_effort": effort,
            "cli_timeout_seconds": timeout_seconds,
            "cli_isolation_dir": str(workdir),
            "tools_disabled": False,
            "tool_access_policy": "read_only_sandbox_prompt_forbidden",
            "observed_tool_event_markers": count_codex_tool_event_markers(transcript),
            "customizations_disabled": True,
        }
        total_tokens = extract_codex_total_tokens(transcript)
        if total_tokens is not None:
            metadata["total_tokens"] = total_tokens
        return raw_text, metadata
    finally:
        try:
            output_last_message.unlink(missing_ok=True)
        except OSError:
            pass


def call_claude_cli(prompt: str, model: str, effort: str) -> tuple[str, dict[str, Any]]:
    normalized_effort = (
        effort.strip()
        or getenv_with_user_fallback("CLAUDE_CLI_EFFORT", "max").strip()
        or "max"
    )
    claude_exe = shutil.which("claude.cmd") or shutil.which("claude")
    if not claude_exe:
        raise RuntimeError("claude CLI is not available on PATH.")
    workdir = isolated_cli_workdir()
    command = build_claude_cli_command(claude_exe, model, normalized_effort)
    timeout_seconds = cli_timeout_seconds("CLAUDE_CLI_TIMEOUT_SECONDS", 600)
    cli_env = os.environ.copy()
    cli_env["CLAUDE_CODE_DISABLE_THINKING"] = "1"
    result = subprocess.run(
        command,
        input=prompt,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        cwd=workdir,
        env=cli_env,
        timeout=timeout_seconds,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"claude CLI failed with exit code {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    stdout = (result.stdout or "").strip()
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"claude CLI returned non-JSON output: {stdout[:400]}") from exc
    raw_text = str(payload.get("result", "")).strip()
    metadata = {
        "cli_command": " ".join(command),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "session_id": payload.get("session_id"),
        "reasoning_effort": normalized_effort,
        "cli_timeout_seconds": timeout_seconds,
        "cli_isolation_dir": str(workdir),
        "tools_disabled": True,
        "customizations_disabled": True,
        "thinking_disabled": True,
        "thinking_disable_source": "CLAUDE_CODE_DISABLE_THINKING=1",
    }
    if "total_cost_usd" in payload:
        metadata["total_cost_usd"] = payload["total_cost_usd"]
    if "usage" in payload:
        metadata["usage"] = payload["usage"]
    if "modelUsage" in payload:
        metadata["modelUsage"] = payload["modelUsage"]
    for field in (
        "num_turns",
        "is_error",
        "terminal_reason",
        "stop_reason",
        "fast_mode_state",
        "permission_denials",
    ):
        if field in payload:
            metadata[field] = payload[field]
    return raw_text, metadata


def call_model_with_metadata(
    provider: str,
    prompt: str,
    model: str,
    max_tokens: int,
    thinking_level: str,
    codex_reasoning_effort: str,
    claude_effort: str,
) -> tuple[str, dict[str, Any]]:
    request_started = datetime.now(timezone.utc)
    started = time.perf_counter()
    if provider == "codex_cli":
        raw_text, metadata = call_codex_cli(prompt, model, codex_reasoning_effort)
    elif provider == "claude_cli":
        raw_text, metadata = call_claude_cli(prompt, model, claude_effort)
    elif provider == "openai":
        raw_text, metadata = call_openai(prompt, model, max_tokens)
    elif provider == "anthropic":
        raw_text, metadata = call_anthropic(prompt, model, max_tokens)
    elif provider == "gemini":
        raw_text, metadata = call_gemini(prompt, model, max_tokens, thinking_level)
    else:
        raise RuntimeError(f"Unsupported provider: {provider}")
    request_finished = datetime.now(timezone.utc)
    metadata = {
        **metadata,
        "request_started_utc": request_started.isoformat(),
        "request_finished_utc": request_finished.isoformat(),
        "elapsed_seconds": round(time.perf_counter() - started, 4),
    }
    return raw_text, metadata


def call_model(provider: str, prompt: str, model: str, max_tokens: int, thinking_level: str) -> str:
    if provider == "openai":
        raw_text, _ = call_openai(prompt, model, max_tokens)
        return raw_text
    if provider == "anthropic":
        raw_text, _ = call_anthropic(prompt, model, max_tokens)
        return raw_text
    if provider == "gemini":
        raw_text, _ = call_gemini(prompt, model, max_tokens, thinking_level)
        return raw_text
    if provider == "codex_cli":
        raw_text, _ = call_codex_cli(prompt, model, os.getenv("CODEX_REASONING_EFFORT", "medium"))
        return raw_text
    if provider == "claude_cli":
        raw_text, _ = call_claude_cli(prompt, model, getenv_with_user_fallback("CLAUDE_CLI_EFFORT", "max") or "max")
        return raw_text
    raise RuntimeError(f"Unsupported provider: {provider}")


def compute_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    parsed = [row for row in records if row["parsed_verdict"] in {"CHECK_ELIMINATED", "CHECK_PRESENT"}]
    counts = confusion_counts_from_records(parsed)
    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]
    tn = counts["tn"]
    metrics = classification_metrics_from_counts(tp, fp, fn, tn)
    cis = bootstrap_binary_metrics(parsed)
    positives = sum(1 for row in records if row["actual_label"] == "CHECK_ELIMINATED")
    pr_curve = precision_recall_curve_points(parsed)
    return {
        "evaluated_samples": len(records),
        "parsed_samples": len(parsed),
        "parse_failures": len(records) - len(parsed),
        "positive_samples": positives,
        "negative_samples": len(records) - positives,
        "positive_rate": round4(positives / len(records) if records else 0.0),
        "positive_rate_ci_95": round_ci(*wilson_interval(positives, len(records))),
        "precision": round4(metrics["precision"]),
        "precision_ci_95": cis["precision"],
        "recall": round4(metrics["recall"]),
        "recall_ci_95": cis["recall"],
        "f1": round4(metrics["f1"]),
        "f1_ci_95": cis["f1"],
        "accuracy": round4(metrics["accuracy"]),
        "accuracy_ci_95": cis["accuracy"],
        "mcc": round4(metrics["mcc"]),
        "mcc_ci_95": cis["mcc"],
        "balanced_accuracy": round4(metrics["balanced_accuracy"]),
        "balanced_accuracy_ci_95": cis["balanced_accuracy"],
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "confusion_matrix": {
            "positive": {"pred_positive": tp, "pred_negative": fn},
            "negative": {"pred_positive": fp, "pred_negative": tn},
        },
        "precision_recall_curve": pr_curve,
    }


def compute_metrics_by_category(records: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in records:
        grouped.setdefault(row["category"], []).append(row)
    return {category: compute_metrics(rows) for category, rows in sorted(grouped.items())}


def compute_routing_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    labels = ["A", "B", "C", "D", "E"]
    parsed = [row for row in records if row.get("parsed_group") in labels]
    confusion = {
        actual: {pred: 0 for pred in labels}
        for actual in labels
    }
    for row in parsed:
        confusion[row["actual_group"]][row["parsed_group"]] += 1
    correct = sum(1 for row in parsed if row["parsed_group"] == row["actual_group"])
    accuracy = correct / len(parsed) if parsed else 0.0
    per_label_f1 = []
    for label in labels:
        tp = sum(1 for row in parsed if row["actual_group"] == label and row["parsed_group"] == label)
        fp = sum(1 for row in parsed if row["actual_group"] != label and row["parsed_group"] == label)
        fn = sum(1 for row in parsed if row["actual_group"] == label and row["parsed_group"] != label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        per_label_f1.append(f1)
    macro_f1 = sum(per_label_f1) / len(labels) if labels else 0.0
    return {
        "evaluated_samples": len(records),
        "parsed_samples": len(parsed),
        "parse_failures": len(records) - len(parsed),
        "accuracy": round4(accuracy),
        "accuracy_ci_95": round_ci(*wilson_interval(correct, len(parsed))),
        "macro_f1": round4(macro_f1),
        "macro_f1_ci_95": bootstrap_macro_f1(
            parsed,
            actual_field="actual_group",
            prediction_field="parsed_group",
            labels=labels,
        ),
        "confusion_matrix": confusion,
    }


def build_initial_record(
    sample: Sample,
    provider: str,
    model: str,
    reasoning_effort: str,
    task_mode: str,
    prompt_variant: str,
    prompt_format: str,
    label_source: str,
) -> dict[str, Any]:
    return {
        "id": sample.sample_id,
        "function_name": sample.function_name,
        "category": sample.category,
        "pattern_id": sample.pattern_id,
        "pattern_name": sample.pattern_name,
        "pattern_desc": sample.pattern_desc,
        "actual_label": sample.actual_label,
        "prompt_file": str(sample.prompt_path.relative_to(ROOT)),
        "prompt_sha1_free_note": "Prompt text saved to file for auditability.",
        "provider": provider if provider != "none" else None,
        "model": model or None,
        "task_mode": task_mode,
        "prompt_variant": prompt_variant,
        "prompt_format": prompt_format,
        "label_source": label_source,
        "llm_verdict": None,
        "parsed_verdict": None,
        "parsed_source_predicate": None,
        "parsed_purpose": None,
        "parsed_expected_check": None,
        "parsed_evidence": None,
        "llm_group": None,
        "parsed_group": None,
        "llm_raw_response": None,
        "cli_command": None,
        "stdout": None,
        "stderr": None,
        "session_id": None,
        "reasoning_effort": reasoning_effort or None,
        "actual_group": sample.actual_group,
        "error": None,
        "status": "prompt_generated",
    }


def evaluate_sample(
    sample: Sample,
    provider: str,
    model: str,
    max_tokens: int,
    thinking_level: str,
    codex_reasoning_effort: str,
    claude_effort: str,
    retries: int,
    sleep_seconds: float,
    task_mode: str,
    prompt_variant: str,
    prompt_format: str,
    label_source: str,
) -> dict[str, Any]:
    record = build_initial_record(
        sample,
        provider,
        model,
        claude_effort if provider == "claude_cli" else codex_reasoning_effort,
        task_mode,
        prompt_variant,
        prompt_format,
        label_source,
    )
    last_error = None
    for attempt in range(retries + 1):
        try:
            raw_text, extra_metadata = call_model_with_metadata(
                provider,
                sample.prompt_text,
                model,
                max_tokens,
                thinking_level,
                codex_reasoning_effort,
                claude_effort,
            )
            parsed_details = parse_detection_details(raw_text) if task_mode == "detection" else {}
            parsed_verdict = parsed_details.get("parsed_verdict") if task_mode == "detection" else None
            parsed_group = parse_group(raw_text) if task_mode == "routing" else None
            record.update(
                {
                    "llm_verdict": parsed_verdict,
                    "parsed_verdict": parsed_verdict,
                    "parsed_purpose": parsed_details.get("parsed_purpose") if task_mode == "detection" else None,
                    "parsed_expected_check": parsed_details.get("parsed_expected_check") if task_mode == "detection" else None,
                    "parsed_evidence": parsed_details.get("parsed_evidence") if task_mode == "detection" else None,
                    "llm_group": parsed_group,
                    "parsed_group": parsed_group,
                    "llm_raw_response": raw_text,
                    "status": "completed"
                    if (parsed_verdict if task_mode == "detection" else parsed_group)
                    else "parse_failed",
                }
            )
            if extra_metadata:
                record.update(extra_metadata)
            last_error = None
            break
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            if attempt < retries:
                time.sleep(max(sleep_seconds, 1.0))
    if last_error is not None:
        record["status"] = "request_failed"
        record["error"] = last_error
    if sleep_seconds > 0:
        time.sleep(sleep_seconds)
    return record


def main() -> int:
    args = parse_args()
    if args.parallel_requests < 1:
        raise ValueError("--parallel-requests must be at least 1.")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    prompt_dir = tagged_path(PROMPT_DIR, args.run_tag)
    raw_results_json = tagged_path(RAW_RESULTS_JSON, args.run_tag)
    metrics_json = tagged_path(METRICS_JSON, args.run_tag)

    samples = collect_samples(args)
    experiment_json = Path(args.experiment_json).resolve()
    asm_o3_path = Path(args.asm_o3).resolve()
    provider = detect_provider(args.provider)
    model = resolve_model(provider, args.model)
    thinking_level = args.thinking_level or os.getenv("GEMINI_THINKING_LEVEL", "")
    codex_reasoning_effort = args.codex_reasoning_effort or os.getenv("CODEX_REASONING_EFFORT", "")
    timestamp = datetime.now(timezone.utc).isoformat()

    raw_records: list[dict[str, Any]] = []
    if not args.dry_run and provider in {"openai", "anthropic", "gemini", "codex_cli", "claude_cli"}:
        worker_count = min(args.parallel_requests, len(samples)) if samples else 1
        if provider in {"codex_cli", "claude_cli"}:
            worker_count = 1
        if worker_count <= 1:
            raw_records = [
                evaluate_sample(
                    sample,
                    provider,
                    model,
                    args.max_tokens,
                    thinking_level,
                    codex_reasoning_effort,
                    args.claude_effort or getenv_with_user_fallback("CLAUDE_CLI_EFFORT", ""),
                    args.retries,
                    args.sleep_seconds,
                    args.task_mode,
                    args.prompt_variant,
                    args.prompt_format,
                    args.label_source,
                )
                for sample in samples
            ]
        else:
            ordered_records: list[dict[str, Any] | None] = [None] * len(samples)
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_index = {
                    executor.submit(
                        evaluate_sample,
                        sample,
                        provider,
                        model,
                        args.max_tokens,
                        thinking_level,
                        codex_reasoning_effort,
                        args.claude_effort or getenv_with_user_fallback("CLAUDE_CLI_EFFORT", ""),
                        args.retries,
                        args.sleep_seconds,
                        args.task_mode,
                        args.prompt_variant,
                        args.prompt_format,
                        args.label_source,
                    ): index
                    for index, sample in enumerate(samples)
                }
                for future in concurrent.futures.as_completed(future_to_index):
                    index = future_to_index[future]
                    ordered_records[index] = future.result()
            raw_records = [record for record in ordered_records if record is not None]
    else:
        raw_records = [
            build_initial_record(
                sample,
                provider,
                model,
                (args.claude_effort or getenv_with_user_fallback("CLAUDE_CLI_EFFORT", "")) if provider == "claude_cli" else codex_reasoning_effort,
                args.task_mode,
                args.prompt_variant,
                args.prompt_format,
                args.label_source,
            )
            for sample in samples
        ]

    dry_run_status = args.dry_run or provider == "none"
    raw_payload = {
        "metadata": {
            "timestamp_utc": timestamp,
            "provider": None if provider == "none" else provider,
            "model": model or None,
            "dry_run": dry_run_status,
            "include_category_hint": args.include_category_hint,
            "task_mode": args.task_mode,
            "prompt_variant": args.prompt_variant,
            "prompt_format": args.prompt_format,
            "label_source": args.label_source,
            "thinking_level": thinking_level or None,
            "codex_reasoning_effort": codex_reasoning_effort or None,
            "claude_effort": (args.claude_effort or getenv_with_user_fallback("CLAUDE_CLI_EFFORT", "")) or None,
            "parallel_requests": args.parallel_requests,
            "eligible_samples": len(samples),
            "prompt_directory": str(prompt_dir.relative_to(ROOT)),
            "asm_source": str(asm_o3_path.relative_to(ROOT)),
            "experiment_json": str(experiment_json.relative_to(ROOT)),
            "semantic_audit_json": (
                str(Path(args.semantic_audit_json).resolve().relative_to(ROOT))
                if args.label_source == "semantic"
                else None
            ),
        },
        "results": raw_records,
    }
    raw_results_json.write_text(json.dumps(raw_payload, indent=2), encoding="utf-8")

    summary = {
        "total_samples": len(samples),
        "positive_samples": sum(1 for sample in samples if sample.actual_label == "CHECK_ELIMINATED"),
        "negative_samples": sum(1 for sample in samples if sample.actual_label == "CHECK_PRESENT"),
    }
    metrics_payload = {
        "metadata": {
            "timestamp_utc": timestamp,
            "provider": None if provider == "none" else provider,
            "model": model or None,
            "dry_run": dry_run_status,
            "include_category_hint": args.include_category_hint,
            "task_mode": args.task_mode,
            "prompt_variant": args.prompt_variant,
            "prompt_format": args.prompt_format,
            "label_source": args.label_source,
            "thinking_level": thinking_level or None,
            "codex_reasoning_effort": codex_reasoning_effort or None,
            "claude_effort": (args.claude_effort or getenv_with_user_fallback("CLAUDE_CLI_EFFORT", "")) or None,
            "parallel_requests": args.parallel_requests,
            "raw_results_file": str(raw_results_json.relative_to(ROOT)),
            "prompt_directory": str(prompt_dir.relative_to(ROOT)),
            "semantic_audit_json": (
                str(Path(args.semantic_audit_json).resolve().relative_to(ROOT))
                if args.label_source == "semantic"
                else None
            ),
        },
        "summary": summary,
    }

    if dry_run_status:
        metrics_payload["status"] = "LLM NOT CALLED - prompts generated for manual or future API evaluation"
    else:
        metrics_payload["status"] = "completed"
        if args.task_mode == "routing":
            metrics_payload["metrics"] = compute_routing_metrics(raw_records)
        else:
            metrics_payload["metrics"] = compute_metrics(raw_records)
            metrics_payload["by_category"] = compute_metrics_by_category(raw_records)

    metrics_json.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")

    print(f"Prompts generated: {len(samples)}")
    print(f"Prompt directory: {prompt_dir}")
    print(f"Raw results: {raw_results_json}")
    print(f"Metrics: {metrics_json}")
    if dry_run_status:
        print("LLM NOT CALLED - prompts generated for manual or future API evaluation")
    else:
        print(json.dumps(metrics_payload["metrics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
