from __future__ import annotations

import math
import random
from typing import Any


Z_95 = 1.959963984540054
DEFAULT_BOOTSTRAP_SAMPLES = 2000
DEFAULT_BOOTSTRAP_SEED = 20260321


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def round4(value: float) -> float:
    return round(float(value), 4)


def round_ci(low: float, high: float) -> list[float]:
    return [round4(low), round4(high)]


def wilson_interval(successes: int, total: int, z: float = Z_95) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1.0 + (z * z) / total
    center = (p + (z * z) / (2.0 * total)) / denom
    margin = (
        z
        * math.sqrt((p * (1.0 - p) / total) + ((z * z) / (4.0 * total * total)))
        / denom
    )
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return (low, high)


def confusion_counts_from_records(
    rows: list[dict[str, Any]],
    *,
    prediction_field: str = "parsed_verdict",
    actual_field: str = "actual_label",
    positive_label: str = "CHECK_ELIMINATED",
) -> dict[str, int]:
    tp = sum(
        1
        for row in rows
        if row[prediction_field] == positive_label and row[actual_field] == positive_label
    )
    fp = sum(
        1
        for row in rows
        if row[prediction_field] == positive_label and row[actual_field] != positive_label
    )
    fn = sum(
        1
        for row in rows
        if row[prediction_field] != positive_label and row[actual_field] == positive_label
    )
    tn = sum(
        1
        for row in rows
        if row[prediction_field] != positive_label and row[actual_field] != positive_label
    )
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def matthews_correlation_coefficient(tp: int, fp: int, fn: int, tn: int) -> float:
    numerator = (tp * tn) - (fp * fn)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return safe_div(numerator, denominator)


def balanced_accuracy(tp: int, fp: int, fn: int, tn: int) -> float:
    tpr = safe_div(tp, tp + fn)
    tnr = safe_div(tn, tn + fp)
    return (tpr + tnr) / 2.0


def classification_metrics_from_counts(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2.0 * precision * recall, precision + recall)
    accuracy = safe_div(tp + tn, tp + fp + fn + tn)
    mcc = matthews_correlation_coefficient(tp, fp, fn, tn)
    bal_acc = balanced_accuracy(tp, fp, fn, tn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "mcc": mcc,
        "balanced_accuracy": bal_acc,
    }


def _classification_from_counts(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    return classification_metrics_from_counts(tp, fp, fn, tn)


def _bootstrap_quantiles(values: list[float]) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    ordered = sorted(values)
    low_idx = max(0, math.floor(0.025 * (len(ordered) - 1)))
    high_idx = min(len(ordered) - 1, math.ceil(0.975 * (len(ordered) - 1)))
    return (ordered[low_idx], ordered[high_idx])


def bootstrap_binary_metrics(
    parsed_records: list[dict[str, Any]],
    *,
    prediction_field: str = "parsed_verdict",
    actual_field: str = "actual_label",
    positive_label: str = "CHECK_ELIMINATED",
    samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> dict[str, list[float]]:
    if not parsed_records:
        zero = round_ci(0.0, 0.0)
        return {
            "precision": zero,
            "recall": zero,
            "f1": zero,
            "accuracy": zero,
            "mcc": zero,
            "balanced_accuracy": zero,
        }

    rng = random.Random(seed)
    precision_values: list[float] = []
    recall_values: list[float] = []
    f1_values: list[float] = []
    accuracy_values: list[float] = []
    mcc_values: list[float] = []
    balanced_accuracy_values: list[float] = []

    for _ in range(samples):
        sample = [parsed_records[rng.randrange(len(parsed_records))] for _ in range(len(parsed_records))]
        tp = sum(
            1
            for row in sample
            if row[prediction_field] == positive_label and row[actual_field] == positive_label
        )
        fp = sum(
            1
            for row in sample
            if row[prediction_field] == positive_label and row[actual_field] != positive_label
        )
        fn = sum(
            1
            for row in sample
            if row[prediction_field] != positive_label and row[actual_field] == positive_label
        )
        tn = sum(
            1
            for row in sample
            if row[prediction_field] != positive_label and row[actual_field] != positive_label
        )
        metrics = _classification_from_counts(tp, fp, fn, tn)
        precision_values.append(metrics["precision"])
        recall_values.append(metrics["recall"])
        f1_values.append(metrics["f1"])
        accuracy_values.append(metrics["accuracy"])
        mcc_values.append(metrics["mcc"])
        balanced_accuracy_values.append(metrics["balanced_accuracy"])

    return {
        "precision": round_ci(*_bootstrap_quantiles(precision_values)),
        "recall": round_ci(*_bootstrap_quantiles(recall_values)),
        "f1": round_ci(*_bootstrap_quantiles(f1_values)),
        "accuracy": round_ci(*_bootstrap_quantiles(accuracy_values)),
        "mcc": round_ci(*_bootstrap_quantiles(mcc_values)),
        "balanced_accuracy": round_ci(*_bootstrap_quantiles(balanced_accuracy_values)),
    }


def bootstrap_macro_f1(
    parsed_records: list[dict[str, Any]],
    *,
    actual_field: str,
    prediction_field: str,
    labels: list[str],
    samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> list[float]:
    if not parsed_records or not labels:
        return round_ci(0.0, 0.0)

    def macro_f1(rows: list[dict[str, Any]]) -> float:
        f1s: list[float] = []
        for label in labels:
            tp = sum(1 for row in rows if row[actual_field] == label and row[prediction_field] == label)
            fp = sum(1 for row in rows if row[actual_field] != label and row[prediction_field] == label)
            fn = sum(1 for row in rows if row[actual_field] == label and row[prediction_field] != label)
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1s.append(2.0 * precision * recall / (precision + recall) if (precision + recall) else 0.0)
        return sum(f1s) / len(f1s)

    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(samples):
        sample = [parsed_records[rng.randrange(len(parsed_records))] for _ in range(len(parsed_records))]
        values.append(macro_f1(sample))
    return round_ci(*_bootstrap_quantiles(values))


def precision_recall_curve_points(
    rows: list[dict[str, Any]],
    *,
    score_field: str = "score",
    actual_field: str = "actual_label",
    positive_label: str = "CHECK_ELIMINATED",
) -> list[dict[str, float]]:
    scored_rows = [
        row for row in rows
        if isinstance(row.get(score_field), (int, float))
    ]
    if not scored_rows:
        return []

    thresholds = sorted({float(row[score_field]) for row in scored_rows}, reverse=True)
    points: list[dict[str, float]] = []
    for threshold in thresholds:
        tp = fp = fn = 0
        for row in scored_rows:
            predicted_positive = float(row[score_field]) >= threshold
            actual_positive = row[actual_field] == positive_label
            if predicted_positive and actual_positive:
                tp += 1
            elif predicted_positive and not actual_positive:
                fp += 1
            elif (not predicted_positive) and actual_positive:
                fn += 1
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        points.append(
            {
                "threshold": round4(threshold),
                "precision": round4(precision),
                "recall": round4(recall),
            }
        )
    return points
