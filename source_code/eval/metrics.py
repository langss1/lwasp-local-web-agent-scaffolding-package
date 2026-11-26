"""Aggregate per-run report.json files into mean +/- std metrics per
configuration/scenario, plus the derived capability-per-compute metrics and a
significance test on iteration counts between configurations.

Never single-number metrics: plan.md explicitly requires mean +/- std over
runs_per_scenario, because the LLM is stochastic.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class AggregatedMetrics:
    config_id: str
    scenario_id: str
    n_runs: int
    success_rate: float
    mean_iterations: float | None
    std_iterations: float | None
    mean_wall_clock_s: float
    std_wall_clock_s: float
    mean_peak_vram_mb: float | None
    mean_peak_ram_mb: float | None
    mean_tokens_used: float
    mean_guardrail_blocks: float
    mean_backtracks: float
    success_per_time: float | None
    success_per_vram: float | None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


def _mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean, std


def load_reports(runs_dir: Path, config_id: str, scenario_id: str) -> list[dict]:
    """A run_id is formatted '<scenario_id>-<config_id>-<hex>' by run_experiment.py."""
    reports = []
    prefix = f"{scenario_id}-{config_id}-"
    for run_folder in runs_dir.glob(f"{prefix}*"):
        report_path = run_folder / "report.json"
        if report_path.exists():
            reports.append(json.loads(report_path.read_text(encoding="utf-8")))
    return reports


def aggregate(reports: list[dict], config_id: str, scenario_id: str) -> AggregatedMetrics:
    n = len(reports)
    successes = [r for r in reports if r.get("success")]
    success_rate = len(successes) / n if n else 0.0

    iters = [r["iterations_to_success"] for r in successes if r.get("iterations_to_success") is not None]
    mean_iters, std_iters = (_mean_std(iters) if iters else (None, None))

    wall = [r["wall_clock_s"] for r in reports]
    mean_wall, std_wall = _mean_std(wall)

    vram = [r["peak_vram_mb"] for r in reports if r.get("peak_vram_mb") is not None]
    ram = [r["peak_ram_mb"] for r in reports if r.get("peak_ram_mb") is not None]
    tokens = [r.get("tokens_used", 0) for r in reports]
    blocks = [r.get("guardrail_blocks", 0) for r in reports]
    backtracks = [r.get("backtracks", 0) for r in reports]

    mean_vram = statistics.mean(vram) if vram else None
    mean_ram = statistics.mean(ram) if ram else None

    success_per_time = (success_rate / mean_wall) if mean_wall else None
    success_per_vram = (success_rate / mean_vram) if mean_vram else None

    return AggregatedMetrics(
        config_id=config_id, scenario_id=scenario_id, n_runs=n, success_rate=success_rate,
        mean_iterations=mean_iters, std_iterations=std_iters,
        mean_wall_clock_s=mean_wall, std_wall_clock_s=std_wall,
        mean_peak_vram_mb=mean_vram, mean_peak_ram_mb=mean_ram,
        mean_tokens_used=statistics.mean(tokens) if tokens else 0.0,
        mean_guardrail_blocks=statistics.mean(blocks) if blocks else 0.0,
        mean_backtracks=statistics.mean(backtracks) if backtracks else 0.0,
        success_per_time=success_per_time, success_per_vram=success_per_vram,
    )


def significance_test(iters_a: list[float], iters_b: list[float]) -> dict[str, Any]:
    """Mann-Whitney U test on iterations_to_success between two configurations.
    Non-parametric because N=10 per config is too small to assume normality.
    """
    try:
        from scipy.stats import mannwhitneyu
    except ImportError:
        return {"available": False, "reason": "scipy not installed"}
    if len(iters_a) < 2 or len(iters_b) < 2:
        return {"available": False, "reason": "not enough successful runs on one side"}
    stat, p_value = mannwhitneyu(iters_a, iters_b, alternative="two-sided")
    return {"available": True, "statistic": float(stat), "p_value": float(p_value),
            "significant_at_0.05": bool(p_value < 0.05)}
