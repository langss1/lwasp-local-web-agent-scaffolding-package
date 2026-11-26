"""Run the full ablation matrix (B0..B4) x scenarios x N runs, per
eval/ablation.yaml and eval/scenarios.yaml, and write an aggregated report.

Each run's raw artifacts land in runs/<scenario>-<config>-<hex>/ (trace.jsonl,
session_state.md, report.json) via Orchestrator itself; this script only
drives the matrix and aggregates afterward.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from eval.metrics import aggregate, load_reports, significance_test  # noqa: E402
from src.orchestrator import Orchestrator, Scenario, load_config  # noqa: E402


def load_ablation(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_scenarios(path: Path) -> list[Scenario]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [Scenario.from_dict(s) for s in data["scenarios"]]


def run_matrix(base_config: dict, ablation: dict, scenarios: list[Scenario],
                configs_filter: list[str] | None = None, scenarios_filter: list[str] | None = None,
                runs_override: int | None = None) -> None:
    runs_per_scenario = runs_override or ablation["experiment"]["runs_per_scenario"]

    for cfg_def in ablation["configurations"]:
        if configs_filter and cfg_def["id"] not in configs_filter:
            continue
        for scenario in scenarios:
            if scenarios_filter and scenario.id not in scenarios_filter:
                continue
            for run_idx in range(runs_per_scenario):
                run_config = copy.deepcopy(base_config)
                run_config["components"] = cfg_def["components"]
                # BUG-2 fix: isolate long_term_memory per config_id so B5/B10 (and
                # any other config with long_term_memory enabled) never read or
                # write each other's lessons. See eval/one_run.py for the full
                # rationale -- this mirrors the same fix for this run path.
                run_config["long_term_memory"] = dict(run_config.get("long_term_memory", {}))
                run_config["long_term_memory"]["store_dir"] = f"knowledge/long_term/{cfg_def['id']}"
                run_config["long_term_memory"]["chroma_dir"] = f"knowledge/long_term/{cfg_def['id']}/chroma"
                run_id = f"{scenario.id}-{cfg_def['id']}-{run_idx:02d}"
                print(f"=== {run_id} ===")
                orch = Orchestrator(run_config, scenario, run_id=run_id)
                report = orch.run()
                print(f"  success={report['success']} iterations={report['iterations_used']} "
                      f"wall_clock_s={report['wall_clock_s']:.1f}")


def build_summary(ablation: dict, scenarios: list[Scenario], runs_dir: Path) -> dict:
    summary: dict = {"configurations": {}, "pairwise_significance": {}}
    per_config_iters: dict[str, dict[str, list[float]]] = {}

    for cfg_def in ablation["configurations"]:
        cfg_id = cfg_def["id"]
        summary["configurations"][cfg_id] = {}
        per_config_iters[cfg_id] = {}
        for scenario in scenarios:
            reports = load_reports(runs_dir, cfg_id, scenario.id)
            if not reports:
                continue
            agg = aggregate(reports, cfg_id, scenario.id)
            summary["configurations"][cfg_id][scenario.id] = agg.to_dict()
            per_config_iters[cfg_id][scenario.id] = [
                r["iterations_to_success"] for r in reports
                if r.get("success") and r.get("iterations_to_success") is not None
            ]

    # The two contribution-isolating comparisons called out in ablation.yaml.
    for a, b, label in [("B2", "B3", "guardrail_effect"), ("B3", "B4", "state_graph_effect")]:
        summary["pairwise_significance"][label] = {}
        for scenario in scenarios:
            iters_a = per_config_iters.get(a, {}).get(scenario.id, [])
            iters_b = per_config_iters.get(b, {}).get(scenario.id, [])
            summary["pairwise_significance"][label][scenario.id] = significance_test(iters_a, iters_b)

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the ablation experiment matrix.")
    parser.add_argument("--config", default=str(PROJECT_ROOT / "config.yaml"))
    parser.add_argument("--ablation", default=str(PROJECT_ROOT / "eval" / "ablation.yaml"))
    parser.add_argument("--scenarios", default=str(PROJECT_ROOT / "eval" / "scenarios.yaml"))
    parser.add_argument("--configs", nargs="*", default=None, help="Subset of configuration ids (e.g. B0 B1)")
    parser.add_argument("--scenario-ids", nargs="*", default=None, help="Subset of scenario ids")
    parser.add_argument("--runs", type=int, default=None, help="Override runs_per_scenario")
    parser.add_argument("--summary-only", action="store_true", help="Skip execution, just aggregate existing runs/")
    args = parser.parse_args()

    base_config = load_config(args.config)
    ablation = load_ablation(Path(args.ablation))
    scenarios = load_scenarios(Path(args.scenarios))

    if not args.summary_only:
        run_matrix(base_config, ablation, scenarios, configs_filter=args.configs,
                   scenarios_filter=args.scenario_ids, runs_override=args.runs)

    runs_dir = PROJECT_ROOT / base_config["logging"]["runs_dir"]
    summary = build_summary(ablation, scenarios, runs_dir)
    summary_path = runs_dir / "ablation_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nSummary written to {summary_path}")
