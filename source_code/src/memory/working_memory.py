"""Working / flash memory: one markdown file per run session, with the fixed
sections described in plan.md 4.3.2. This is the primary material fed into the
prompt context each turn, together with the state-graph summary and RAG hits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SECTIONS = ["Observe", "Plan", "Attempt Log", "Reflection", "Resume"]


@dataclass
class WorkingMemory:
    run_dir: Path
    sections: dict[str, list[str]] = field(default_factory=lambda: {s: [] for s in SECTIONS})

    @property
    def path(self) -> Path:
        return self.run_dir / "session_state.md"

    def add(self, section: str, line: str) -> None:
        if section not in self.sections:
            raise ValueError(f"Unknown working-memory section: {section}")
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.sections[section].append(f"[{timestamp}] {line}")
        self._flush()

    def render(self) -> str:
        parts = []
        for section in SECTIONS:
            body = "\n".join(self.sections[section]) or "(empty)"
            parts.append(f"## {section}\n{body}")
        return "\n\n".join(parts)

    def render_for_prompt(self, max_attempt_lines: int = 12) -> str:
        """Trimmed view for the LLM context: full Observe/Plan/Reflection/Resume,
        but only the most recent attempts (long attempt logs blow the context
        budget on a small local model).
        """
        parts = []
        for section in SECTIONS:
            lines = self.sections[section]
            if section == "Attempt Log" and len(lines) > max_attempt_lines:
                lines = ["(earlier attempts omitted)"] + lines[-max_attempt_lines:]
            body = "\n".join(lines) or "(empty)"
            parts.append(f"## {section}\n{body}")
        return "\n\n".join(parts)

    def _flush(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(self.render(), encoding="utf-8")

    @classmethod
    def start(cls, run_dir: Path, scenario_desc: str) -> "WorkingMemory":
        wm = cls(run_dir=run_dir)
        wm.add("Plan", f"Scenario: {scenario_desc}")
        wm.add("Plan", "Phases: info gathering -> vulnerability assessment -> exploitation -> verification.")
        return wm
