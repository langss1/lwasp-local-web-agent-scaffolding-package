"""Reflection: turns a failed/blocked attempt into a short lesson appended to
working memory, so the next prompt context nudges the model toward a genuinely
different strategy instead of repeating itself in different words.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ReflectionNote:
    trigger: str            # "block" | "failure"
    action_summary: str
    reason: str
    suggestion: str


class Reflection:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def on_block(self, action: dict[str, Any], verdict) -> ReflectionNote | None:
        if not self.enabled:
            return None
        return ReflectionNote(
            trigger="block",
            action_summary=_summarize_action(action),
            reason=verdict.reason,
            suggestion=(
                "This idea was already tried in a semantically equivalent form and failed. "
                "Do not reword it. Switch to a different injection technique, a different "
                "filter bypass, a different parameter, or move to a different phase entirely."
            ),
        )

    def after_attempt(self, action: dict[str, Any], observation: dict[str, Any]) -> ReflectionNote | None:
        if not self.enabled or observation.get("success"):
            return None
        signal = observation.get("signal", "no useful signal")
        return ReflectionNote(
            trigger="failure",
            action_summary=_summarize_action(action),
            reason=f"Attempt did not succeed: {signal}.",
            suggestion=_suggest_next_step(observation),
        )


def _summarize_action(action: dict[str, Any]) -> str:
    params = action.get("params", {})
    if action.get("type") == "HTTP_REQUEST":
        return f"HTTP_REQUEST {params.get('method')} {params.get('endpoint')} param={params.get('param')} value={params.get('value')!r}"
    return f"{action.get('type')} {params}"


def _suggest_next_step(observation: dict[str, Any]) -> str:
    signal = (observation.get("signal") or "").lower()
    if "escape" in signal or "filtered" in signal or "sanitiz" in signal:
        return "The input appears to be filtered/escaped. Try an encoding or syntax variant that evades this specific filter, referencing the knowledge base for that filter category."
    if "reflected" in signal and "execut" not in signal:
        return "Input is reflected but not executing. Try a different XSS context breakout (attribute vs. tag vs. event handler) rather than the same payload shape."
    if "different number of columns" in signal:
        return "Adjust the UNION column count to match the target query before retrying."
    if "no data leak" in signal or "fail" in signal:
        return "No observable effect. Reconsider whether this endpoint/parameter is actually the vulnerable one; re-observe before trying again."
    return "Analyze the response for filter/escape signals and pick a genuinely different technique."
