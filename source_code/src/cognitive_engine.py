"""Cognitive Engine: wraps the local LLM (Qwen 2.5 via Ollama) and enforces the
strict THOUGHT / ACTION output contract described in prompts/system_prompt.md.

This module does pure reasoning I/O. It never touches the network target and
never decides whether an action is allowed -- that is the guardrail's job.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import ollama

ALLOWED_ACTION_TYPES = {
    "OBSERVE",
    "HTTP_REQUEST",
    "RUN_TOOL",
    "VERIFY",
    "SEARCH_KNOWLEDGE",
    "RUN_SCRIPT",
    "WEB_SEARCH",
    "JUMP_STATE",
    "FINISH",
}

# Case-insensitive, markdown-tolerant labels. A small local model often emits
# **THOUGHT:**, "Thought:", or a leading "### ACTION" -- all should parse.
_THOUGHT_LABEL = re.compile(r"(?im)^[\s>#*`-]*thought\s*:?\s*", re.MULTILINE)
_ACTION_LABEL = re.compile(r"(?i)[\s>#*`-]*action\s*:?\s*")


class ActionParseError(Exception):
    """Raised when the model output does not follow the THOUGHT/ACTION contract."""


def _extract_json_object(text: str, start: int = 0) -> tuple[str, int] | None:
    """Return the first balanced {...} object at or after `start`, plus the index
    just past its closing brace. Brace-counting (string-aware) so trailing prose
    after the JSON -- a very common small-model habit -- does not break parsing.
    """
    i = text.find("{", start)
    if i < 0:
        return None
    depth = 0
    in_str = False
    escape = False
    for j in range(i, len(text)):
        ch = text[j]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[i:j + 1], j + 1
    return None


@dataclass
class Step:
    thought: str
    action: dict
    raw_output: str


class CognitiveEngine:
    def __init__(self, model: str, base_url: str, temperature: float = 0.2,
                 top_p: float = 0.9, seed: int | None = 42, retry_limit: int = 2,
                 num_predict: int = 512, num_ctx: int = 8192,
                 num_thread: int | None = None):
        self.model = model
        self.temperature = temperature
        self.top_p = top_p
        self.seed = seed
        self.retry_limit = retry_limit
        # Cap the CPU threads Ollama uses for inference. Qwen2.5 7B is ~58%
        # CPU-offloaded on the 4GB GPU, so inference is CPU-bound and pins the CPU
        # at ~94 C on all 12 cores. Running on fewer threads (e.g. 8) trades a
        # little per-token speed for a steady ~85 C instead of maxing out and
        # tripping the thermal guard -- which avoids the far costlier on/off
        # thrash of unloading+reloading the 7B model every time (user ask
        # 2026-10-14: "jangan pake max, agak di-anuin"). None = Ollama default.
        self.num_thread = num_thread
        # Explicit context window so the (large) RAG + skills + tools prompt is
        # not silently truncated -- a too-small default would drop the tail of
        # the prompt (including the ACTION contract) without any error.
        self.num_ctx = num_ctx
        # Cap generated tokens. One THOUGHT + one-line ACTION fits well under this;
        # without a cap a small model can ramble for minutes and burn the whole
        # per-run wall-clock budget on a single turn (observed live on RTX 2050:
        # one turn ran >8 min and got the run killed mid-loop).
        self.num_predict = num_predict
        self.client = ollama.Client(host=base_url)
        self.total_tokens = 0

    def _call_model(self, messages: list[dict]) -> str:
        options = {"temperature": self.temperature, "top_p": self.top_p,
                   "num_predict": self.num_predict, "num_ctx": self.num_ctx}
        if self.seed is not None:
            options["seed"] = self.seed
        if self.num_thread is not None:
            options["num_thread"] = self.num_thread
        try:
            # think=False: qwen3.5+ ships as a thinking model with thinking ON by
            # default, which routes the whole reply into a `thinking` field and
            # leaves message.content EMPTY -> PARSE_FAILURE death-spiral. Disabling
            # thinking restores the clean ReAct JSON the parser expects (the base
            # model stays frozen; this is a decode-mode flag, not a weight change).
            # Fallback for older ollama-python without the `think` kwarg.
            try:
                response = self.client.chat(model=self.model, messages=messages,
                                            options=options, think=False)
            except TypeError:
                response = self.client.chat(model=self.model, messages=messages, options=options)
        except ollama.ResponseError as exc:
            # Ollama can abort a generation server-side (HTTP 500), most often
            # "prediction aborted, token repeat limit reached" when a small model
            # gets stuck emitting the same token. Before this guard that bubbled
            # up as an uncaught exception and killed the WHOLE run (observed
            # 2026-10-13 on sqli_medium). Treat it like empty/malformed output:
            # return "" so step()'s retry loop asks the model to resend, and if
            # it keeps aborting the run records a PARSE_FAILURE iteration and
            # continues -- the same graceful degradation used for HTTP timeouts.
            return ""
        self.total_tokens += response.get("prompt_eval_count", 0) + response.get("eval_count", 0)
        return response["message"]["content"]

    @staticmethod
    def parse(raw_output: str) -> Step:
        """Parse a raw model response into a Step. Raises ActionParseError on
        malformed output (missing blocks or invalid JSON in the ACTION block).
        """
        cleaned = raw_output.replace("```json", "").replace("```", "").strip()

        # Locate the ACTION label; the JSON object is the first balanced {...}
        # after it. Fall back to the first JSON object anywhere that carries a
        # "type" field, so an output that omits the label still parses.
        action_label = _ACTION_LABEL.search(cleaned)
        search_from = action_label.end() if action_label else 0
        extracted = _extract_json_object(cleaned, search_from)
        if extracted is None and action_label is None:
            # No label and no object after position 0: scan for any {...} that
            # looks like an action (has a "type" key).
            pos = 0
            while True:
                found = _extract_json_object(cleaned, pos)
                if found is None:
                    break
                if '"type"' in found[0]:
                    extracted = found
                    break
                pos = found[1]
        if extracted is None:
            raise ActionParseError(
                "Output missing an ACTION JSON object in the required format."
            )
        action_text, action_end = extracted

        # THOUGHT is whatever precedes the ACTION label (or the JSON). A missing
        # THOUGHT label is tolerated -- the reasoning text is still captured.
        thought_region = cleaned[:action_label.start()] if action_label else cleaned[:cleaned.find(action_text)]
        thought_label = _THOUGHT_LABEL.search(thought_region)
        thought = thought_region[thought_label.end():].strip() if thought_label else thought_region.strip()

        try:
            action = json.loads(action_text)
        except json.JSONDecodeError as exc:
            raise ActionParseError(f"ACTION block is not valid JSON: {exc}") from exc

        if not isinstance(action, dict) or "type" not in action:
            raise ActionParseError("ACTION JSON missing required 'type' field.")
        if action["type"] not in ALLOWED_ACTION_TYPES:
            raise ActionParseError(
                f"ACTION type '{action['type']}' is not one of {sorted(ALLOWED_ACTION_TYPES)}."
            )
        action.setdefault("tool", None)

        # Fold flattened parameters back into params. A small model frequently
        # emits {"type": "HTTP_REQUEST", "method": ..., "value": ..., "params": {}}
        # -- the payload keys at the top level and params left empty. Without
        # this, the executor reads an empty value and silently sends nothing,
        # which looks like a failed attempt but is really a dropped payload.
        params = action.get("params")
        if not isinstance(params, dict):
            params = {}
        for key in [k for k in action if k not in ("type", "tool", "params")]:
            params.setdefault(key, action.pop(key))
        action["params"] = params
        return Step(thought=thought, action=action, raw_output=raw_output)

    def step(self, messages: list[dict]) -> Step:
        """Run one reasoning turn. On malformed output, ask the model to repair
        it (up to retry_limit times) before giving up.
        """
        conversation = list(messages)
        last_error: Exception | None = None
        for attempt in range(self.retry_limit + 1):
            raw_output = self._call_model(conversation)
            try:
                return self.parse(raw_output)
            except ActionParseError as exc:
                last_error = exc
                conversation.append({"role": "assistant", "content": raw_output})
                conversation.append({
                    "role": "user",
                    "content": (
                        f"Your previous output was invalid: {exc} "
                        "Resend using exactly THOUGHT: ... then ACTION: <one-line JSON>. "
                        "No other text."
                    ),
                })
        raise ActionParseError(
            f"Exceeded retry_limit ({self.retry_limit}) trying to get valid THOUGHT/ACTION output. "
            f"Last error: {last_error}"
        )
