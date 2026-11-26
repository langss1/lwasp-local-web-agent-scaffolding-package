# K4 (R2-3) — Public controller comparison: adaptation attempt + blocker

> Honest outcome: the LLM path works, but the controller cannot be run under conditions
> **matched** to our autonomous arms without changing its design. Per the pre-registered
> plan (K3_K4_PLAN_FINAL.md §"Conditional escape"), the attempt and the concrete blocker
> are documented and the Table 9 claim is NARROWED. **No PentestGPT run numbers are
> fabricated.**

## What was attempted (all verified, on the pod)
1. Controller = **PentestGPT (GreyDGL), legacy path**, commit
   **`e8b1bb77d1ac00329675cec3b060aba971ec1ac8`** (pinned in `k4_controller_pin.json`).
   Package `pentestgpt` 1.0.0 / "modernized legacy v2.0.0", console script `pentestgpt-legacy`.
2. Installed in an isolated venv (`/workspace/PentestGPT/.venvpg`).
3. Configured for our local model: the registry exposes a dynamic `ollama:<model>` id with
   base_url `http://localhost:11434/v1`; CLI flags `--reasoning-model ollama:qwen2.5
   --parsing-model ollama:qwen2.5 --base-url http://127.0.0.1:11434/v1` are present.
4. **LLM round-trip CONFIRMED:** `get_client("ollama:qwen2.5").send_new_message(...)` returned
   a correct completion from our frozen qwen2.5 via ollama (~17.6 s). So PentestGPT legacy
   *can* drive our local model end-to-end at the LLM layer.

## The blocker (why a matched full-cycle run is not possible)
PentestGPT legacy is, by design, a **human-in-the-loop advisory assistant**, not an
autonomous agent. Evidence read directly from its source
(`pentestgpt_legacy/utils/pentest_gpt.py`, commit above):
- The session is a **human REPL**: `input_handler`/`local_input_handler` block on
  `prompt_ask("Your input: ")` / `prompt_ask("> ")`; the dispatch menu is
  `next / more / todo / discuss / google / help / quit`.
- Tool execution is **delegated to the human operator**. The built-in prompts literally
  instruct the user to *"Paste the output of the security test tool used"* and *"Paste the
  relevant content of a web page"* (prompt table, lines ~53–55).
- There is **no autonomous command/tool executor** in the legacy package: a repository-wide
  search for `subprocess` / `os.system` / `pexpect` / `paramiko` / HTTP-client calls against
  a target returns **nothing** in `pentestgpt_legacy/` outside the LLM provider layer.

Consequently the ReAct cycle `model → action → tool → observation → next decision` is broken
at **action/tool**: PentestGPT emits a *suggested* command (reasoning + task-tree), but a
**human** must run it against the target and paste the observation back. Our arms execute
tools autonomously with an independent success oracle. The two are therefore **not matched**:
- Inserting a human (or a script standing in as the operator) adds an **un-matched operator
  step** the plan explicitly excludes.
- Building an auto-executor that parses PentestGPT's suggested commands and runs them would
  **add a capability it deliberately lacks and replace its human-in-loop control design** —
  forbidden by the adapter rule ("bridge interfaces only; do NOT replace the controller's own
  control logic").

## Consequence for the manuscript (narrowed Table 9 claim)
- We do **not** report a matched autonomous OSR head-to-head for PentestGPT, because one
  cannot be produced without changing its design or adding an un-matched operator.
- Table 9 is narrowed to an **architectural / capability** comparison, stated as such:
  PentestGPT legacy is a human-advised assistant (human executes tools and supplies
  observations), whereas our system closes the loop autonomously with an independent
  verification oracle. The distinction we claim is **categorical** (autonomy + objective
  verification), not a numeric OSR delta.
- What IS positively established and reportable: (a) the controller is runnable and can be
  driven by the same local qwen2.5 we use (LLM round-trip verified), and (b) its design
  requires a human operator for the action/observation steps — which is the specific gap our
  contribution addresses.

## Reproducibility pointers
- `k4_controller_pin.json` — controller, commit, entrypoint, LLM path, pinned timestamp.
- Round-trip check: `get_client("ollama:qwen2.5").send_new_message("...")` on `.venvpg`.
- Interaction model: `pentestgpt_legacy/utils/pentest_gpt.py` (`input_handler`, prompt table).

## Optional future extension (NOT done here; would be a DIFFERENT, labelled condition)
A PentestGPT-*with-operator* run (a scripted operator executes its suggested commands against
DVWA and pastes results back) could be reported as a separate, clearly-labelled condition —
but it is **not** a matched autonomous comparison and is not claimed as one.
