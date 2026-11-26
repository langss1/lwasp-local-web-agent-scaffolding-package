"""Semantic guardrail (PCB: Payload, Context, Behavior). New contribution
described in plan.md 4.5.

Instead of exact-string anti-looping, this compares the *embedding* of a
candidate action against previously failed attempts in the same context
(endpoint + param + level). A near-duplicate in meaning (different spacing,
encoding, casing) gets blocked even though the strings differ.
"""

from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

import numpy as np


def normalize_payload(payload: str) -> str:
    """Canonicalise a payload so cosmetic variants collapse together before
    embedding: url-decode (so %27/%20/+ match their literal forms), lowercase,
    and collapse runs of whitespace. This is what lets the guardrail see through
    encoding/spacing/case evasion (plan.md 4.5) with a real embedding model,
    which -- unlike the test's stub embedder -- does not decode %27 on its own.
    Measured live 2026-09-30: a url-encoded duplicate scored only 0.815 without
    this step (below the 0.92 threshold), so the evasion slipped through.
    """
    text = urllib.parse.unquote_plus(payload or "")
    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text


def cosine_similarity(a: list[float], b: list[float]) -> float:
    va, vb = np.array(a, dtype=float), np.array(b, dtype=float)
    denom = (np.linalg.norm(va) * np.linalg.norm(vb))
    if denom == 0:
        return 0.0
    return float(np.dot(va, vb) / denom)


@dataclass
class PcbRecord:
    payload: str
    context: dict[str, Any]
    behavior: dict[str, Any]
    embedding: list[float]
    timestamp: float = field(default_factory=time.time)

    def context_key(self) -> tuple:
        return (
            self.context.get("endpoint"),
            self.context.get("param"),
            self.context.get("dvwa_level"),
        )


@dataclass
class GuardrailVerdict:
    blocked: bool
    reason: str
    similarity: float | None = None
    matched_payload: str | None = None


def response_signature(status_code: int, body: str) -> str:
    """Cheap, stable signature of an HTTP response for prior_response_sig."""
    digest = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{status_code}:{len(body)}:{digest}"


class SemanticGuardrail:
    def __init__(self, embed_fn: Callable[[str], list[float]], threshold: float = 0.92):
        """embed_fn: same embedding model used by the RAG store, injected so the
        guardrail and the knowledge base stay consistent.
        """
        self.embed_fn = embed_fn
        self.threshold = threshold
        self._records: list[PcbRecord] = []

    def _context_text(self, payload: str, context: dict[str, Any]) -> str:
        """Text that gets embedded for the similarity comparison.

        Only the payload is embedded, NOT the endpoint/param/level. Those already
        gate the comparison as an exact-match key (see check()), so embedding them
        again just makes every candidate in the same context share 3/4 of its text
        -- which inflates cosine similarity and blocks genuinely different SQL
        techniques (measured live 2026-09-30: distinct time-blind vs data-
        extraction vs error-based payloads all scored 0.94-0.97 and were wrongly
        blocked). Embedding the payload alone lets similarity reflect the actual
        technique difference, which is what the guardrail is meant to catch.
        """
        return f"payload: {normalize_payload(payload)}"

    def record(self, payload: str, context: dict[str, Any], behavior: dict[str, Any]) -> PcbRecord:
        embedding = self.embed_fn(self._context_text(payload, context))
        rec = PcbRecord(payload=payload, context=context, behavior=behavior, embedding=embedding)
        self._records.append(rec)
        return rec

    def check(self, payload: str, context: dict[str, Any]) -> GuardrailVerdict:
        """Compare against prior FAILED attempts sharing the same
        (endpoint, param, dvwa_level) context.

        BLOCK DECISION = **canonical identity** (2026-10-15): a candidate is blocked
        only when it is IDENTICAL, after canonicalisation (`normalize_payload`:
        url-decode + lowercase + whitespace-collapse), to a previously failed
        payload in the same context. This still sees through encoding / spacing /
        casing evasion -- those variants canonicalise to the same text -- but it no
        longer blocks a GENUINELY DIFFERENT technique that merely embeds close to a
        failure. (Live failure 2026-10-15: at sqli_medium the correct `1 OR 1=1 -- `
        scored >=0.92 against a failed `1 OR '1'='1' -- ` and was wrongly blocked,
        suppressing the winning payload. User direction: block only 100%-identical.)

        The embedding cosine is still computed and reported (evidence/telemetry),
        but it no longer drives the decision.
        """
        candidate_embedding = self.embed_fn(self._context_text(payload, context))
        target_key = (context.get("endpoint"), context.get("param"), context.get("dvwa_level"))
        candidate_norm = normalize_payload(payload)

        best_similarity = 0.0
        best_match: PcbRecord | None = None
        identical_match: PcbRecord | None = None
        for rec in self._records:
            if rec.context_key() != target_key:
                continue
            if rec.behavior.get("success"):
                continue  # only guard against repeating known FAILURES
            sim = cosine_similarity(candidate_embedding, rec.embedding)
            if sim > best_similarity:
                best_similarity = sim
                best_match = rec
            if identical_match is None and normalize_payload(rec.payload) == candidate_norm:
                identical_match = rec

        if identical_match is not None:
            return GuardrailVerdict(
                blocked=True,
                reason=(
                    f"Identical (after canonicalisation) to a previously failed attempt "
                    f"on the same endpoint/param/level: payload='{identical_match.payload}' "
                    f"(embedding similarity={best_similarity:.3f}, reported only)."
                ),
                similarity=best_similarity,
                matched_payload=identical_match.payload,
            )
        return GuardrailVerdict(blocked=False, reason="No identical prior failure (distinct technique allowed).",
                                 similarity=best_similarity)

    def block_count(self) -> int:
        return sum(1 for r in self._records if not r.behavior.get("success"))
