"""Cross-session long-term memory: distilled lessons carried from one run into
the next. This is the "flash -> permanent" promotion described in plan.md 4.3.2
(the Resume section) taken one step further -- the working-memory .md lives for a
single run, but the lessons distilled from it persist here and are retrieved into
future runs' context.

Conceptually this is the agent accumulating experience across sessions WITHOUT
touching model weights: it is retrieval at runtime, never fine-tuning. Do not
describe this as "training the model" -- nothing here changes qwen2.5's weights.
Vectorising a lesson (text -> numbers for search) is unrelated to quantising a
model (shrinking weights). Keep the two apart.

Storage mirrors the two-layer pattern proven in the RAG store:

| Layer            | Form                              | Why                                   |
|------------------|-----------------------------------|---------------------------------------|
| Source of truth  | one JSONL line per lesson         | human-readable, greppable, deletable  |
| Index            | Chroma collection `agent_lessons` | semantic retrieval                    |

The index is always rebuildable from the JSONL, so a corrupt or missing index is
never fatal. If embedding is unavailable (Ollama busy loading a model), retrieval
degrades to word-overlap scoring rather than failing the run.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

COLLECTION = "agent_lessons"

# A lesson that runs long enough eats the whole budget on its own.
MAX_LESSON_CHARS = 400

# Retrieval budget (whitespace-word proxy for tokens, same proxy the RAG
# chunker uses -- avoids pulling a tokenizer dependency just for a budget check).
DEFAULT_TOKEN_BUDGET = 350
DEFAULT_TOP_K = 5

# Lock for the read-modify-write cycle. Ablation harnesses can launch runs back
# to back; two processes appending at once could lose an update. This is a
# simple exclusive-create lock (one machine, cooperating processes), with a
# staleness timeout so a crashed holder never wedges the file forever.
LOCK_TIMEOUT_S = 5.0
LOCK_POLL_S = 0.05

_WORD = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "for", "from", "with", "and", "was", "were", "that", "this", "into",
    "not", "but", "its", "has", "had", "did", "does", "any", "all", "via",
    "level", "dvwa", "param", "endpoint",  # over-common in this domain: drop as noise
}


class LongTermMemoryError(Exception):
    """A lesson is invalid or the store cannot be written."""


def _words(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOP and len(w) > 2}


def _word_overlap(a: str, b: str) -> float:
    wa, wb = _words(a), _words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def _token_proxy(text: str) -> int:
    return len(text.split())


@dataclass
class Lesson:
    """One distilled takeaway from a completed run.

    `vuln_type` is the isolation key: an SQLi lesson surfacing during an XSS run
    is misleading advice, not useful context (mirrors the project-scoping rule in
    lang-ai's memori.py). Retrieval filters on it.
    """

    text: str
    vuln_type: str = ""          # "sqli" | "xss_reflected" | "xss_stored" | ""
    level: str = ""              # "low" | "medium" | ""
    endpoint: str = ""
    param: str = ""
    outcome: str = ""            # "success" | "fail" | ""
    run_id: str = ""
    created: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        self.text = (self.text or "").strip()
        if not self.id:
            # Hash text + vuln_type so the same wording learned for SQLi and XSS
            # are still two distinct lessons.
            key = f"{self.text.lower()}|{self.vuln_type}"
            self.id = hashlib.sha1(key.encode()).hexdigest()[:12]
        if not self.created:
            self.created = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def line(self) -> str:
        """One-line form injected into the prompt context."""
        tag = f"[{self.vuln_type}/{self.level}]" if self.vuln_type else ""
        mark = {"success": "OK", "fail": "X"}.get(self.outcome, "-")
        return f"- {tag} ({mark}) {self.text}"


# ---------------------------------------------------------------------------
# Store (JSONL source of truth)
# ---------------------------------------------------------------------------

class LongTermMemory:
    def __init__(
        self,
        store_dir: str | Path,
        embed_fn: Callable[[str], list[float]] | None = None,
        chroma_dir: str | Path | None = None,
    ):
        self.store_dir = Path(store_dir)
        self.jsonl_path = self.store_dir / "lessons.jsonl"
        self.lock_path = self.store_dir / "lessons.lock"
        self.embed_fn = embed_fn
        # The lessons index can share the RAG Chroma dir or live on its own; it
        # is a distinct collection either way.
        self.chroma_dir = Path(chroma_dir) if chroma_dir else self.store_dir / "chroma"
        self._index: "_LessonIndex | None" = None

    # -- low-level jsonl io -------------------------------------------------

    def _load(self) -> list[Lesson]:
        if not self.jsonl_path.exists():
            return []
        # Read defensively: on Windows an in-flight os.replace from a concurrent
        # record() (now more frequent since WEB_SEARCH records lessons mid-run)
        # can briefly make the file raise OSError [Errno 22] on open. A transient
        # read failure must NEVER crash the run -- treat it as "no lessons this
        # read" (the JSONL is only a cache; the run proceeds fine without it).
        try:
            raw = self.jsonl_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []
        out: list[Lesson] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(Lesson(**json.loads(line)))
            except (json.JSONDecodeError, TypeError):
                continue  # one broken line must not sink the whole store
        return out

    def _write(self, lessons: list[Lesson]) -> None:
        """Atomic write: temp file then os.replace (atomic on NTFS and POSIX),
        so a crash mid-write never leaves a half-written JSONL that drops every
        lesson behind the truncation point.
        """
        self.store_dir.mkdir(parents=True, exist_ok=True)
        body = "\n".join(json.dumps(asdict(le), ensure_ascii=False) for le in lessons)
        body = body + ("\n" if body else "")
        tmp = self.jsonl_path.with_suffix(".jsonl.tmp")
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, self.jsonl_path)

    @contextmanager
    def _lock(self):
        self.store_dir.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except (FileExistsError, PermissionError):
                # Windows can raise PermissionError (not FileExistsError) right
                # after another process unlinks its own lock -- NTFS is slow to
                # drop the dir entry. Treat both as "held, retry".
                try:
                    if time.time() - self.lock_path.stat().st_mtime > LOCK_TIMEOUT_S:
                        self.lock_path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.time() - t0 > LOCK_TIMEOUT_S:
                    raise LongTermMemoryError(
                        "Long-term memory is locked by another run. Try again shortly."
                    )
                time.sleep(LOCK_POLL_S)
        try:
            yield
        finally:
            self.lock_path.unlink(missing_ok=True)

    # -- public api ---------------------------------------------------------

    def all(self) -> list[Lesson]:
        """Every stored lesson, newest first."""
        return sorted(self._load(), key=lambda le: le.created, reverse=True)

    def record(
        self,
        text: str,
        vuln_type: str = "",
        level: str = "",
        endpoint: str = "",
        param: str = "",
        outcome: str = "",
        run_id: str = "",
    ) -> Lesson | None:
        """Distil and store one lesson. Returns the stored lesson, or None if it
        was empty or an exact duplicate (same wording + vuln_type already known).
        """
        text = re.sub(r"\s{2,}", " ", (text or "").strip())
        if not text:
            return None
        if len(text) > MAX_LESSON_CHARS:
            text = text[: MAX_LESSON_CHARS - 1].rstrip() + "…"

        new = Lesson(
            text=text, vuln_type=vuln_type, level=level, endpoint=endpoint,
            param=param, outcome=outcome, run_id=run_id,
        )
        with self._lock():
            lessons = self._load()
            if any(le.id == new.id for le in lessons):
                return None
            lessons.append(new)
            self._write(lessons)

        # Indexing failure is never a reason to reject the write: the JSONL is
        # the source of truth and the index rebuilds from it.
        if self.embed_fn is not None:
            try:
                self._get_index().add([new])
            except Exception:
                pass
        return new

    def retrieve(
        self,
        query: str,
        vuln_type: str = "",
        top_k: int = DEFAULT_TOP_K,
        budget: int = DEFAULT_TOKEN_BUDGET,
    ) -> list[Lesson]:
        """Lessons most relevant to `query`, within a token budget.

        Filters to the current `vuln_type` (plus untyped general lessons): a
        lesson learned on one vulnerability class is misleading during another.
        Falls back to word-overlap ranking when embeddings are unavailable.
        """
        pool = [le for le in self._load() if le.vuln_type in ("", vuln_type)]
        if not pool:
            return []

        ranked: list[Lesson] = []
        if self.embed_fn is not None:
            try:
                relevant_texts = self._get_index().search(query, top_k, vuln_type)
                by_text = {le.text: le for le in pool}
                ranked = [by_text[t] for t in relevant_texts if t in by_text]
            except Exception:
                ranked = []
        if not ranked:
            ranked = sorted(
                pool, key=lambda le: _word_overlap(query, le.text), reverse=True
            )[:top_k]

        # Prefer lessons about what WORKED. A small model is easily steered by
        # whatever text it reads, so lead with success/actionable lessons and let
        # failure notes follow only if budget remains (plan6.md: components must
        # add actionable signal, not discouragement). Stable sort keeps the
        # relevance order within each outcome group.
        ranked = sorted(ranked, key=lambda le: 0 if le.outcome == "success" else 1)

        out: list[Lesson] = []
        used = 0
        for le in ranked:
            n = _token_proxy(le.line())
            if used + n > budget:
                continue
            out.append(le)
            used += n
        return out

    def block(self, lessons: list[Lesson]) -> str:
        """Lessons rendered as a prompt-ready block."""
        if not lessons:
            return ""
        body = "\n".join(le.line() for le in lessons)
        return (
            "What earlier runs against this lab learned -- concrete moves that "
            "WORKED (OK) and footholds still worth pursuing. Reach for what "
            "worked here; adapt it to the current target. Do not quote this list "
            "back to anyone.\n"
            f"{body}"
        )

    def rebuild_index(self) -> int:
        """Rebuild the Chroma index from the JSONL. Source of truth is the file."""
        if self.embed_fn is None:
            raise LongTermMemoryError("Cannot rebuild index without an embed_fn.")
        lessons = self._load()
        idx = self._get_index(fresh=True)
        idx.reset()
        idx.add(lessons)
        return len(lessons)

    def stats(self) -> dict:
        lessons = self._load()
        by_type: dict[str, int] = {}
        for le in lessons:
            by_type[le.vuln_type or "(general)"] = by_type.get(le.vuln_type or "(general)", 0) + 1
        return {
            "total": len(lessons),
            "by_vuln_type": by_type,
            "successes": sum(1 for le in lessons if le.outcome == "success"),
            "path": str(self.jsonl_path),
        }

    # -- index (lazy) -------------------------------------------------------

    def _get_index(self, fresh: bool = False) -> "_LessonIndex":
        if fresh or self._index is None:
            self._index = _LessonIndex(str(self.chroma_dir), self.embed_fn)
        return self._index


class _LessonIndex:
    """Thin Chroma wrapper. Always rebuildable from the JSONL, so any failure
    here is caught by the caller and demoted to a word-overlap fallback.
    """

    def __init__(self, chroma_dir: str, embed_fn: Callable[[str], list[float]]):
        import chromadb

        self.embed_fn = embed_fn
        self.db = chromadb.PersistentClient(path=chroma_dir)
        self.col = self.db.get_or_create_collection(
            name=COLLECTION, metadata={"hnsw:space": "cosine"}
        )

    def reset(self) -> None:
        try:
            self.db.delete_collection(COLLECTION)
        except Exception:
            pass
        self.col = self.db.get_or_create_collection(
            name=COLLECTION, metadata={"hnsw:space": "cosine"}
        )

    def add(self, lessons: list[Lesson]) -> None:
        if not lessons:
            return
        self.col.upsert(
            ids=[le.id for le in lessons],
            documents=[le.text for le in lessons],
            embeddings=[self.embed_fn(le.text) for le in lessons],
            metadatas=[
                {"vuln_type": le.vuln_type, "level": le.level, "outcome": le.outcome}
                for le in lessons
            ],
        )

    def search(self, query: str, top_k: int, vuln_type: str) -> list[str]:
        if self.col.count() == 0:
            return []
        # Return the current type plus untyped lessons; an SQLi run should not
        # pull XSS lessons even if they embed nearby.
        where = None
        if vuln_type:
            where = {"vuln_type": {"$in": [vuln_type, ""]}}
        result = self.col.query(
            query_embeddings=[self.embed_fn(query)],
            n_results=min(top_k, self.col.count()),
            where=where,
            include=["documents"],
        )
        docs = result.get("documents", [[]])
        return list(docs[0]) if docs else []
