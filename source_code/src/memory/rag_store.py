"""Long-term RAG memory over the local knowledge corpus (OWASP docs, SecLists
payload categories, optional extra theory). Persistent ChromaDB collection.

This is retrieval at runtime, not model training -- never conflate the two.
Chunking here is separate from, and unrelated to, weight quantization.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import chromadb


def chunk_text(text: str, chunk_size_tokens: int = 500, overlap_tokens: int = 50) -> list[str]:
    """Whitespace-token chunking (good enough proxy for LLM tokens without
    pulling in a tokenizer dependency just for ingestion).
    """
    words = text.split()
    if not words:
        return []
    chunks = []
    step = max(chunk_size_tokens - overlap_tokens, 1)
    for start in range(0, len(words), step):
        chunk_words = words[start:start + chunk_size_tokens]
        if not chunk_words:
            break
        chunks.append(" ".join(chunk_words))
        if start + chunk_size_tokens >= len(words):
            break
    return chunks


@dataclass
class RetrievedChunk:
    text: str
    source: str
    category: str
    score: float


class OllamaEmbedder:
    """Embedding function backed by an Ollama embedding model (nomic-embed-text)."""

    def __init__(self, client, model: str = "nomic-embed-text"):
        self.client = client
        self.model = model

    def __call__(self, text: str) -> list[float]:
        resp = self.client.embeddings(model=self.model, prompt=text)
        return resp["embedding"]


class SentenceTransformerEmbedder:
    """Fully offline alternative embedding function (all-MiniLM-L6-v2)."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name)

    def __call__(self, text: str) -> list[float]:
        return self.model.encode(text).tolist()


class RagStore:
    def __init__(self, chroma_dir: str, collection_name: str, embed_fn: Callable[[str], list[float]]):
        self.embed_fn = embed_fn
        self.client = chromadb.PersistentClient(path=chroma_dir)
        self.collection = self.client.get_or_create_collection(
            collection_name, metadata={"hnsw:space": "cosine"}
        )

    def _embed_with_fallback(self, chunk: str, min_words: int = 20) -> list[list[float]] | None:
        """Embed a chunk; if the embedding model's context is exceeded (dense
        payload-list files can pack far more subword tokens per word than
        prose), recursively halve the chunk until it fits, or drop it if it
        can't be split further. Returns a list of (sub-chunk, embedding) pairs
        as [sub_chunk_text, embedding] tuples, flattened by the caller.
        """
        words = chunk.split()
        try:
            return [(chunk, self.embed_fn(chunk))]
        except Exception:
            if len(words) <= min_words:
                return []  # give up on this fragment rather than crash ingestion
            mid = len(words) // 2
            left = " ".join(words[:mid])
            right = " ".join(words[mid:])
            return self._embed_with_fallback(left, min_words) + self._embed_with_fallback(right, min_words)

    def ingest_file(self, path: Path, category: str, chunk_size_tokens: int = 500,
                     overlap_tokens: int = 50) -> int:
        text = path.read_text(encoding="utf-8", errors="ignore")
        chunks = chunk_text(text, chunk_size_tokens, overlap_tokens)
        if not chunks:
            return 0
        ids, embeddings, metadatas, documents = [], [], [], []
        count = 0
        for i, chunk in enumerate(chunks):
            for sub_chunk, embedding in self._embed_with_fallback(chunk):
                ids.append(f"{path.stem}-{category}-{i}-{count}")
                embeddings.append(embedding)
                metadatas.append({"source": path.name, "category": category})
                documents.append(sub_chunk)
                count += 1
        if not embeddings:
            return 0
        self.collection.upsert(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents)
        return len(embeddings)

    def retrieve(self, query: str, k: int = 5, category: str | None = None) -> list[RetrievedChunk]:
        where = {"category": category} if category else None
        result = self.collection.query(
            query_embeddings=[self.embed_fn(query)], n_results=k, where=where,
        )
        chunks: list[RetrievedChunk] = []
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        dists = result.get("distances", [[]])[0]
        for doc, meta, dist in zip(docs, metas, dists):
            chunks.append(RetrievedChunk(
                text=doc, source=meta.get("source", "?"), category=meta.get("category", "?"),
                score=1.0 - dist,
            ))
        return chunks
