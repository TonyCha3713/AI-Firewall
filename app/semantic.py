"""Stage 2: semantic similarity against known attack signatures.

Embeds the prompt (in overlapping chunks, so an attack buried in a long benign
prompt still stands out), then compares it with every attack signature and every
benign anchor using cosine similarity.

Backends:
  - "sentence-transformers" (default): all-MiniLM-L6-v2, 384-dim, ~5-15 ms on CPU.
  - "tfidf" (fallback): character n-gram TF-IDF. No download needed, but it only
    matches similar *wording*, not meaning. Used automatically if the model can't load.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

import numpy as np

from .signatures import ATTACKS, BENIGN_ANCHORS

log = logging.getLogger("firewall.semantic")

DEFAULT_MODEL = os.getenv("FIREWALL_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

# Thresholds differ per backend because the similarity scales differ.
THRESHOLDS = {
    "sentence-transformers": {"block": 0.70, "flag": 0.55, "margin": 0.05},
    "tfidf": {"block": 0.45, "flag": 0.32, "margin": 0.05},
}
SHORT_PROMPT_WORDS = 40   # prompts this short are embedded whole, no chunking
LONG_SENTENCE_WORDS = 40  # sentences longer than this get split into word windows
MAX_CHUNKS = 128          # unique chunks per prompt (very long prompts are also caught by the length rule)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


class _SentenceTransformerBackend:
    name = "sentence-transformers"

    def __init__(self, model_name: str):
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(model_name, device="cpu")

    def fit(self, corpus: list[str]) -> None:  # pretrained, nothing to fit
        pass

    def encode(self, texts: list[str]) -> np.ndarray:
        return self.model.encode(texts, normalize_embeddings=True, convert_to_numpy=True).astype(np.float32)


class _TfidfBackend:
    name = "tfidf"

    def __init__(self):
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, lowercase=True)

    def fit(self, corpus: list[str]) -> None:
        self.vec.fit(corpus)

    def encode(self, texts: list[str]) -> np.ndarray:
        m = self.vec.transform(texts).toarray().astype(np.float32)
        norms = np.linalg.norm(m, axis=1, keepdims=True)
        return m / np.maximum(norms, 1e-12)


@dataclass
class SemanticResult:
    attack_score: float      # best cosine similarity to any attack signature
    benign_score: float      # best cosine similarity to any benign anchor
    family: str              # attack family of the closest signature
    closest_signature: str
    backend: str


def chunk(text: str) -> list[str]:
    """Split a long prompt into sentence-sized chunks.

    Embedding models average over every word, so one attack sentence inside a big
    window of normal text gets diluted. Embedding each sentence (and each pair of
    neighbouring sentences, for attacks split across two) keeps the attack sentence
    on its own, where it scores about as high as it would alone.
    """
    if len(text.split()) <= SHORT_PROMPT_WORDS:
        return [text]

    sentences: list[str] = []
    for s in _SENTENCE_SPLIT.split(text):
        words = s.split()
        if not words:
            continue
        if len(words) <= LONG_SENTENCE_WORDS:
            sentences.append(" ".join(words))
        else:  # run-on text with no punctuation: overlapping word windows
            step = LONG_SENTENCE_WORDS // 2
            for i in range(0, len(words) - step, step):
                sentences.append(" ".join(words[i:i + LONG_SENTENCE_WORDS]))

    chunks = sentences + [f"{a} {b}" for a, b in zip(sentences, sentences[1:])]
    # Drop duplicates (repeated boilerplate is common) while keeping order.
    return list(dict.fromkeys(chunks))[:MAX_CHUNKS]


class SemanticDetector:
    def __init__(self, backend: str | None = None, model_name: str = DEFAULT_MODEL):
        backend = backend or os.getenv("FIREWALL_SEMANTIC_BACKEND", "sentence-transformers")
        self.backend = self._load_backend(backend, model_name)
        self.thresholds = THRESHOLDS[self.backend.name]

        self.attack_texts: list[str] = []
        self.attack_families: list[str] = []
        for family, examples in ATTACKS.items():
            self.attack_texts.extend(examples)
            self.attack_families.extend([family] * len(examples))

        self.backend.fit(self.attack_texts + BENIGN_ANCHORS)
        # Rows are L2-normalized, so cosine similarity is just a dot product.
        self.attack_matrix = self.backend.encode(self.attack_texts)
        self.benign_matrix = self.backend.encode(BENIGN_ANCHORS)
        log.info("Semantic stage ready: backend=%s, %d attack signatures, %d benign anchors",
                 self.backend.name, len(self.attack_texts), len(BENIGN_ANCHORS))

    @staticmethod
    def _load_backend(backend: str, model_name: str):
        if backend == "tfidf":
            return _TfidfBackend()
        try:
            return _SentenceTransformerBackend(model_name)
        except Exception as exc:  # no internet, missing package, etc.
            log.warning("Could not load embedding model %r (%s). Falling back to TF-IDF.", model_name, exc)
            return _TfidfBackend()

    def score(self, texts: list[str]) -> SemanticResult:
        """Score one or more text variants; keep the worst (most attack-like) chunk."""
        chunks: list[str] = []
        for t in texts:
            chunks.extend(chunk(t))
        chunks = list(dict.fromkeys(chunks))
        emb = self.backend.encode(chunks)

        # np.errstate: NumPy 2.x on macOS (Apple Accelerate) emits bogus
        # "divide by zero / overflow in matmul" warnings even when results are fine.
        # nan_to_num is a safety net in case a value really is bad.
        with np.errstate(all="ignore"):
            attack_sims = np.nan_to_num(emb @ self.attack_matrix.T, nan=0.0, posinf=0.0, neginf=0.0)
            benign_sims = np.nan_to_num(emb @ self.benign_matrix.T, nan=0.0, posinf=0.0, neginf=0.0)

        best_chunk, best_sig = np.unravel_index(np.argmax(attack_sims), attack_sims.shape)
        return SemanticResult(
            attack_score=float(attack_sims[best_chunk, best_sig]),
            benign_score=float(benign_sims[best_chunk].max()),
            family=self.attack_families[best_sig],
            closest_signature=self.attack_texts[best_sig],
            backend=self.backend.name,
        )
