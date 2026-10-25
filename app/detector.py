"""Two-stage pipeline: rules first, semantic second."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum

from .normalize import variants
from .rules import RuleHit, Severity, run_rules
from .semantic import SemanticDetector

# Each MEDIUM rule hit lowers the semantic thresholds by this much (capped).
MEDIUM_HIT_DISCOUNT = 0.07
MAX_DISCOUNT = 0.14
# If a prompt is this much closer to a benign anchor than to any attack, medium rule hits are ignored.
BENIGN_OVERRIDE = 0.15


class Verdict(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"      # suspicious: log it / send for review, but let it through
    BLOCK = "block"


@dataclass
class ScanResult:
    verdict: Verdict
    stage: str                       # "rules" | "semantic"
    reasons: list[str]
    rule_hits: list[dict] = field(default_factory=list)
    semantic: dict | None = None
    latency_ms: float = 0.0


class Detector:
    def __init__(self, semantic: SemanticDetector | None = None):
        self.semantic = semantic or SemanticDetector()

    def scan(self, prompt: str) -> ScanResult:
        start = time.perf_counter()
        texts = variants(prompt)

        # ---- Stage 1: rules ----
        hits = run_rules(prompt, texts)
        high = [h for h in hits if h.severity == Severity.HIGH]
        medium = [h for h in hits if h.severity == Severity.MEDIUM]
        hit_dicts = [_hit_dict(h) for h in hits]

        if high:
            return ScanResult(
                verdict=Verdict.BLOCK,
                stage="rules",
                reasons=[f"rule {h.rule_id} ({h.category})" for h in high],
                rule_hits=hit_dicts,
                latency_ms=_ms(start),
            )

        # ---- Stage 2: semantic ----
        sem = self.semantic.score(texts)
        t = self.semantic.thresholds
        discount = min(MEDIUM_HIT_DISCOUNT * len(medium), MAX_DISCOUNT)
        block_t, flag_t = t["block"] - discount, t["flag"] - discount
        gap = sem.attack_score - sem.benign_score   # >0 means it looks more like an attack than a known-benign prompt
        semantic_flag = sem.attack_score >= flag_t and gap > 0
        # A medium rule hit alone is enough to flag, unless the prompt clearly matches a benign anchor.
        rule_flag = bool(medium) and gap > -BENIGN_OVERRIDE

        if sem.attack_score >= block_t and gap >= t["margin"]:
            verdict = Verdict.BLOCK
        elif semantic_flag or rule_flag:
            verdict = Verdict.FLAG
        else:
            verdict = Verdict.ALLOW

        reasons = []
        if verdict != Verdict.ALLOW:
            if semantic_flag or verdict == Verdict.BLOCK:
                reasons.append(f"semantically similar to {sem.family} (score {sem.attack_score:.2f})")
            reasons += [f"rule {h.rule_id} ({h.category})" for h in medium]

        return ScanResult(
            verdict=verdict,
            stage="semantic",
            reasons=reasons,
            rule_hits=hit_dicts,
            semantic={
                **asdict(sem),
                "attack_score": round(sem.attack_score, 4),
                "benign_score": round(sem.benign_score, 4),
                "block_threshold": round(block_t, 3),
                "flag_threshold": round(flag_t, 3),
            },
            latency_ms=_ms(start),
        )


def _hit_dict(h: RuleHit) -> dict:
    return {"rule_id": h.rule_id, "category": h.category, "severity": h.severity.value, "matched": h.matched}


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)
