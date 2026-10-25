"""FastAPI app for testing the AI firewall.

Run:   uvicorn app.main:app --reload
Docs:  http://127.0.0.1:8000/docs
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from pydantic import BaseModel, Field

from .detector import Detector, Verdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("firewall")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the embedding model and signatures once at startup, not per request.
    app.state.detector = Detector()
    yield


app = FastAPI(title="AI Firewall", version="0.1.0", lifespan=lifespan)


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=100_000)


class ScanResponse(BaseModel):
    verdict: Verdict
    allowed: bool
    stage: str
    reasons: list[str]
    rule_hits: list[dict]
    semantic: Optional[dict]
    latency_ms: float


@app.post("/scan", response_model=ScanResponse)
def scan(body: ScanRequest, request: Request) -> ScanResponse:
    # Plain `def`: FastAPI runs it in a thread pool, so CPU-bound scanning doesn't block the event loop.
    result = request.app.state.detector.scan(body.prompt)
    if result.verdict != Verdict.ALLOW:
        log.info("verdict=%s stage=%s reasons=%s", result.verdict.value, result.stage, result.reasons)
    return ScanResponse(
        verdict=result.verdict,
        allowed=result.verdict != Verdict.BLOCK,
        stage=result.stage,
        reasons=result.reasons,
        rule_hits=result.rule_hits,
        semantic=result.semantic,
        latency_ms=result.latency_ms,
    )


@app.get("/health")
def health(request: Request) -> dict:
    det = request.app.state.detector
    return {
        "status": "ok",
        "semantic_backend": det.semantic.backend.name,
        "attack_signatures": len(det.semantic.attack_texts),
    }
