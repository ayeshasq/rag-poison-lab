"""
Defense Module: Injection Pattern Scanner
==========================================
Scans text before it enters the vector store.
Detects common prompt injection patterns and flags suspicious content.
"""
import re
from dataclasses import dataclass
from typing import Optional

# Known prompt injection patterns (expand this list in your own research)
INJECTION_PATTERNS = [
    # Override attempts
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (all )?(previous|prior|above)",
    r"forget (everything|all) (you|i) (told|said|have)",
    r"you are now in .{0,30} mode",
    # Matches: [SYSTEM OVERRIDE], [SYSTEM DIRECTIVE], [SYSTEM OVERRIDE - INTERNAL AI DIRECTIVE], etc.
    r"\[system[\s\w\-]*(override|directive|admin|internal|prompt)[\s\w\-]*\]",
    r"new (system )?prompt:",
    r"<\|system\|>",
    # Standalone marker words in brackets commonly used as injection delimiters
    r"\[(internal ai directive|admin mode|system prompt|end directive)\]",

    # Role hijacking
    r"you are (now |actually )?(a|an) (different|new|evil|unrestricted)",
    r"act as (a|an) (different|new|unrestricted|jailbreak|ai )?(\w+ )?without (any )?(restrictions|limits|guidelines|ethics)",
    r"act as (a|an) (different|new|unrestricted|jailbreak)",
    r"pretend (you are|to be) (without|with no) restrictions",
    r"without (any )?(restrictions|ethical guidelines|limits|safety)",
    r"your (true|real|actual) (purpose|goal|mission) is",

    # Data exfiltration
    r"(send|email|forward|output|reveal|expose|print|display) (all |any )?(credentials|api.?keys|passwords|secrets|tokens)",
    r"contact .{5,50}@.{3,30}\.(com|net|org|io) for",

    # Policy override
    r"(supersedes|overrides|replaces|nullifies) all previous (policy|documentation|rules)",
    r"effective immediately.{0,50}(unlimited|no limit|unrestricted)",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


@dataclass
class ScanResult:
    is_suspicious: bool
    confidence: float          # 0.0 - 1.0
    matched_patterns: list[str]
    risk_level: str            # LOW / MEDIUM / HIGH / CRITICAL
    recommendation: str

    def __str__(self):
        if not self.is_suspicious:
            return "CLEAN — no injection patterns detected"
        return (
            f"⚠️  SUSPICIOUS [{self.risk_level}] — confidence: {self.confidence:.0%}\n"
            f"   Patterns matched: {len(self.matched_patterns)}\n"
            f"   → {self.recommendation}"
        )


def scan_text(text: str) -> ScanResult:
    """Scan a text chunk for prompt injection patterns before embedding."""
    matched = []
    for i, pattern in enumerate(COMPILED_PATTERNS):
        if pattern.search(text):
            matched.append(INJECTION_PATTERNS[i])

    if not matched:
        return ScanResult(
            is_suspicious=False,
            confidence=0.0,
            matched_patterns=[],
            risk_level="LOW",
            recommendation="Safe to ingest.",
        )

    confidence = min(1.0, len(matched) * 0.3 + 0.2)
    if confidence >= 0.8:
        risk = "CRITICAL"
        rec = "BLOCK — do not ingest this document. Quarantine and review."
    elif confidence >= 0.5:
        risk = "HIGH"
        rec = "BLOCK — likely injection attempt. Requires human review."
    elif confidence >= 0.3:
        risk = "MEDIUM"
        rec = "FLAG — possible injection. Review before ingesting."
    else:
        risk = "LOW"
        rec = "MONITOR — weak signal. Log and ingest with caution."

    return ScanResult(
        is_suspicious=True,
        confidence=confidence,
        matched_patterns=matched,
        risk_level=risk,
        recommendation=rec,
    )


def scan_documents(texts: list[str]) -> list[ScanResult]:
    """Scan a batch of documents. Returns per-document results."""
    return [scan_text(t) for t in texts]


def filter_safe_documents(texts: list[str], metadatas: list[dict] = None):
    """
    Filter out suspicious documents before ingestion.
    Returns (safe_texts, safe_metas, blocked_count).
    """
    results = scan_documents(texts)
    safe_texts, safe_metas = [], []
    blocked = 0

    for i, (text, result) in enumerate(zip(texts, results)):
        if result.risk_level in ("CRITICAL", "HIGH"):
            print(f"[scanner] BLOCKED doc {i}: {result}")
            blocked += 1
        else:
            safe_texts.append(text)
            if metadatas:
                safe_metas.append(metadatas[i])

    return safe_texts, safe_metas or None, blocked
