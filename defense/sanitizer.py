"""
Defense Module: Text Sanitizer
===============================
Strips injection payloads from text before it enters the pipeline.
Used when you can't reject the document outright (e.g., large PDFs
where only part of the content is poisoned).
"""
import re


def strip_hidden_text_markers(text: str) -> str:
    """Remove common hidden-text injection markers."""
    # Strip zero-width characters (used to hide payloads)
    text = re.sub(r'[\u200b-\u200f\u202a-\u202e\ufeff]', '', text)
    # Strip content between injection marker tags
    text = re.sub(r'\[SYSTEM.*?END DIRECTIVE\]', '[REDACTED]', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<\|system\|>.*?<\|end\|>', '[REDACTED]', text, flags=re.DOTALL | re.IGNORECASE)
    return text


def normalize_whitespace(text: str) -> str:
    """Collapse runs of whitespace that might hide payloads between visible content."""
    text = re.sub(r'\n{4,}', '\n\n', text)  # Max 2 blank lines
    text = re.sub(r'[ \t]{10,}', ' ', text)  # Collapse long spaces
    return text.strip()


def redact_injection_sentences(text: str) -> str:
    """Replace sentences matching injection patterns with [REDACTED]."""
    from defense.scanner import COMPILED_PATTERNS
    sentences = re.split(r'(?<=[.!?])\s+', text)
    cleaned = []
    for sentence in sentences:
        if any(p.search(sentence) for p in COMPILED_PATTERNS):
            cleaned.append("[CONTENT REDACTED BY SECURITY FILTER]")
        else:
            cleaned.append(sentence)
    return " ".join(cleaned)


def sanitize(text: str, aggressive: bool = False) -> tuple[str, list[str]]:
    """
    Full sanitization pipeline.
    Returns (cleaned_text, list_of_actions_taken).
    """
    actions = []
    original_len = len(text)

    text = strip_hidden_text_markers(text)
    if len(text) < original_len:
        actions.append(f"Stripped {original_len - len(text)} hidden characters")

    text = normalize_whitespace(text)
    actions.append("Normalized whitespace")

    if aggressive:
        text = redact_injection_sentences(text)
        actions.append("Redacted injection-matching sentences")

    return text, actions
