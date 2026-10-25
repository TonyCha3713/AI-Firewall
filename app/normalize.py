"""Text normalization: run before every detector so obfuscation doesn't slip past."""

import base64
import binascii
import re
import unicodedata

# Zero-width chars, BOM, and the Unicode "tag" block (used for invisible ASCII smuggling).
_INVISIBLE = re.compile(r"[​-‏⁠-⁤﻿\U000E0000-\U000E007F]")
_SPACES = re.compile(r"[^\S\n]+")  # whitespace except newlines
_NEWLINES = re.compile(r"\s*\n\s*")
# Candidate base64 blobs: 24+ chars of the base64 alphabet.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

# Common leetspeak substitutions (applied to a separate variant, not the canonical text).
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

MAX_DECODED_BLOBS = 5
MAX_BLOB_LEN = 4096


def has_invisible_chars(text: str) -> bool:
    return bool(_INVISIBLE.search(text))


def canonicalize(text: str) -> str:
    """NFKC (folds fullwidth/ligatures), strip invisibles, lowercase, collapse whitespace.

    Newlines are kept (collapsed to one) so line-anchored structural rules still work.
    """
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = text.lower()
    text = _SPACES.sub(" ", text)
    return _NEWLINES.sub("\n", text).strip()


def _decode_base64_blobs(text: str) -> list[str]:
    decoded = []
    for match in _B64_BLOB.findall(text)[:MAX_DECODED_BLOBS]:
        blob = match[:MAX_BLOB_LEN]
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Keep only decodes that look like readable text.
        printable = sum(c.isprintable() or c.isspace() for c in candidate)
        if candidate and printable / len(candidate) > 0.9:
            decoded.append(canonicalize(candidate))
    return decoded


def variants(text: str) -> list[str]:
    """Canonical text plus decoded/de-leeted variants. Every detector scans all of them."""
    canonical = canonicalize(text)
    out = [canonical]
    deleet = canonical.translate(_LEET)
    if deleet != canonical:
        out.append(deleet)
    out.extend(_decode_base64_blobs(unicodedata.normalize("NFKC", text)))
    return out
