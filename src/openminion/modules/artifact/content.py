"""Content sniffing and bounded text extraction for artifact ingestion."""

import mimetypes
from pathlib import Path

_FALLBACK_MIME_BY_SUFFIX = {
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
}


def _determine_mime(provided: str | None, path: Path | None, sample: bytes) -> str:
    if provided:
        return provided
    if path is not None:
        guessed, _ = mimetypes.guess_type(str(path))
        if guessed:
            return guessed
        fallback = _FALLBACK_MIME_BY_SUFFIX.get(path.suffix.lower())
        if fallback:
            return fallback

    normalized_sample = sample
    if normalized_sample.startswith(b"\xef\xbb\xbf"):
        normalized_sample = normalized_sample[3:]
    normalized_sample = normalized_sample.lstrip()

    if normalized_sample.startswith(b"{") or normalized_sample.startswith(b"["):
        return "application/json"

    if not normalized_sample:
        return "application/octet-stream"

    if b"\x00" in normalized_sample:
        return "application/octet-stream"

    if _is_probably_text(normalized_sample):
        return "text/plain"

    return "application/octet-stream"


def _decode_text(data: bytes) -> tuple[str, list[str]]:
    if not data:
        return "", []

    if b"\x00" in data[:4096]:
        return "", ["binary_content"]

    try:
        return data.decode("utf-8"), []
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), ["decode_errors_replaced"]


def _detect_encoding(data: bytes) -> str | None:
    if not data:
        return None
    _text, warnings = _decode_text(data)
    if "binary_content" in warnings:
        return "binary"
    if "decode_errors_replaced" in warnings:
        return "utf-8-lossy"
    return "utf-8"


def _extract_ingest_text_from_bytes(data: bytes, *, max_chars: int = 20000) -> str:
    limit = max(0, int(max_chars))
    text, _warnings = _decode_text(data[: limit * 4 + 3])
    return text[:limit].strip()


def _is_probably_text(sample: bytes) -> bool:
    if not sample:
        return True
    printable = sum(b in {9, 10, 13} or 32 <= b <= 126 for b in sample)
    return printable / len(sample) >= 0.85
