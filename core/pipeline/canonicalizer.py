import base64
import binascii
import copy
import re
import unicodedata
import urllib.parse
from typing import Any

from core.schemas.events import EvaluationRequest

# Invisible, formatting, and zero-width characters to strip
ZERO_WIDTH_REGEX = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD\u2000-\u200A]"
)

# Potential base64 segments (at least 8 chars, base64 alphabet, proper padding)
BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")

# Common visual confusable homoglyphs (Cyrillic and Greek lookalikes to Latin)
HOMOGLYPH_MAP = str.maketrans({
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u0456': 'i', '\u0458': 'j',
    '\u043e': 'o', '\u0440': 'p', '\u0455': 's', '\u0445': 'x', '\u0443': 'y',
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E', '\u041d': 'H',
    '\u0406': 'I', '\u0408': 'J', '\u041a': 'K', '\u041c': 'M', '\u041e': 'O',
    '\u0420': 'P', '\u0422': 'T', '\u0425': 'X', '\u0405': 'S',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I',
    '\u039a': 'K', '\u039c': 'M', '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P',
    '\u03a4': 'T', '\u03a7': 'X', '\u03bf': 'o',
})

# Potential hex sequences: \x41\x42 or 0x410x42 or standalone hex strings of length >= 8
HEX_PREFIX_PATTERN = re.compile(r"(?:\\x|0x)([0-9a-fA-F]{2})")
STANDALONE_HEX_PATTERN = re.compile(r"\b([0-9a-fA-F]{8,})\b")

MAX_DECODE_DEPTH = 2
MAX_DECODED_BYTES = 65536


def strip_invisible_characters(text: str) -> str:
    """Strips zero-width, formatting, and invisible Unicode control characters."""
    if not text:
        return ""
    return ZERO_WIDTH_REGEX.sub("", text)


def normalize_homoglyphs(text: str) -> str:
    """Normalizes visually confusable Unicode characters to standard ASCII/Latin via NFKC and homoglyph mapping."""
    if not text:
        return ""
    # 1. NFKC compatibility normalization (full-width, math, ligatures)
    nfkc_norm = unicodedata.normalize("NFKC", text)
    # 2. Cross-script confusable translation
    return nfkc_norm.translate(HOMOGLYPH_MAP)


def _safe_decode_base64(candidate: str) -> str | None:
    try:
        # Avoid decoding trivial numbers or short strings
        if len(candidate) < 8 or len(candidate) % 4 != 0:
            return None
        decoded_bytes = base64.b64decode(candidate, validate=True)
        if len(decoded_bytes) > MAX_DECODED_BYTES:
            return None
        # Check if printable UTF-8
        decoded_str = decoded_bytes.decode("utf-8")
        # Check if mostly printable characters
        printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded_str) / len(decoded_str)
        if printable_ratio >= 0.85 and len(decoded_str.strip()) >= 3:
            return decoded_str
    except Exception:
        pass
    return None


def _safe_decode_hex(candidate: str) -> str | None:
    try:
        if len(candidate) < 8 or len(candidate) % 2 != 0:
            return None
        decoded_bytes = binascii.unhexlify(candidate)
        if len(decoded_bytes) > MAX_DECODED_BYTES:
            return None
        decoded_str = decoded_bytes.decode("utf-8")
        printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded_str) / len(decoded_str)
        if printable_ratio >= 0.85 and len(decoded_str.strip()) >= 3:
            return decoded_str
    except Exception:
        pass
    return None


def extract_decoded_layers(text: str, depth: int = 1) -> list[str]:
    """Finds and decodes URL-encoded, Hex, and Base64 segments within text up to max depth."""
    if depth > MAX_DECODE_DEPTH or not text:
        return []

    decoded_layers: list[str] = []

    # 1. URL decoding
    try:
        if "%" in text:
            url_decoded = urllib.parse.unquote(text)
            if url_decoded != text:
                decoded_layers.append(url_decoded)
                decoded_layers.extend(extract_decoded_layers(url_decoded, depth=depth + 1))
    except Exception:
        pass

    # 2. Hex prefix decoding (\x41\x42 or 0x410x42)
    try:
        hex_matches = HEX_PREFIX_PATTERN.findall(text)
        if hex_matches and len(hex_matches) >= 4:
            hex_str = "".join(hex_matches)
            decoded_hex = _safe_decode_hex(hex_str)
            if decoded_hex:
                decoded_layers.append(decoded_hex)
                decoded_layers.extend(extract_decoded_layers(decoded_hex, depth=depth + 1))
    except Exception:
        pass

    # 3. Standalone hex decoding
    try:
        for m in STANDALONE_HEX_PATTERN.finditer(text):
            candidate = m.group(1)
            decoded_hex = _safe_decode_hex(candidate)
            if decoded_hex and decoded_hex != candidate:
                decoded_layers.append(decoded_hex)
                decoded_layers.extend(extract_decoded_layers(decoded_hex, depth=depth + 1))
    except Exception:
        pass

    # 4. Base64 decoding
    try:
        for m in BASE64_PATTERN.finditer(text):
            candidate = m.group(0)
            decoded_b64 = _safe_decode_base64(candidate)
            if decoded_b64 and decoded_b64 != candidate:
                decoded_layers.append(decoded_b64)
                decoded_layers.extend(extract_decoded_layers(decoded_b64, depth=depth + 1))
    except Exception:
        pass

    return decoded_layers


def canonicalize_text(text: str) -> str:
    """
    Applies full canonicalization and de-obfuscation:
    1. Strips zero-width and invisible control characters.
    2. Normalizes homoglyphs via NFKC.
    3. Unrolls hidden Base64/Hex/URL encoded segments into the inspection payload.
    """
    if not text:
        return ""

    cleaned = strip_invisible_characters(text)
    normalized = normalize_homoglyphs(cleaned)

    # Extract any obfuscated / encoded sub-payloads
    decoded_layers = extract_decoded_layers(normalized, depth=1)
    if decoded_layers:
        # Append decoded representations separated by newlines so scanners evaluate both
        normalized = normalized + "\n" + "\n".join(decoded_layers)

    return normalized


def _canonicalize_value(val: Any) -> Any:
    if isinstance(val, str):
        return canonicalize_text(val)
    if isinstance(val, dict):
        return {k: _canonicalize_value(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_canonicalize_value(item) for item in val]
    return val


def canonicalize_request(request: EvaluationRequest) -> EvaluationRequest:
    """
    Creates a deep-copied, canonicalized representation of EvaluationRequest
    for pre-scanner evaluation.
    Preserves original request for downstream proxy forwarding.
    """
    req_copy = copy.deepcopy(request)

    if req_copy.content:
        if req_copy.content.trusted_instructions:
            req_copy.content.trusted_instructions = canonicalize_text(req_copy.content.trusted_instructions)
        if req_copy.content.untrusted_data:
            req_copy.content.untrusted_data = _canonicalize_value(req_copy.content.untrusted_data)
        if req_copy.content.output_payload:
            req_copy.content.output_payload = _canonicalize_value(req_copy.content.output_payload)

    if req_copy.action and req_copy.action.parameters:
        req_copy.action.parameters = _canonicalize_value(req_copy.action.parameters)

    return req_copy
