import posixpath
import re
import unicodedata
import urllib.parse

from ..models.errors import InvalidPath

_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
# Decoding these bytes changes path segments or introduces another encoding layer.
_STRUCTURAL_BYTES = frozenset(b"%./\\")


def _reject_ambiguous_input(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise InvalidPath()
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise InvalidPath()
    if "\\" in path:
        raise InvalidPath()

    escapes = _PERCENT_ESCAPE.findall(path)
    if path.count("%") != len(escapes):
        raise InvalidPath()
    for escape in escapes:
        byte = int(escape[1:], 16)
        if byte in _STRUCTURAL_BYTES or byte < 32 or byte == 127:
            raise InvalidPath()

    try:
        decoded = urllib.parse.unquote(path, errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidPath() from exc

    if unicodedata.normalize("NFKC", decoded) != decoded:
        raise InvalidPath()
    return decoded


def normalize_path(path: str) -> str:
    """Return one canonical POSIX path or fail on ambiguous input."""

    decoded = _reject_ambiguous_input(path)
    if decoded.startswith("disk:"):
        decoded = decoded.removeprefix("disk:")
    clean_path = posixpath.normpath(decoded)
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path
    return clean_path


def _normalized_roots(allowed_roots: list[str]) -> tuple[str, ...]:
    roots: list[str] = []
    for root in allowed_roots:
        roots.append(normalize_path(root))
    return tuple(dict.fromkeys(roots))


def is_path_allowed(path: str, allowed_roots: list[str]) -> bool:
    norm_path = normalize_path(path)
    for norm_root in _normalized_roots(allowed_roots):
        if norm_root == "/":
            return True
        if norm_path == norm_root or norm_path.startswith(f"{norm_root}/"):
            return True
    return False


def validate_path(path: str, allowed_roots: list[str]) -> str:
    try:
        norm_path = normalize_path(path)
        allowed = is_path_allowed(norm_path, allowed_roots)
    except InvalidPath:
        raise
    except Exception as exc:
        raise InvalidPath() from exc
    if not allowed:
        raise InvalidPath()
    return norm_path


def validate_wiki_slug(slug: str, allowed_roots: list[str]) -> str:
    normalized = validate_path(
        "/" + slug.removeprefix("/") if not slug.startswith("/") else slug,
        allowed_roots,
    )
    return normalized.removeprefix("/")
