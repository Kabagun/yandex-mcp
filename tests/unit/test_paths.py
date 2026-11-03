import pytest

from yandex_workspace_mcp.models.errors import InvalidPath
from yandex_workspace_mcp.policies import paths as path_policy

validate_path = path_policy.validate_path


def test_validate_path_normalization():
    assert validate_path("/Work", ["/"]) == "/Work"
    assert validate_path("Work", ["/"]) == "/Work"


def test_validate_path_traversal():
    with pytest.raises(InvalidPath):
        # /Work/../../Personal -> /Personal, which is not in /Work
        validate_path("/Work/../../Personal", ["/Work"])


def test_validate_path_allowed_roots():
    roots = ["/Work", "/Research"]
    assert validate_path("/Work/report.md", roots) == "/Work/report.md"
    assert validate_path("/Research", roots) == "/Research"

    with pytest.raises(InvalidPath):
        validate_path("/Personal/photo.jpg", roots)

    with pytest.raises(InvalidPath):
        validate_path("/", roots)


def test_validate_path_no_allowed_roots():
    with pytest.raises(InvalidPath):
        validate_path("/Work", [])


@pytest.mark.parametrize(
    "path",
    [
        "/Work/%252e%252e/Personal",
        "/Work/%2e%2e/Work",
        "/Work/a%2Fb",
        "/Work/a%5Cb",
        "/Work/a%00b",
        "/Work/a%0ab",
        "/Work/a%7Fb",
        "/Work/a%2541",
        "/Work/a%25",
        "/Work/%ZZ/file",
        "/Work/evil\\file",
        "/Work/evil\x00file",
        "/Work/evil\nfile",
        "/Work／evil",
    ],
)
def test_validate_path_rejects_ambiguous_or_encoded_paths(path: str) -> None:
    with pytest.raises(InvalidPath, match="Invalid or unauthorized path"):
        validate_path(path, ["/Work"])


def test_validate_path_uses_segment_boundaries() -> None:
    with pytest.raises(InvalidPath):
        validate_path("/Workshop/report.md", ["/Work"])


def test_validate_wiki_slug_returns_slug_without_leading_slash() -> None:
    assert path_policy.validate_wiki_slug("/Team/Page", ["Team"]) == "Team/Page"


@pytest.mark.parametrize(
    "path",
    ["/%2e%2e/Personal", "/Personal%2F..%2FWork", "/a%2541", "/a%25", "/a%7Fb"],
)
def test_encoded_structure_is_rejected_even_when_the_whole_disk_is_allowed(path: str) -> None:
    with pytest.raises(InvalidPath):
        validate_path(path, ["/"])


@pytest.mark.parametrize(
    "path,expected",
    [
        ("Work", "/Work"),
        ("disk:/Work/", "/Work"),
        ("/Work/./sub/../file.txt", "/Work/file.txt"),
        ("/Work/a%20b.txt", "/Work/a b.txt"),
        ("/Work/%D0%9E%D1%82%D1%87%D1%91%D1%82.md", "/Work/Отчёт.md"),
        ("/Work/Отчёт 2026.md", "/Work/Отчёт 2026.md"),
        ("disk:disk:/Work", "/disk:/Work"),
    ],
)
def test_safe_names_remain_compatible_and_normalization_is_idempotent(
    path: str, expected: str
) -> None:
    normalized = validate_path(path, ["/"])
    assert normalized == expected
    assert path_policy.normalize_path(normalized) == normalized
