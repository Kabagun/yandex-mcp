import pytest

from yandex_workspace_mcp.clients.disk import validate_yandex_signed_url
from yandex_workspace_mcp.models.errors import APIError


def test_ssrf_valid_urls():
    valid_urls = [
        "https://yandex.net/download/...",
        "https://downloader.disk.yandex.net/file.txt",
        "https://a.b.c.yandex.net/file",
    ]
    for url in valid_urls:
        validate_yandex_signed_url(url)  # Should not raise


def test_ssrf_invalid_schemes():
    invalid_urls = [
        "http://downloader.disk.yandex.net/file",
        "ftp://yandex.net/file",
        "file:///etc/passwd",
    ]
    for url in invalid_urls:
        with pytest.raises(APIError, match="Signed URL must use HTTPS"):
            validate_yandex_signed_url(url)


def test_ssrf_evil_domains():
    invalid_urls = [
        "https://evil-yandex.net/file",
        "https://yandex.net.evil.com/file",
        "https://downloader.disk.yandex.net.evil.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://169.254.169.254",
    ]
    for url in invalid_urls:
        with pytest.raises(
            APIError,
            match="Invalid download URL domain returned by Yandex|resolves to private/local IP",
        ):
            validate_yandex_signed_url(url)
