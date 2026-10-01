"""Tokenless public HTTPS downloads for ChatGPT's temporary file capabilities."""

import ipaddress
import urllib.parse

import anyio
import httpx

from ..models.errors import InvalidInput, PermissionDenied, UpstreamTimeout, UpstreamUnavailable
from .signed import IPAddress, SignedTransferClient, _is_public


def validate_file_source_url(url: str) -> str:
    """Accept DNS hostnames on HTTPS/443 without userinfo, fragments or IP literals."""
    if not isinstance(url, str) or not url or any(c.isspace() or ord(c) < 32 for c in url):
        raise InvalidInput("File download URL must use public HTTPS.")
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme != "https"
            or not host
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "#" in url
            or "\\" in url
            or "%" in host
        ):
            raise ValueError
        try:
            ipaddress.ip_address(host.rstrip("."))
        except ValueError:
            pass
        else:
            raise ValueError
    except ValueError as exc:
        raise InvalidInput("File download URL must use public HTTPS.") from exc
    return url


class PublicFileTransferClient(SignedTransferClient):
    """Separate file-source policy using the same pinned, credential-free TLS machinery."""

    async def validate(self, url: str) -> tuple[str, set[IPAddress]]:
        """Resolve a public HTTPS source and refuse empty or mixed/private DNS answers."""
        validated = validate_file_source_url(url)
        host = urllib.parse.urlsplit(validated).hostname
        assert host is not None
        addresses = await self.resolver(host)
        if not addresses or any(not _is_public(address) for address in addresses):
            raise PermissionDenied("File download source must resolve only to public addresses.")
        return validated, addresses

    async def download(self, url: str, *, max_bytes: int) -> bytes:
        """Fetch once, preserving bytes, without redirects, credentials or HTTP decompression."""
        if max_bytes < 0:
            raise InvalidInput()
        try:
            validated, addresses = await self.validate(url)
            async with self._client_for(validated, addresses) as client:
                request = client.build_request(
                    "GET",
                    validated,
                    headers={"Accept": "application/octet-stream", "Accept-Encoding": "identity"},
                )
                self._strip_credentials(request)
                response = await client.send(
                    request, stream=True, auth=None, follow_redirects=False
                )
                try:
                    self._validate_peer(response, addresses)
                    if 300 <= response.status_code < 400:
                        raise PermissionDenied("File download redirects are not allowed.")
                    if response.status_code in {401, 403, 404, 410}:
                        raise InvalidInput(
                            "File download is unavailable or expired. Attach the file again."
                        )
                    if response.status_code != 200:
                        raise UpstreamUnavailable("File download source is unavailable.")
                    encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
                    if encoding != "identity":
                        raise InvalidInput("File download must use identity HTTP encoding.")
                    declared = response.headers.get("Content-Length")
                    if declared is not None:
                        if len(declared) > 20 or not declared.isascii() or not declared.isdecimal():
                            raise InvalidInput("File download has an invalid length.")
                        if int(declared) > max_bytes:
                            raise PermissionDenied("Upload exceeds the configured maximum size.")
                    content = bytearray()
                    async for chunk in response.aiter_raw(self.chunk_size):
                        if len(content) + len(chunk) > max_bytes:
                            raise PermissionDenied("Upload exceeds the configured maximum size.")
                        content.extend(chunk)
                    return bytes(content)
                finally:
                    with anyio.CancelScope(shield=True):
                        await response.aclose()
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout(
                "File download timed out. Attach the file again and retry."
            ) from exc
        except httpx.RequestError as exc:
            raise UpstreamUnavailable("File download source is unavailable.") from exc
        except UpstreamUnavailable as exc:
            raise UpstreamUnavailable("File download source is unavailable.") from exc
