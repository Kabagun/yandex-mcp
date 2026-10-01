"""Fetch the identity of the request's existing authorized Yandex account."""

import hashlib
import hmac
from typing import Any

import httpx

from ..auth.credentials import StoredCredentialProvider
from ..auth.models import Principal
from ..models.errors import AuthenticationError
from ..models.profile import AccountProfile


def _subject(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= 256)
        or value != value.strip()
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        return None
    return value


def _display(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    return value.strip()


def _email(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or not (3 <= len(value) <= 254)
        or value.count("@") != 1
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        return None
    local, domain = value.split("@")
    return value if local and domain else None


class ProfileService:
    def __init__(self, credentials: StoredCredentialProvider, client: httpx.AsyncClient) -> None:
        self._credentials = credentials
        self._client = client

    async def get_profile(self, principal: Principal) -> AccountProfile:
        """Return current profile metadata only after validating the stored account subject."""
        if not principal.client_id:
            raise AuthenticationError()
        record = await self._credentials.resolve_record(principal)
        expected_subject = _subject(record.yandex_subject)
        if record.principal_id != principal.principal_id or expected_subject is None:
            raise AuthenticationError()
        try:
            response = await self._client.get(
                "https://login.yandex.ru/info",
                params={"format": "json"},
                headers={
                    "Accept": "application/json",
                    "Authorization": f"OAuth {record.access_token}",
                },
            )
            response.raise_for_status()
            account = response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            raise AuthenticationError() from None
        if not isinstance(account, dict):
            raise AuthenticationError()
        subject = _subject(account.get("id"))
        if subject is None or not hmac.compare_digest(
            subject.encode("utf-8"), expected_subject.encode("utf-8")
        ):
            raise AuthenticationError()

        # The Yandex ID namespace deliberately excludes MCP client IDs, issuer URLs,
        # tokens and display metadata: reconnecting cannot change the account ID.
        identifier = hashlib.sha256(f"yandex-account-profile:v1\0{subject}".encode()).hexdigest()
        email = _email(account.get("default_email"))
        login = _display(account.get("login"))
        return AccountProfile(
            id=f"yandex:{identifier}",
            name=(
                _display(account.get("display_name")) or _display(account.get("real_name")) or login
            ),
            email=email,
            nickname=email or login,
        )
