from enum import StrEnum

from mcp.server.auth.middleware.auth_context import get_access_token

from ..models.errors import PermissionDenied
from .models import Principal, WorkspaceScope


class OperationClass(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


WorkspacePrincipal = Principal


_IMPLIED_SCOPES: dict[WorkspaceScope, frozenset[WorkspaceScope]] = {
    WorkspaceScope.READ: frozenset({WorkspaceScope.READ}),
    WorkspaceScope.WRITE: frozenset({WorkspaceScope.READ, WorkspaceScope.WRITE}),
    WorkspaceScope.DELETE: frozenset(
        {WorkspaceScope.READ, WorkspaceScope.WRITE, WorkspaceScope.DELETE}
    ),
    WorkspaceScope.MAIL_READ: frozenset({WorkspaceScope.MAIL_READ}),
    WorkspaceScope.MAIL_WRITE: frozenset({WorkspaceScope.MAIL_READ, WorkspaceScope.MAIL_WRITE}),
    WorkspaceScope.MAIL_DELETE: frozenset(
        {WorkspaceScope.MAIL_READ, WorkspaceScope.MAIL_WRITE, WorkspaceScope.MAIL_DELETE}
    ),
}


def scopes_for_permissions(
    *, can_read: bool, can_write: bool, can_delete: bool, service: str = "workspace"
) -> frozenset[WorkspaceScope]:
    """Expand operation permissions within one service, never across profiles."""
    read, write, delete = (
        (WorkspaceScope.MAIL_READ, WorkspaceScope.MAIL_WRITE, WorkspaceScope.MAIL_DELETE)
        if service == "mail"
        else (WorkspaceScope.READ, WorkspaceScope.WRITE, WorkspaceScope.DELETE)
    )
    scopes: set[WorkspaceScope] = set()
    if can_read:
        scopes.update(_IMPLIED_SCOPES[read])
    if can_write:
        scopes.update(_IMPLIED_SCOPES[write])
    if can_delete:
        scopes.update(_IMPLIED_SCOPES[delete])
    return frozenset(scopes)


def effective_static_scopes(
    requested: list[str] | tuple[str, ...],
    permission_ceiling: frozenset[WorkspaceScope],
) -> frozenset[WorkspaceScope]:
    if not requested:
        return permission_ceiling
    expanded: set[WorkspaceScope] = set()
    for raw in requested:
        try:
            expanded.update(_IMPLIED_SCOPES[WorkspaceScope(raw)])
        except ValueError:
            continue
    return frozenset(expanded.intersection(permission_ceiling))


def expand_scope_values(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    expanded: set[WorkspaceScope] = set()
    for raw in values:
        try:
            expanded.update(_IMPLIED_SCOPES[WorkspaceScope(raw)])
        except ValueError:
            continue
    return tuple(scope.value for scope in WorkspaceScope if scope in expanded)


def current_principal(
    local_principal: WorkspacePrincipal, *, require_authenticated: bool = False
) -> WorkspacePrincipal:
    access_token = get_access_token()
    if access_token is None:
        if require_authenticated:
            return WorkspacePrincipal(principal_id="unauthenticated", scopes=frozenset())
        return local_principal
    scopes = frozenset(
        WorkspaceScope(value)
        for value in access_token.scopes
        if value in WorkspaceScope._value2member_map_
    )
    principal_id = access_token.subject or access_token.client_id
    return WorkspacePrincipal(
        principal_id=principal_id,
        scopes=scopes,
        client_id=access_token.client_id,
    )


def require_scope(
    principal: WorkspacePrincipal, operation: OperationClass, *, service: str = "workspace"
) -> None:
    """Require an exact operation scope belonging to the requested service."""
    required = WorkspaceScope(f"{service}:{operation.value}")
    if required not in principal.scopes:
        raise PermissionDenied()
