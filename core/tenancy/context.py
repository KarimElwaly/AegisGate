from contextvars import ContextVar

current_tenant_id: ContextVar[str] = ContextVar("current_tenant_id", default="default")
current_workspace_id: ContextVar[str] = ContextVar("current_workspace_id", default="default")
current_virtual_key_id: ContextVar[str | None] = ContextVar("current_virtual_key_id", default=None)

