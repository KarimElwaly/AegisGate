from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.schemas.events import EvaluationRequest


class DefaultPluginConfig(BaseModel):
    model_config = ConfigDict(extra="allow")


class ScannerResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    scanner_name: str
    tier: int
    status: str = "pass"  # pass | flag | block | error
    score: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None
    mutated_content: Any | None = None
    mutated_parameters: dict[str, Any] | None = None
    redaction_map: dict[str, str] | None = None


class BaseScanner(ABC):
    name: str = "base_scanner"
    version: str = "1.0.0"
    tier: int = 1  # 1 | 2 | 3
    supported_stages: list[str] = []
    config_schema: type[BaseModel] = DefaultPluginConfig

    @abstractmethod
    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        """Execute scan logic and return standardized ScannerResult."""


class BaseContextResolver(ABC):
    name: str = "base_resolver"
    version: str = "1.0.0"
    config_schema: type[BaseModel] = DefaultPluginConfig

    @abstractmethod
    async def resolve(
        self,
        request: EvaluationRequest,
        config: BaseModel,
    ) -> dict[str, Any]:
        """Resolve external context and return key-value dictionary."""


class BaseNotifier(ABC):
    name: str = "base_notifier"
    version: str = "1.0.0"
    config_schema: type[BaseModel] = DefaultPluginConfig

    @abstractmethod
    async def notify(
        self,
        event_type: str,
        payload: dict[str, Any],
        config: BaseModel,
    ) -> bool:
        """Send notification to external system."""
