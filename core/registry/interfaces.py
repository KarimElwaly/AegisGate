from abc import ABC, abstractmethod
from typing import Any, Optional, Type
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
    message: Optional[str] = None
    mutated_content: Optional[Any] = None
    mutated_parameters: Optional[dict[str, Any]] = None
    redaction_map: Optional[dict[str, str]] = None


class BaseScanner(ABC):
    name: str = "base_scanner"
    version: str = "1.0.0"
    tier: int = 1  # 1 | 2 | 3
    supported_stages: list[str] = []
    config_schema: Type[BaseModel] = DefaultPluginConfig

    @abstractmethod
    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        """Execute scan logic and return standardized ScannerResult."""
        pass


class BaseContextResolver(ABC):
    name: str = "base_resolver"
    version: str = "1.0.0"
    config_schema: Type[BaseModel] = DefaultPluginConfig

    @abstractmethod
    async def resolve(
        self,
        request: EvaluationRequest,
        config: BaseModel,
    ) -> dict[str, Any]:
        """Resolve external context and return key-value dictionary."""
        pass


class BaseNotifier(ABC):
    name: str = "base_notifier"
    version: str = "1.0.0"
    config_schema: Type[BaseModel] = DefaultPluginConfig

    @abstractmethod
    async def notify(
        self,
        event_type: str,
        payload: dict[str, Any],
        config: BaseModel,
    ) -> bool:
        """Send notification to external system."""
        pass
