import uuid
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from core.schemas.common import ActorTypeEnum, StageEnum


class ActorModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    type: ActorTypeEnum | str = ActorTypeEnum.AGENT
    role: str = "default"
    delegation_chain: list[str] = Field(default_factory=list)


class ActionModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = "default_action"
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    estimated_tokens: int = 0
    estimated_cost_usd: float = 0.0


class ContentModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    trusted_instructions: Optional[str] = None
    untrusted_data: Any = None
    output_payload: Any = None
    citations: list[str] = Field(default_factory=list)


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    workspace_id: str = "default"
    environment: str = "dev"
    policy_pack_id: str = "base-enterprise"
    policy_pack_version: str = "latest"
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    span_id: Optional[str] = None
    session_id: Optional[str] = None
    stage: StageEnum = StageEnum.LLM_INPUT
    actor: ActorModel = Field(default_factory=lambda: ActorModel(id="default_actor"))
    action: ActionModel = Field(default_factory=ActionModel)
    content: ContentModel = Field(default_factory=ContentModel)
    execution_mode_override: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
