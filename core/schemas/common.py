from enum import Enum


class StageEnum(str, Enum):
    LLM_INPUT = "llm_input"
    LLM_OUTPUT = "llm_output"
    TOOL_PRE_CALL = "tool_pre_call"
    TOOL_POST_CALL = "tool_post_call"
    AGENT_HANDOFF = "agent_handoff"
    MEMORY_WRITE = "memory_write"
    RAG_RETRIEVAL = "rag_retrieval"


class ActorTypeEnum(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"


class EnvironmentEnum(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class DecisionEnum(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MODIFY = "MODIFY"
    SUSPEND_FOR_APPROVAL = "SUSPEND_FOR_APPROVAL"
    ESCALATE = "ESCALATE"


class EffectiveModeEnum(str, Enum):
    ENFORCE = "enforce"
    SHADOW = "shadow"


class SeverityEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScannerStatusEnum(str, Enum):
    PASS = "pass"
    FLAG = "flag"
    BLOCK = "block"
    ERROR = "error"
