import json
from typing import Any

import jsonschema
from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest


class JsonSchemaScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    enabled: bool = True
    action_on_error: str = "block"  # "block" | "flag"
    target_field: str = "auto"  # "output_payload" | "parameters" | "auto"
    schema_definition: dict[str, Any] = Field(default_factory=dict, alias="expected_schema")


class JsonSchemaScanner(BaseScanner):
    name = "json_schema_scanner"
    version = "1.0.0"
    tier = 1
    supported_stages = ["llm_input", "llm_output", "tool_pre_call", "tool_post_call", "agent_handoff"]
    config_schema = JsonSchemaScannerConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, JsonSchemaScannerConfig) else JsonSchemaScannerConfig(**config.model_dump())
        active_schema = cfg.schema_definition or getattr(cfg, "expected_schema", {})
        if not active_schema and hasattr(cfg, "model_dump"):
            active_schema = cfg.model_dump().get("expected_schema", {}) or {}

        if not cfg.enabled or not active_schema:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        data_to_validate: Any = None

        if cfg.target_field == "parameters":
            data_to_validate = request.action.parameters
        elif cfg.target_field == "output_payload":
            data_to_validate = request.content.output_payload
        else:
            # Auto-detect target based on payload presence
            if request.content.output_payload is not None:
                data_to_validate = request.content.output_payload
            elif request.action.parameters:
                data_to_validate = request.action.parameters
            elif request.content.untrusted_data is not None:
                data_to_validate = request.content.untrusted_data

        # If data is string representation of json, parse it
        if isinstance(data_to_validate, str):
            try:
                data_to_validate = json.loads(data_to_validate)
            except Exception as e:
                return ScannerResult(
                    scanner_name=self.name,
                    tier=self.tier,
                    status=cfg.action_on_error,
                    score=1.0 if cfg.action_on_error == "block" else 0.5,
                    details={"error": "Payload is not valid JSON string", "raw_error": str(e)},
                    message="JSON Schema validation failed: invalid JSON string",
                )

        if data_to_validate is None:
            # Nothing to validate
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        try:
            jsonschema.validate(instance=data_to_validate, schema=active_schema)
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")
        except jsonschema.ValidationError as err:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_error,
                score=1.0 if cfg.action_on_error == "block" else 0.5,
                details={
                    "validation_error": err.message,
                    "path": list(err.path),
                    "schema_path": list(err.schema_path),
                },
                message=f"JSON Schema validation error: {err.message}",
            )
        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status="error",
                score=0.5,
                details={"error": str(e)},
                message=f"JSON Schema validator error: {e!s}",
            )
