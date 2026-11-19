import ipaddress
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest


class ToolParamGuardConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    action_on_violation: str = "block"  # "block" | "flag"
    block_path_traversal: bool = True
    block_shell_metachars: bool = True
    enforce_sql_read_only: bool = False
    denied_cidrs: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    protected_ips_or_cidrs: list[str] = Field(default_factory=list)
    param_regex_rules: dict[str, str] = Field(default_factory=dict)


class ToolParamGuard(BaseScanner):
    name = "tool_param_guard"
    version = "1.0.0"
    tier = 1
    supported_stages = ["tool_pre_call"]
    config_schema = ToolParamGuardConfig

    PATH_TRAVERSAL_REGEX = re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|[a-zA-Z]:\\windows)", re.IGNORECASE)
    SHELL_METACHARS_REGEX = re.compile(r"[;&|`$><]")
    SQL_MUTATING_KEYWORDS = re.compile(
        r"(?i)\b(DROP|TRUNCATE|DELETE|INSERT|UPDATE|ALTER|GRANT|REVOKE|EXEC|EXECUTE)\b"
    )
    IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")

    def _check_ip_against_networks(self, ip_str: str, cidr_list: list[str]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for cidr in cidr_list:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in net:
                    return True
        except ValueError:
            pass
        return False

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, ToolParamGuardConfig) else ToolParamGuardConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        params = request.action.parameters or {}
        violations: list[dict[str, Any]] = []

        def inspect_value(param_key: str, val: Any) -> None:
            if isinstance(val, dict):
                for k, v in val.items():
                    inspect_value(f"{param_key}.{k}", v)
                return
            if isinstance(val, list):
                for idx, v in enumerate(val):
                    inspect_value(f"{param_key}[{idx}]", v)
                return

            str_val = str(val)

            # 1. Path traversal check
            if cfg.block_path_traversal and self.PATH_TRAVERSAL_REGEX.search(str_val):
                violations.append({
                    "param": param_key,
                    "type": "path_traversal",
                    "value": str_val[:50],
                    "reason": "Path traversal attempt detected",
                })

            # 2. Shell metacharacters check
            if cfg.block_shell_metachars and self.SHELL_METACHARS_REGEX.search(str_val):
                violations.append({
                    "param": param_key,
                    "type": "shell_metachars",
                    "value": str_val[:50],
                    "reason": "Dangerous shell metacharacters detected",
                })

            # 3. SQL read-only check
            if cfg.enforce_sql_read_only and self.SQL_MUTATING_KEYWORDS.search(str_val):
                violations.append({
                    "param": param_key,
                    "type": "sql_mutation",
                    "value": str_val[:50],
                    "reason": "Mutating SQL command detected when read-only enforced",
                })

            # 4. CIDR & IP checks
            ip_matches = self.IP_REGEX.findall(str_val)
            for ip in ip_matches:
                # Protected CIDRs (e.g. Domain Controller / internal VIP)
                if cfg.protected_ips_or_cidrs and self._check_ip_against_networks(ip, cfg.protected_ips_or_cidrs):
                    violations.append({
                        "param": param_key,
                        "type": "protected_ip_target",
                        "value": ip,
                        "reason": f"Target IP {ip} belongs to a protected infrastructure range",
                    })

                # Denied CIDRs
                if cfg.denied_cidrs and self._check_ip_against_networks(ip, cfg.denied_cidrs):
                    violations.append({
                        "param": param_key,
                        "type": "denied_cidr",
                        "value": ip,
                        "reason": f"Target IP {ip} falls inside a denied CIDR block",
                    })

                # Allowed CIDRs (if specified, IP MUST match one)
                if cfg.allowed_cidrs and not self._check_ip_against_networks(ip, cfg.allowed_cidrs):
                    violations.append({
                        "param": param_key,
                        "type": "not_in_allowed_cidr",
                        "value": ip,
                        "reason": f"Target IP {ip} is not inside allowed CIDR blocks",
                    })

            # 5. Parameter Regex Rules
            if param_key in cfg.param_regex_rules:
                pattern = cfg.param_regex_rules[param_key]
                if not re.match(pattern, str_val):
                    violations.append({
                        "param": param_key,
                        "type": "param_regex_mismatch",
                        "value": str_val[:50],
                        "reason": f"Parameter '{param_key}' does not match required format",
                    })

        for p_key, p_val in params.items():
            inspect_value(p_key, p_val)

        if not violations:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        status = cfg.action_on_violation
        first_reason = violations[0]["reason"]
        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status=status,
            score=1.0 if status == "block" else 0.5,
            details={"violations_count": len(violations), "violations": violations},
            message=f"Tool Parameter Guard detected {len(violations)} violation(s): {first_reason}",
        )
