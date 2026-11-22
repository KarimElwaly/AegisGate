import re
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.sql_ast_guard")

try:
    import sqlglot
    from sqlglot import exp
    HAS_SQLGLOT = True
except ImportError:
    HAS_SQLGLOT = False


class SqlAstGuardConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    allowed_statement_types: list[str] = Field(default_factory=lambda: ["SELECT"])
    blocked_statement_types: list[str] = Field(
        default_factory=lambda: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT", "REVOKE"]
    )
    allowed_tables: list[str] = Field(default_factory=list)
    denied_tables: list[str] = Field(
        default_factory=lambda: ["pg_shadow", "pg_authid", "users_credentials", "system_secrets"]
    )
    denied_columns: list[str] = Field(
        default_factory=lambda: ["password", "password_hash", "secret_key", "auth_token", "ssn"]
    )
    enforce_limit: bool = True
    max_limit: int = 100
    auto_inject_limit: bool = True
    enforce_tenant_predicate: bool = False
    tenant_column: str = "tenant_id"
    auto_inject_tenant_predicate: bool = False
    sql_parameter_names: list[str] = Field(default_factory=lambda: ["query", "sql", "sql_query", "statement"])


class SqlAstGuard(BaseScanner):
    """Tier-1 Deterministic SQL AST & Syntax Governance Scanner.
    Validates SQL queries inside tool parameters (tool_pre_call) and LLM outputs (llm_output),
    blocking destructive statements, schema inspection, forbidden tables/columns,
    and enforcing limits and multi-tenant isolation predicates.
    """

    name = "sql_ast_guard"
    version = "1.0.0"
    tier = 1
    supported_stages = ["tool_pre_call", "llm_output"]
    config_schema = SqlAstGuardConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, SqlAstGuardConfig) else SqlAstGuardConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # 1. Extract target SQL text from request
        target_sql: str | None = None
        sql_param_key: str | None = None

        if request.action and request.action.parameters:
            params = request.action.parameters
            for key in cfg.sql_parameter_names:
                if key in params and isinstance(params[key], str) and params[key].strip():
                    target_sql = params[key].strip()
                    sql_param_key = key
                    break

        if not target_sql and request.content:
            if request.content.output_payload and isinstance(request.content.output_payload, str):
                extracted = self._extract_sql_from_markdown(request.content.output_payload)
                if extracted:
                    target_sql = extracted

        if not target_sql:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # 2. Parse and analyze SQL
        violations: list[str] = []
        mutated_sql: str | None = None

        if HAS_SQLGLOT:
            violations, mutated_sql = self._analyze_with_sqlglot(target_sql, cfg, request.tenant_id)
        else:
            violations, mutated_sql = self._analyze_with_fallback(target_sql, cfg, request.tenant_id)

        if violations:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status="block",
                score=1.0,
                details={
                    "violations": violations,
                    "target_sql": target_sql[:200],
                },
                message=f"SQL Governance violation: {'; '.join(violations)}",
            )

        if mutated_sql and mutated_sql != target_sql:
            mutated_params = None
            mutated_content = None
            if sql_param_key and request.action and request.action.parameters:
                mutated_params = dict(request.action.parameters)
                mutated_params[sql_param_key] = mutated_sql
            elif request.content and request.content.output_payload:
                mutated_content = {"output_payload": mutated_sql}

            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status="modify",
                score=0.2,
                mutated_parameters=mutated_params,
                mutated_content=mutated_content,
                details={"mutated_sql": mutated_sql},
                message="SQL query modified by SqlAstGuard governance rules",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

    def _extract_sql_from_markdown(self, text: str) -> str | None:
        match = re.search(r"```(?:sql)?\s*([\s\S]*?)```", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        trimmed = text.strip()
        if re.match(r"(?i)^(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE)\b", trimmed):
            return trimmed
        return None

    def _analyze_with_sqlglot(
        self, sql: str, cfg: SqlAstGuardConfig, tenant_id: str
    ) -> tuple[list[str], str | None]:
        violations: list[str] = []
        try:
            expression = sqlglot.parse_one(sql)
        except Exception as e:
            return [f"SQL syntax parse error: {e!s}"], None

        stmt_type = expression.key.upper()
        allowed = [s.upper() for s in cfg.allowed_statement_types]
        blocked = [s.upper() for s in cfg.blocked_statement_types]

        if blocked and stmt_type in blocked:
            violations.append(f"Blocked SQL statement type: {stmt_type}")
        if allowed and stmt_type not in allowed:
            violations.append(f"Statement type '{stmt_type}' not in allowed list: {allowed}")

        # Check tables
        tables = [t.name.lower() for t in expression.find_all(exp.Table)]
        for t in tables:
            if cfg.denied_tables and t in [dt.lower() for dt in cfg.denied_tables]:
                violations.append(f"Access to denied table: '{t}'")
            if cfg.allowed_tables and t not in [at.lower() for at in cfg.allowed_tables]:
                violations.append(f"Table '{t}' not in allowed tables list")

        # Check columns
        columns = [c.name.lower() for c in expression.find_all(exp.Column)]
        for c in columns:
            if cfg.denied_columns and c in [dc.lower() for dc in cfg.denied_columns]:
                violations.append(f"Access to denied column: '{c}'")

        if violations:
            return violations, None

        # Handle LIMIT
        mutated = False
        if stmt_type == "SELECT" and cfg.enforce_limit:
            limit_node = expression.args.get("limit")
            if limit_node is None:
                if cfg.auto_inject_limit:
                    expression = expression.limit(cfg.max_limit)
                    mutated = True
                else:
                    violations.append(f"Query missing required LIMIT clause (max allowed: {cfg.max_limit})")
            else:
                try:
                    val = int(limit_node.expression.this)
                    if val > cfg.max_limit:
                        if cfg.auto_inject_limit:
                            expression.set("limit", exp.Limit(this=exp.Literal.number(cfg.max_limit)))
                            mutated = True
                        else:
                            violations.append(f"LIMIT {val} exceeds maximum allowed limit {cfg.max_limit}")
                except Exception:
                    pass

        # Handle Tenant Predicate
        if stmt_type == "SELECT" and cfg.enforce_tenant_predicate:
            has_tenant_filter = False
            for eq in expression.find_all(exp.EQ):
                if eq.left and getattr(eq.left, "name", "").lower() == cfg.tenant_column.lower():
                    has_tenant_filter = True
                    break
            if not has_tenant_filter:
                if cfg.auto_inject_tenant_predicate and tenant_id:
                    expression = expression.where(f"{cfg.tenant_column} = '{tenant_id}'")
                    mutated = True
                else:
                    violations.append(f"Query missing mandatory tenant predicate: '{cfg.tenant_column} = ...'")

        return violations, expression.sql() if mutated else sql

    def _analyze_with_fallback(
        self, sql: str, cfg: SqlAstGuardConfig, tenant_id: str
    ) -> tuple[list[str], str | None]:
        violations: list[str] = []
        normalized = sql.strip()

        # 1. Statement Type
        first_word_match = re.match(r"^([A-Za-z]+)\b", normalized)
        stmt_type = first_word_match.group(1).upper() if first_word_match else "UNKNOWN"

        allowed = [s.upper() for s in cfg.allowed_statement_types]
        blocked = [s.upper() for s in cfg.blocked_statement_types]

        if blocked and stmt_type in blocked:
            violations.append(f"Blocked SQL statement type: {stmt_type}")
        if allowed and stmt_type not in allowed:
            violations.append(f"Statement type '{stmt_type}' not in allowed list: {allowed}")

        # Check for UNION exfiltration
        if re.search(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b", normalized):
            if "UNION" in blocked:
                violations.append("Blocked SQL statement: UNION query detected")

        # Check for multiple stacked queries
        if ";" in normalized.rstrip(";"):
            violations.append("Multiple stacked SQL statements detected")

        # 2. Denied tables
        for dt in cfg.denied_tables:
            if re.search(rf"(?i)\b(?:FROM|JOIN|INTO|UPDATE)\s+[\"`]?{re.escape(dt)}[\"`]?\b", normalized):
                violations.append(f"Access to denied table: '{dt}'")

        # 3. Denied columns
        for dc in cfg.denied_columns:
            if re.search(rf"(?i)\b[\"`]?{re.escape(dc)}[\"`]?\b", normalized):
                violations.append(f"Access to denied column: '{dc}'")

        if violations:
            return violations, None

        mutated_sql = normalized
        mutated = False

        # 4. Enforce Limit
        if stmt_type == "SELECT" and cfg.enforce_limit:
            limit_match = re.search(r"(?i)\bLIMIT\s+(\d+)\b", normalized)
            if not limit_match:
                if cfg.auto_inject_limit:
                    clean_sql = normalized.rstrip(";")
                    mutated_sql = f"{clean_sql} LIMIT {cfg.max_limit};"
                    mutated = True
                else:
                    violations.append(f"Query missing required LIMIT clause (max allowed: {cfg.max_limit})")
            else:
                val = int(limit_match.group(1))
                if val > cfg.max_limit:
                    if cfg.auto_inject_limit:
                        mutated_sql = re.sub(
                            r"(?i)\bLIMIT\s+\d+\b",
                            f"LIMIT {cfg.max_limit}",
                            normalized,
                        )
                        mutated = True
                    else:
                        violations.append(f"LIMIT {val} exceeds maximum allowed limit {cfg.max_limit}")

        # 5. Enforce Tenant Predicate
        if stmt_type == "SELECT" and cfg.enforce_tenant_predicate:
            tenant_regex = rf"(?i)\b{re.escape(cfg.tenant_column)}\s*=\s*['\"]?{re.escape(tenant_id)}['\"]?"
            if not re.search(tenant_regex, normalized):
                if cfg.auto_inject_tenant_predicate and tenant_id:
                    clean = mutated_sql.rstrip(";").rstrip()
                    if re.search(r"(?i)\bWHERE\b", clean):
                        # Inject AND tenant_id = ...
                        mutated_sql = re.sub(
                            r"(?i)\bWHERE\b",
                            f"WHERE {cfg.tenant_column} = '{tenant_id}' AND",
                            clean,
                            count=1,
                        ) + ";"
                    else:
                        # Append WHERE before ORDER BY / LIMIT
                        parts = re.split(r"(?i)\b(ORDER\s+BY|LIMIT|GROUP\s+BY)\b", clean, maxsplit=1)
                        if len(parts) > 1:
                            mutated_sql = f"{parts[0].strip()} WHERE {cfg.tenant_column} = '{tenant_id}' {parts[1]} {parts[2].strip()};"
                        else:
                            mutated_sql = f"{clean} WHERE {cfg.tenant_column} = '{tenant_id}';"
                    mutated = True
                else:
                    violations.append(f"Query missing mandatory tenant predicate: '{cfg.tenant_column} = {tenant_id}'")

        return violations, mutated_sql if mutated else sql

