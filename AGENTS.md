# AegisGate Workspace Rules
- Always read `MASTER_PROMPT.md` and `PROGRESS.md` (if present) before planning or writing code.
- Never place domain-specific logic (SOC, SIEM, Log Analysis, Fleet, Finance) inside `core/`.
- Never import from `plugins/` or `policy_packs/` inside `core/pipeline/`; always resolve through `PluginRegistry`.
- Every plugin must expose a Pydantic `ConfigSchema`.
- Never use SQLAlchemy `create_all()` in production paths; use Alembic migrations.
- Execute strictly ONE phase per session. Do not start the next phase until all tests and DoD benchmarks pass and I confirm.
- At the end of each phase, update `PROGRESS.md` with created files, test coverage, and latency benchmark results.
- Execute phases sequentially, verifying all tests and committing to git after each phase before continuing.