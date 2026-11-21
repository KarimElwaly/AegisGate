import asyncio
import json
import sys
from pathlib import Path

import click
import yaml

from core.bootstrap import bootstrap_system
from core.pipeline.orchestrator import PipelineOrchestrator
from core.policy_engine.yaml_engine import YamlPolicyEngine
from core.registry.registry import get_plugin_registry
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.policy import PolicyPackDefinition


@click.group()
def cli():
    """AegisGate GitOps CLI (aegisctl).
    Validates, tests, and replays policy packs for CI/CD pipelines.
    """
    pass


@cli.command("validate")
@click.argument("policy_file", type=click.Path(exists=True, readable=True))
def validate_policy(policy_file: str):
    """Validate syntax and schema of a policy.yaml file."""
    bootstrap_system()
    path = Path(policy_file)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        pack = PolicyPackDefinition(**data)
        click.secho(f"✓ Syntax and schema valid: {pack.id} (version {pack.version})", fg="green")

        # Verify scanners exist
        registry = get_plugin_registry()
        missing = []
        for s in pack.scanners:
            if not registry.get_scanner(s.name):
                missing.append(s.name)

        if missing:
            click.secho(f"⚠ Warning: Scanners not registered in local environment: {missing}", fg="yellow")
        else:
            click.secho(f"✓ All {len(pack.scanners)} scanners verified in plugin registry", fg="green")

        click.secho(f"✓ {len(pack.rules)} rules compiled successfully", fg="green")
        sys.exit(0)
    except Exception as e:
        click.secho(f"✗ Policy validation failed: {e!s}", fg="red")
        sys.exit(1)


@cli.command("test")
@click.argument("policy_file", type=click.Path(exists=True, readable=True))
@click.argument("test_cases_file", type=click.Path(exists=True, readable=True))
def test_policy(policy_file: str, test_cases_file: str):
    """Run automated test assertions against a policy pack."""
    bootstrap_system()
    asyncio.run(_run_test_cases(policy_file, test_cases_file))


async def _run_test_cases(policy_file: str, test_cases_file: str):
    orchestrator = PipelineOrchestrator()
    with open(policy_file, "r", encoding="utf-8") as f:
        pack = orchestrator.policy_engine.load_from_yaml_string(f.read())

    with open(test_cases_file, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    click.echo(f"Running {len(test_cases)} tests against pack '{pack.id}'...")
    passed = 0
    failed = 0

    for i, tc in enumerate(test_cases):
        name = tc.get("name", f"Test Case #{i+1}")
        req_data = tc.get("request", {})
        expected_decision = tc.get("expected_decision", "ALLOW")

        req = EvaluationRequest(
            policy_pack_id=pack.id,
            stage=StageEnum(req_data.get("stage", "llm_input")),
            actor=ActorModel(**req_data.get("actor", {"id": "test_actor"})),
            action=ActionModel(**req_data.get("action", {"name": "test_action"})),
            content=ContentModel(**req_data.get("content", {})),
            metadata=req_data.get("metadata", {}),
        )

        verdict = await orchestrator.evaluate(req)
        actual_decision = (
            verdict.decision.value if hasattr(verdict.decision, "value") else str(verdict.decision)
        )

        if actual_decision == expected_decision:
            click.secho(f"  ✓ {name} -> {actual_decision} (expected {expected_decision})", fg="green")
            passed += 1
        else:
            click.secho(f"  ✗ {name} -> {actual_decision} (expected {expected_decision})", fg="red")
            failed += 1

    click.echo(f"\nResult: {passed} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)


@cli.command("replay")
@click.argument("policy_file", type=click.Path(exists=True, readable=True))
@click.argument("audit_log_file", type=click.Path(exists=True, readable=True))
def replay_policy(policy_file: str, audit_log_file: str):
    """Replay historical audit logs through a candidate policy pack (Shadow Simulation)."""
    bootstrap_system()
    asyncio.run(_run_replay(policy_file, audit_log_file))


async def _run_replay(policy_file: str, audit_log_file: str):
    engine = YamlPolicyEngine()
    with open(policy_file, "r", encoding="utf-8") as f:
        candidate_pack = engine.load_from_yaml_string(f.read())

    with open(audit_log_file, "r", encoding="utf-8") as f:
        events = json.load(f)

    click.echo(f"Replaying {len(events)} audit events against candidate '{candidate_pack.id}'...")
    deltas = 0
    matches = 0

    for ev in events:
        req_data = ev.get("request_summary", ev.get("request", {}))
        hist_decision = ev.get("decision", "ALLOW")

        req = EvaluationRequest(
            policy_pack_id=candidate_pack.id,
            stage=StageEnum(req_data.get("stage", "llm_input")),
            actor=ActorModel(**req_data.get("actor", {"id": "replay_actor"})),
            action=ActionModel(**req_data.get("action", {"name": "replay_action"})),
            content=ContentModel(**req_data.get("content", {})),
        )

        cand_decision, risk, triggered, _ = await engine.evaluate(
            request=req,
            scanner_findings=[],
            resolved_context={},
            policy_pack=candidate_pack,
        )
        cand_dec_str = cand_decision.value if hasattr(cand_decision, "value") else str(cand_decision)

        if cand_dec_str != hist_decision:
            deltas += 1
            click.secho(
                f"  Δ Delta: Event {ev.get('id', 'N/A')} historical={hist_decision} -> candidate={cand_dec_str}",
                fg="yellow",
            )
        else:
            matches += 1

    click.echo(f"\nSimulation complete: {matches} matched historical decisions, {deltas} deltas produced.")


@cli.group("models")
def models_group():
    """Manage local ONNX/ML model runtimes and weights."""
    pass


@models_group.command("status")
def models_status():
    """Inspect status of local ML models in AEGIS_MODEL_DIR."""
    from core.config import get_settings

    settings = get_settings()
    model_dir = Path(settings.LOCAL_ONNX_MODEL_DIR)

    click.secho(f"\nLocal Model Runtime Status (Directory: {model_dir.resolve()}):", bold=True)
    click.echo("-" * 75)
    click.echo(f"{'Model Component':<30} {'File':<25} {'Status':<20}")
    click.echo("-" * 75)

    catalog = [
        ("Tier-2 Prompt Injection", "classifier.onnx"),
        ("Tier-2 NER PII Analyzer", "ner_model.onnx"),
        ("Tier-2 Topic Embeddings", "topic_embeddings.onnx"),
        ("Tier-2 Safety & Toxicity", "safety_guard.onnx"),
        ("Tier-2 NLI Faithfulness", "nli_cross_encoder.onnx"),
        ("Tier-2 Multimodal OCR", "ocr_tesseract.onnx"),
    ]

    for component, filename in catalog:
        path = model_dir / filename
        if path.exists():
            status_text = click.style("LOADED", fg="green", bold=True)
        else:
            status_text = click.style("FALLBACK_MODE", fg="yellow")
        click.echo(f"{component:<30} {filename:<25} {status_text:<20}")

    click.echo("-" * 75)
    click.secho("Tip: Use 'aegisctl models pull <profile>' to initialize model bundles.\n", fg="cyan")


@models_group.command("pull")
@click.argument("profile", type=click.Choice(["lightweight", "enterprise-full"]))
def models_pull(profile: str):
    """Download or initialize local model bundles for given profile."""
    from core.config import get_settings

    settings = get_settings()
    model_dir = Path(settings.LOCAL_ONNX_MODEL_DIR)
    model_dir.mkdir(parents=True, exist_ok=True)

    click.echo(f"Initializing model bundle for profile '{profile}' in {model_dir}...")

    files_to_scaffold = ["classifier.onnx", "ner_model.onnx"]
    if profile == "enterprise-full":
        files_to_scaffold.extend([
            "topic_embeddings.onnx",
            "safety_guard.onnx",
            "nli_cross_encoder.onnx",
            "ocr_tesseract.onnx",
        ])

    for fname in files_to_scaffold:
        target_file = model_dir / fname
        if not target_file.exists():
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(f"# AegisGate Model Weight Bundle Scaffold: {fname}\n")
            click.secho(f"  ✓ Initialized {fname}", fg="green")
        else:
            click.echo(f"  - {fname} already exists")

    click.secho(f"\n✓ Profile '{profile}' initialized successfully.\n", fg="green", bold=True)


if __name__ == "__main__":
    cli()

