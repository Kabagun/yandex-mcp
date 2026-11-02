import tomllib
from pathlib import Path


def test_supported_python_range_and_build_dependencies() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert data["project"]["requires-python"] == ">=3.12,<3.14"
    assert "mcp[cli]>=2.3.0,<3.0.0" in data["project"]["dependencies"]
    assert "cryptography>=44" in data["project"]["dependencies"]
    assert "build>=1.2" in data["dependency-groups"]["dev"]


def test_container_and_ci_use_locked_and_artifact_level_gates() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "COPY uv.lock" in dockerfile
    assert "uv sync --frozen" in dockerfile
    assert "ruff format --check" in workflow
    assert "yandex-workspace-mcp doctor" in workflow
    assert "scripts/check_tool_matrix.py" in workflow
    assert "docker build" in workflow


def test_live_workflow_verifies_machine_readable_cleanup_status() -> None:
    workflow = Path(".github/workflows/live-contract.yml").read_text(encoding="utf-8")

    assert "--report" in workflow
    assert "cleanup_ok" in workflow
    assert 'echo "contract_sweep cleanup' not in workflow
