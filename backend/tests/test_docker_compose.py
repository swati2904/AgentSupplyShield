from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_docker_compose_defines_current_runtime_services() -> None:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    services = compose["services"]
    assert {"api-server", "frontend", "postgres", "redis"}.issubset(services)
    assert services["api-server"]["build"]["dockerfile"] == "backend/Dockerfile"
    assert services["frontend"]["build"]["dockerfile"] == "frontend/Dockerfile"
    assert "8000:8000" in services["api-server"]["ports"]
    assert "4173:4173" in services["frontend"]["ports"]
    assert "healthcheck" in services["api-server"]
    assert set(compose["volumes"]) == {"postgres-data", "redis-data"}


def test_docker_artifacts_use_existing_entrypoints_and_keep_private_files_out() -> None:
    backend_dockerfile = (REPO_ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    frontend_dockerfile = (REPO_ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert "uvicorn" in backend_dockerfile
    assert "app.main:app" in backend_dockerfile
    assert "COPY configs /app/configs" in backend_dockerfile
    assert "npm run build" in frontend_dockerfile
    assert "npm\", \"run\", \"preview" in frontend_dockerfile
    assert ".agent_state.md" in dockerignore
    assert "AGENTS.md" in dockerignore
    assert "AgentSupplyShield_roadmap_execution.md" in dockerignore
