# AgentSupplyShield Architecture Diagram

This diagram shows the current public-facing architecture for AgentSupplyShield. External tool repositories, schemas, and docs are treated as untrusted input until findings are grounded in evidence and reviewed through policy.

```mermaid
flowchart TD
    reviewer["Security reviewer / researcher"] --> dashboard["Reporting dashboard<br/>React + TypeScript"]
    dashboard --> api["API server<br/>FastAPI"]

    github["GitHub repo / MCP-style docs"] --> crawler["Text-only crawler<br/>URL checks + relevant files"]
    local["Local README / schema folder"] --> ingestion["Safe local ingestion<br/>allowlists + size limits"]

    crawler --> parser["Parser layer<br/>Markdown + JSON/YAML"]
    ingestion --> parser

    parser --> artifacts["Raw + parsed artifacts<br/>local persistence"]
    parser --> evidence["Evidence spans<br/>line ranges + hashes"]

    evidence --> detectors["Static detectors<br/>prompt injection + credentials + permissions"]
    detectors --> risk["Risk scoring<br/>severity + confidence"]
    risk --> policy["Policy firewall<br/>allow / warn / quarantine / block"]

    evidence --> retrieval["RAG evidence layer<br/>lexical + embedding-ready hybrid retrieval"]
    evidence --> graph["Tool-risk graph<br/>repos + tools + capabilities + domains + findings"]

    policy --> sandbox["Sandbox runner<br/>mock tools + mock secrets"]
    graph --> sandbox
    retrieval --> reports["Evidence-grounded reports<br/>JSON + Markdown"]
    policy --> reports
    sandbox --> reports

    reports --> dashboard
    graph --> dashboard
    retrieval --> dashboard
```

## Runtime Shape

The local runtime currently includes:

- `api-server`: FastAPI backend and scanner orchestration.
- `frontend`: Vite dashboard preview.
- `postgres`: Compose service reserved for database-backed persistence.
- `redis`: Compose service reserved for queue/cache-backed workers.

Worker services are intentionally not exposed as separate Compose entrypoints until dedicated worker commands exist.

## Evidence Boundary

AgentSupplyShield keeps security claims tied to evidence:

- raw external text is stored separately from parsed records;
- findings cite evidence IDs, artifact paths, and line ranges;
- reports separate detected evidence from inferred risk;
- sandbox traces use mock tools and mock secrets only.
