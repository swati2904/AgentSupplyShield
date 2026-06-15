from fastapi import FastAPI

app = FastAPI(title="AgentSupplyShield API")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agentsupplyshield-api"}
