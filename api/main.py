"""FastAPI service for the Threat Response System.

Run from the Threat_Response_System folder:
    .venv/bin/uvicorn api.main:app --reload

Then open http://localhost:8000/docs to try every endpoint in the browser.
"""

import io
from contextlib import asynccontextmanager
from typing import Optional

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from src import threat_engine as engine

# Largest number of connections accepted in one /predict/batch request
MAX_BATCH_SIZE = 10_000


@asynccontextmanager
async def lifespan(app):
    # Load the models once when the server starts, not on every request
    engine.load_models()
    yield


app = FastAPI(
    title="Threat Response System API",
    description="Detects network attacks, names the attack type, scores the risk "
                "and recommends a response. Trained on UNSW-NB15.",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------- Request and response shapes ----------------

class Connection(BaseModel):
    """One network connection with the 42 UNSW-NB15 features."""
    dur: float = Field(ge=0, description="Connection duration in seconds")
    proto: str = Field(description="Protocol, e.g. tcp, udp")
    service: str = Field(description="Service, e.g. http, dns, or '-' for none")
    state: str = Field(description="Connection state, e.g. FIN, INT, CON")
    spkts: float = Field(ge=0, description="Packets sent by the source")
    dpkts: float = Field(ge=0, description="Packets sent by the destination")
    sbytes: float = Field(ge=0, description="Bytes sent by the source")
    dbytes: float = Field(ge=0, description="Bytes sent by the destination")
    rate: float = Field(ge=0)
    sttl: float = Field(ge=0, description="Source time-to-live")
    dttl: float = Field(ge=0, description="Destination time-to-live")
    sload: float = Field(ge=0, description="Source bits per second")
    dload: float = Field(ge=0, description="Destination bits per second")
    sloss: float = Field(ge=0, description="Source packets lost or resent")
    dloss: float = Field(ge=0, description="Destination packets lost or resent")
    sinpkt: float = Field(ge=0)
    dinpkt: float = Field(ge=0)
    sjit: float = Field(ge=0)
    djit: float = Field(ge=0)
    swin: float = Field(ge=0)
    stcpb: float = Field(ge=0)
    dtcpb: float = Field(ge=0)
    dwin: float = Field(ge=0)
    tcprtt: float = Field(ge=0)
    synack: float = Field(ge=0)
    ackdat: float = Field(ge=0)
    smean: float = Field(ge=0)
    dmean: float = Field(ge=0)
    trans_depth: float = Field(ge=0)
    response_body_len: float = Field(ge=0)
    ct_srv_src: float = Field(ge=0)
    ct_state_ttl: float = Field(ge=0)
    ct_dst_ltm: float = Field(ge=0)
    ct_src_dport_ltm: float = Field(ge=0)
    ct_dst_sport_ltm: float = Field(ge=0)
    ct_dst_src_ltm: float = Field(ge=0)
    is_ftp_login: float = Field(ge=0)
    ct_ftp_cmd: float = Field(ge=0)
    ct_flw_http_mthd: float = Field(ge=0)
    ct_src_ltm: float = Field(ge=0)
    ct_srv_dst: float = Field(ge=0)
    is_sm_ips_ports: float = Field(ge=0)

    # Example shown on the /docs page (a real row from the official test set)
    model_config = {
        "json_schema_extra": {
            "examples": [{
                "dur": 1.1e-05, "proto": "udp", "service": "-", "state": "INT",
                "spkts": 2, "dpkts": 0, "sbytes": 496, "dbytes": 0, "rate": 90909.0902,
                "sttl": 254, "dttl": 0, "sload": 180363632, "dload": 0, "sloss": 0,
                "dloss": 0, "sinpkt": 0.011, "dinpkt": 0, "sjit": 0, "djit": 0,
                "swin": 0, "stcpb": 0, "dtcpb": 0, "dwin": 0, "tcprtt": 0, "synack": 0,
                "ackdat": 0, "smean": 248, "dmean": 0, "trans_depth": 0,
                "response_body_len": 0, "ct_srv_src": 2, "ct_state_ttl": 2,
                "ct_dst_ltm": 1, "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1,
                "ct_dst_src_ltm": 2, "is_ftp_login": 0, "ct_ftp_cmd": 0,
                "ct_flw_http_mthd": 0, "ct_src_ltm": 1, "ct_srv_dst": 2,
                "is_sm_ips_ports": 0,
            }]
        }
    }


class AnalysisResult(BaseModel):
    prediction: str
    attack_type: Optional[str]
    risk_score: float
    risk_level: str
    recommended_action: str


class Summary(BaseModel):
    total_connections: int
    attacks_detected: int
    attack_rate: float
    risk_levels: dict[str, int]
    attack_types: dict[str, int]


class BatchResult(BaseModel):
    summary: Summary
    results: list[AnalysisResult]


# ---------------- Helpers ----------------

def run_analysis(data):
    """Run the models and turn input errors into a clear 422 response."""
    try:
        return engine.analyze(data)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))


def to_batch_result(results):
    # Turn the results table into JSON-friendly records (NaN -> None)
    records = results.astype(object).where(results.notna(), None).to_dict(orient="records")
    return {"summary": engine.summarize(results), "results": records}


# ---------------- Endpoints ----------------

@app.get("/health")
def health():
    """Check that the server is running and the models are loaded."""
    engine.load_models()
    return {"status": "ok", "models_loaded": True}


@app.get("/model-info")
def model_info():
    """Describe the inputs the models need and how the outputs are worked out."""
    return {
        "dataset": "UNSW-NB15",
        "detector": "Random Forest (attack vs normal)",
        "attack_type_model": "Random Forest (9 attack types)",
        "attack_threshold": engine.ATTACK_THRESHOLD,
        "features": engine.FEATURES,
        "categorical_features": engine.CATEGORICAL_FEATURES,
        "risk_levels": {
            "Low": "score below 30",
            "Medium": "30 to 59.9",
            "High": "60 to 84.9",
            "Critical": "85 and above",
        },
        "response_actions": engine.RESPONSE_ACTIONS,
    }


@app.post("/predict", response_model=AnalysisResult)
def predict(connection: Connection):
    """Analyze one connection."""
    data = pd.DataFrame([connection.model_dump()])
    return to_batch_result(run_analysis(data))["results"][0]


@app.post("/predict/batch", response_model=BatchResult)
def predict_batch(connections: list[Connection]):
    """Analyze a list of connections sent as JSON."""
    if not connections:
        raise HTTPException(status_code=422, detail="Send at least one connection")
    if len(connections) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"At most {MAX_BATCH_SIZE} connections per request. Use /predict/csv for bigger files.",
        )
    data = pd.DataFrame([c.model_dump() for c in connections])
    return to_batch_result(run_analysis(data))


@app.post("/predict/csv", response_model=BatchResult)
async def predict_csv(file: UploadFile = File(...)):
    """Analyze every row of an uploaded CSV file (same columns as UNSW-NB15).

    Extra columns such as id, label or attack_cat are ignored.
    """
    try:
        data = pd.read_csv(io.BytesIO(await file.read()))
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read the file as CSV")
    if data.empty:
        raise HTTPException(status_code=422, detail="The CSV file has no rows")
    return to_batch_result(run_analysis(data))
