"""Shared prediction logic for the Threat Response System.

This file loads the two models trained in Threat_Response_System.ipynb and
turns raw network connections into:
  1. a prediction (Attack or Normal)
  2. an attack type (Exploits, DoS, ...)
  3. a risk score (0-100) and risk level (Low / Medium / High / Critical)
  4. a recommended response action

The FastAPI service (api/main.py) uses this file.
"""

from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# Where the notebook saved the models
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
DETECTOR_PATH = MODELS_DIR / "attack_detector.pkl"
ATTACK_TYPE_PATH = MODELS_DIR / "attack_type_classifier.pkl"

# A connection is called an attack when the model is at least 50% sure
ATTACK_THRESHOLD = 0.5

# Text columns
CATEGORICAL_FEATURES = ["proto", "service", "state"]

# Number columns
NUMERICAL_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
    "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports",
]

# All 42 input columns, in the same order as the training data
FEATURES = ["dur"] + CATEGORICAL_FEATURES + NUMERICAL_FEATURES[1:]

RISK_LEVELS = ["Low", "Medium", "High", "Critical"]

# What to do for each attack type, in simple steps (same as the notebook)
RESPONSE_ACTIONS = {
    "Generic": "Block the source IP and check the targeted service for weaknesses",
    "Exploits": "Isolate the targeted host, patch the vulnerable software, check for compromise",
    "Fuzzers": "Rate-limit or block the source IP and check application logs for crashes",
    "DoS": "Turn on rate limiting, block the source IP, contact the ISP if traffic keeps growing",
    "Reconnaissance": "Block the scanning IP and close ports or services that are not needed",
    "Analysis": "Watch the source closely and review firewall and IDS rules",
    "Backdoor": "Isolate the host now, remove the backdoor, and reset passwords",
    "Shellcode": "Isolate the host, stop suspicious processes, and patch the exploited software",
    "Worms": "Isolate infected hosts, block the spreading port, and scan the whole network",
}
NO_ACTION = "No action needed"


def risk_level(score):
    """Turn a 0-100 risk score into a simple level (same cut-offs as the notebook)."""
    if score < 30:
        return "Low"
    elif score < 60:
        return "Medium"
    elif score < 85:
        return "High"
    return "Critical"


@lru_cache(maxsize=1)
def load_models():
    """Load both models once and keep them in memory."""
    for path in (DETECTOR_PATH, ATTACK_TYPE_PATH):
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found. Run Threat_Response_System.ipynb first to train and save the models."
            )
    return joblib.load(DETECTOR_PATH), joblib.load(ATTACK_TYPE_PATH)


def prepare_input(data):
    """Check the input has every column the models need, and put them in order.

    Extra columns (like id, label or attack_cat) are ignored.
    """
    missing = [col for col in FEATURES if col not in data.columns]
    if missing:
        raise ValueError(f"Missing columns: {', '.join(missing)}")

    X = data[FEATURES].copy()
    X[CATEGORICAL_FEATURES] = X[CATEGORICAL_FEATURES].astype(str)

    # Every number column must really contain numbers
    X[NUMERICAL_FEATURES] = X[NUMERICAL_FEATURES].apply(pd.to_numeric, errors="coerce")
    bad_cols = X[NUMERICAL_FEATURES].columns[X[NUMERICAL_FEATURES].isna().any()].tolist()
    if bad_cols:
        raise ValueError(f"Empty or non-numeric values in: {', '.join(bad_cols)}")
    return X


def analyze(data):
    """Run both models on a table of connections and return one result row per connection."""
    detector, attack_type_model = load_models()
    X = prepare_input(data)

    attack_prob = detector.predict_proba(X)[:, 1]
    is_attack = attack_prob >= ATTACK_THRESHOLD
    attack_type = attack_type_model.predict(X)

    results = pd.DataFrame(index=data.index)
    results["prediction"] = np.where(is_attack, "Attack", "Normal")
    results["attack_type"] = np.where(is_attack, attack_type, None)
    results["risk_score"] = (attack_prob * 100).round(1)
    results["risk_level"] = results["risk_score"].apply(risk_level)
    results["recommended_action"] = (
        results["attack_type"].map(RESPONSE_ACTIONS).fillna(NO_ACTION)
    )
    return results


def summarize(results):
    """Count the results so the dashboard can show totals and charts."""
    attacks = results[results["prediction"] == "Attack"]
    return {
        "total_connections": int(len(results)),
        "attacks_detected": int(len(attacks)),
        "attack_rate": round(float(len(attacks) / len(results)), 4) if len(results) else 0.0,
        "risk_levels": {
            level: int((results["risk_level"] == level).sum()) for level in RISK_LEVELS
        },
        "attack_types": {
            name: int(count) for name, count in attacks["attack_type"].value_counts().items()
        },
    }
