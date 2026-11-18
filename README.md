# Threat Response System

Detects attacks in network traffic, names the attack type, gives each connection
a risk score and recommends what to do about it. Built on the **UNSW-NB15**
dataset, served through a FastAPI service and a Streamlit dashboard.

**Live demo:** https://threat-response-system.streamlit.app

## Problem

A network sees thousands of connections every minute and a security team cannot
look at all of them. The goal is to sort traffic automatically: flag the
connections that look like attacks, say what kind of attack they look like, and
rank them by risk so the most dangerous ones are handled first.

## Dataset

| | |
|---|---|
| Source | [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) (UNSW Canberra) |
| Training file | `UNSW_NB15_training-set.csv`, 175,341 rows |
| Official test file | `UNSW_NB15_testing-set.csv`, 82,332 rows |
| Features | 42 (39 numerical, 3 categorical: `proto`, `service`, `state`) |
| Targets | `label` (0 = normal, 1 = attack) and `attack_cat` (9 attack types + Normal) |

The official test file is included because the dashboard samples from it. To
retrain the models, download the training file from the link above and place it
in this folder.

## Approach

**Exploration.** No missing values. The numerical features are heavily
right-skewed: 34 of 39 have skewness above 1.

**Preprocessing.** Logistic Regression uses `log1p` on the skewed columns and
standard scaling on all numerical columns. Tree models use the raw numbers.
Every model one-hot encodes `proto`, `service` and `state`.

**Two models.**
1. *Detector*: attack or normal. Four models were compared and the best was
   picked on a 20% split of the training file, so the official test file stays
   an honest final check.
2. *Attack type classifier*: trained only on attack rows, with class weights so
   rare attacks (Worms, Shellcode) are not ignored.

**Risk and response.** The risk score is the detector's attack probability
× 100: Low (< 30), Medium (30-60), High (60-85) and Critical (85+). Each attack
type maps to a recommended response action.

## Results

**Detector (F1 score)**

| Model | 20% split | Official test file |
|---|---|---|
| Logistic Regression (baseline) | 0.951 | 0.862 |
| Logistic Regression + log transform | 0.951 | 0.887 |
| **Random Forest (selected)** | **0.971** | **0.891** |
| Gradient Boosting | 0.970 | 0.893 |

On the official test file, the Random Forest scores 86.7% accuracy. It catches
99% of attacks but also flags 28% of normal traffic. The official test file
contains traffic patterns the training file does not, which is a known property
of UNSW-NB15.

**Attack type classifier.** 76% accuracy on the official test file's attack rows.
Generic, Reconnaissance, Fuzzers and Exploits are recognised well (F1
0.72-0.98). Analysis, Backdoor and DoS look very similar in this dataset and are
often confused with each other.

## Project structure

```
Threat_Response_System/
├── Threat_Response_System.ipynb   # EDA, training, evaluation, saves the models
├── src/threat_engine.py           # loads the models; prediction, risk and response logic
├── api/main.py                    # FastAPI service
├── dashboard/                     # Streamlit website (talks to the API)
│   ├── app.py                     #   entry point: theme, top navigation, footer
│   ├── common.py                  #   API calls, charts and shared page styling
│   ├── views/                     #   one file per page
│   └── assets/                    #   logo and icon
├── .streamlit/config.toml         # colours, font and light/dark theme
├── models/                        # trained models (saved by the notebook, compressed)
└── requirements.txt
```

## How to run

```bash
# 1. Install
python -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Optional: retrain the models by running every cell of the notebook
#    (the trained models are already in models/)
.venv/bin/jupyter lab Threat_Response_System.ipynb

# 3. Start the dashboard (http://localhost:8501)
.venv/bin/streamlit run dashboard/app.py
```

The dashboard starts the API in the background by itself if it is not already
running. To run the API on its own (for example to use http://localhost:8000/docs):

```bash
.venv/bin/uvicorn api.main:app
```

If the API runs on another machine, set `THREAT_API_URL` before starting the
dashboard. It only starts the API itself when the address is on this computer.

## API

| Method | Endpoint | What it does |
|---|---|---|
| GET | `/health` | Checks that the server is up and the models are loaded |
| GET | `/model-info` | Lists the input features, risk levels and response actions |
| POST | `/predict` | Analyzes one connection (JSON) |
| POST | `/predict/batch` | Analyzes up to 10,000 connections (JSON list) |
| POST | `/predict/csv` | Analyzes every row of an uploaded CSV file |

Every endpoint returns a prediction, an attack type, a risk score, a risk
level and a recommended action for each connection. `/predict/batch` and
`/predict/csv` also return a summary with totals per risk level and attack type.

## Dashboard

A small website with a top navigation bar. It follows the browser's light or
dark setting and works on phones.

- **Home**: what the system does, how it works and its known limits.
- **Analyze traffic**: upload a CSV or sample the official test file. Shows
  headline numbers, risk-level and attack-type charts, one recommended response
  per attack type, a filterable alerts table and a CSV download. If the file has
  true labels, it also shows accuracy, attacks caught and false alarms.
- **Investigate**: pick a test row (optionally by attack type), change its
  values and see the verdict, risk score and recommended action.
- **Playbook**: risk-level cut-offs and the action for each attack type.

Each page shows whether the analysis service is ready. If it cannot be reached,
visitors see a short message and a **Try again** button.

## Limitations

- About 28% of normal connections in the official test file are flagged as
  attacks, so alerts need a human review.
- The response actions are fixed rules for each attack type, not learned from
  data.
- Trained on UNSW-NB15 only, which was generated in a lab in 2015.
  Real networks look different, so the models would need retraining on local
  traffic.
