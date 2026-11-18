"""Shared code for the dashboard pages: API calls, data, charts and page styling."""

import atexit
import base64
import io
import os
import subprocess
import sys
import time
from html import escape
from pathlib import Path
from urllib.parse import urlparse

import altair as alt
import pandas as pd
import requests
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
ASSETS = Path(__file__).resolve().parent / "assets"
OFFICIAL_TEST_PATH = ROOT / "UNSW_NB15_testing-set.csv"
DEFAULT_API_URL = os.environ.get("THREAT_API_URL", "http://localhost:8000")

RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
# Status colours: green = good, amber = warning, orange = serious, red = critical
RISK_COLORS = ["#0ca30c", "#fab219", "#ec835a", "#d03b3b"]
RISK_COLOR = dict(zip(RISK_LEVELS, RISK_COLORS))
BAR_COLOR = "#2563eb"
# Mid-grey text that is readable on both the light and the dark theme
LABEL_COLOR = "#8c8b86"
CATEGORICAL_FEATURES = ["proto", "service", "state"]
NON_FEATURE_COLUMNS = ["id", "label", "attack_cat"]
# Traffic is sent to the API in chunks of this size so a progress bar can be shown
CHUNK_SIZE = 2_000


# ---------------- Talking to the API ----------------

class APIError(Exception):
    pass


def api_url():
    return st.session_state.setdefault("api_url", DEFAULT_API_URL)


def request_api(url, method, path, timeout=120, **kwargs):
    """Call the API and return its JSON, or raise APIError with a readable message."""
    try:
        response = requests.request(method, f"{url}{path}", timeout=timeout, **kwargs)
    except requests.ConnectionError:
        raise APIError("We couldn't connect to the analysis service. Please try again in a moment.")
    except requests.Timeout:
        raise APIError("The analysis is taking longer than expected. Please try again, "
                       "or analyze fewer connections at a time.")
    if response.status_code in (400, 413, 422):
        # Problems with the data that was sent: the message says what to fix
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = None
        raise APIError(f"We couldn't analyze this traffic. {detail or 'Please check the file and try again.'}")
    if response.status_code != 200:
        raise APIError("Something went wrong on our side. Please try again in a moment.")
    return response.json()


def call_api(method, path, **kwargs):
    """Call the API and return (json, error message)."""
    try:
        return request_api(api_url(), method, path, **kwargs), None
    except APIError as error:
        return None, str(error)


# Failed calls raise, and Streamlit does not cache exceptions,
# so a service that was down is checked again on the next interaction.
@st.cache_data(ttl=30, show_spinner=False)
def get_health(url):
    return request_api(url, "GET", "/health", timeout=5)


@st.cache_data(ttl=300, show_spinner=False)
def get_model_info(url):
    return request_api(url, "GET", "/model-info", timeout=10)


@st.cache_resource(show_spinner=False)
def _start_local_service(url):
    """Start the API in the background if it should run on this computer. Runs once per dashboard."""
    address = urlparse(url)
    if address.hostname not in ("localhost", "127.0.0.1"):
        return None
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1",
         "--port", str(address.port or 80)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    atexit.register(process.terminate)
    return process


def _healthy(url):
    try:
        get_health(url)
        return True
    except APIError:
        return False


def api_online():
    """True when the analysis service answers. Starts it first if it runs locally and is not up yet."""
    url = api_url()
    if _healthy(url):
        return True
    process = _start_local_service(url)
    if process is None or process.poll() is not None:
        return False
    with st.spinner("Getting the analysis service ready..."):
        for _ in range(60):
            time.sleep(0.5)
            if process.poll() is not None:
                return False
            if _healthy(url):
                return True
    return False


def analyze_traffic(traffic):
    """Send the traffic to the API in chunks, with a progress bar. Returns (results, error)."""
    parts = []
    total = len(traffic)
    progress = st.progress(0.0, text=f"Analyzing 0 of {total:,} connections...")
    for start in range(0, total, CHUNK_SIZE):
        chunk = traffic.iloc[start:start + CHUNK_SIZE]
        response, error = call_api(
            "POST", "/predict/csv",
            files={"file": ("traffic.csv", chunk.to_csv(index=False).encode(), "text/csv")},
        )
        if error:
            progress.empty()
            return None, error
        parts.append(pd.DataFrame(response["results"]))
        done = min(start + CHUNK_SIZE, total)
        progress.progress(done / total, text=f"Analyzing {done:,} of {total:,} connections...")
    progress.empty()
    return pd.concat(parts, ignore_index=True), None


def summarize(results):
    """Totals for the headline numbers and charts (same shape as the API summary)."""
    attacks = results[results["prediction"] == "Attack"]
    return {
        "total_connections": len(results),
        "attacks_detected": len(attacks),
        "attack_rate": len(attacks) / len(results) if len(results) else 0.0,
        "risk_levels": {level: int((results["risk_level"] == level).sum()) for level in RISK_LEVELS},
        "attack_types": {k: int(v) for k, v in attacks["attack_type"].value_counts().items()},
    }


# ---------------- Data ----------------

@st.cache_data
def load_official_test():
    return pd.read_csv(OFFICIAL_TEST_PATH)


@st.cache_data
def sample_official_test(n_rows, seed):
    return load_official_test().sample(n_rows, random_state=seed).reset_index(drop=True)


@st.cache_data
def read_uploaded_csv(data):
    return pd.read_csv(io.BytesIO(data))


@st.cache_data
def category_options():
    official = load_official_test()
    return {col: sorted(official[col].astype(str).unique()) for col in CATEGORICAL_FEATURES}


# ---------------- Charts ----------------

def risk_level_chart(risk_counts):
    data = pd.DataFrame({"Risk level": RISK_LEVELS,
                         "Connections": [risk_counts.get(l, 0) for l in RISK_LEVELS]})
    base = alt.Chart(data).encode(
        x=alt.X("Risk level:N", sort=RISK_LEVELS, title=None, axis=alt.Axis(labelAngle=0)),
        y=alt.Y("Connections:Q", title=None),
    )
    bars = base.mark_bar(cornerRadiusEnd=6, size=48).encode(
        color=alt.Color("Risk level:N", scale=alt.Scale(domain=RISK_LEVELS, range=RISK_COLORS),
                        legend=None),
        tooltip=["Risk level", alt.Tooltip("Connections:Q", format=",")],
    )
    labels = base.mark_text(dy=-8, color=LABEL_COLOR).encode(text=alt.Text("Connections:Q", format=","))
    return (bars + labels).properties(height=300)


def attack_type_chart(type_counts):
    data = pd.DataFrame(list(type_counts.items()), columns=["Attack type", "Connections"])
    base = alt.Chart(data).encode(
        y=alt.Y("Attack type:N", sort="-x", title=None),
        x=alt.X("Connections:Q", title=None),
    )
    bars = base.mark_bar(cornerRadiusEnd=6, color=BAR_COLOR).encode(
        tooltip=["Attack type", alt.Tooltip("Connections:Q", format=",")],
    )
    labels = base.mark_text(align="left", dx=4, color=LABEL_COLOR).encode(text=alt.Text("Connections:Q", format=","))
    return (bars + labels).properties(height=300)


# ---------------- Page building blocks ----------------

def keep_widget_state(*keys):
    """Keep widget values when the user moves to another page and comes back."""
    for key in keys:
        if key in st.session_state:
            st.session_state[key] = st.session_state[key]


ICONS = {
    "shield": '<path d="M12 3l8 3v6c0 5-3.4 8.4-8 9.5C7.4 20.4 4 17 4 12V6z"/><path d="M9 12l2 2 4-4"/>',
    "tag": '<path d="M3 12V4h8l10 10-8 8z"/><circle cx="7.5" cy="8.5" r="1.5"/>',
    "gauge": '<path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-6"/>',
    "bolt": '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
    "upload": '<path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 20h16"/>',
    "list": '<path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    "chart": '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    "alert": '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 17h.01"/>',
    "check": '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
}


def _icon_css():
    """One CSS class per icon. st.html removes <svg> tags and inline url() styles,
    so each SVG is drawn as a CSS mask filled with the current text colour."""
    rules = []
    for name, paths in ICONS.items():
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" '
               f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{paths}</svg>')
        data = base64.b64encode(svg.encode()).decode()
        rules.append(f".trs-ico-{name} {{ --i: url(data:image/svg+xml;base64,{data}); }}")
    return "\n".join(rules)


def icon(name, size=20):
    return f'<span class="trs-ico trs-ico-{name}" style="width:{size}px;height:{size}px"></span>'


def html(markup):
    st.html(markup)


def risk_pill(level):
    color = RISK_COLOR.get(level, LABEL_COLOR)
    return f'<span class="trs-pill" style="--c:{color}">{escape(level)}</span>'


def stat_tiles(tiles):
    """A responsive row of number tiles. tiles = [(label, value, note, colour or None)]."""
    cells = []
    for label, value, note, color in tiles:
        accent = f' style="--accent:{color}"' if color else ""
        note_html = f'<div class="trs-tile-note">{escape(note)}</div>' if note else ""
        cells.append(
            f'<div class="trs-tile"{accent}><div class="trs-tile-label">{escape(label)}</div>'
            f'<div class="trs-tile-value">{escape(value)}</div>{note_html}</div>'
        )
    html(f'<div class="trs-grid trs-grid-tiles">{"".join(cells)}</div>')


def section_title(title, subtitle=None):
    sub = f'<p class="trs-section-sub">{escape(subtitle)}</p>' if subtitle else ""
    html(f'<div class="trs-section"><div class="trs-section-title">{escape(title)}</div>{sub}</div>')


def banner(text, tone="info"):
    """A coloured message strip. tone: info, warning, danger, success."""
    icons = {"info": "info", "warning": "alert", "danger": "alert", "success": "check"}
    html(f'<div class="trs-banner trs-banner-{tone}">{icon(icons[tone])}<div>{text}</div></div>')


def page_header(eyebrow, title, subtitle):
    """Page title on the left, service status on the right. Returns True when the service is online."""
    left, right = st.columns([3, 1], vertical_alignment="bottom")
    with left:
        html(
            f'<div class="trs-page-head"><div class="trs-eyebrow">{escape(eyebrow)}</div>'
            f'<div class="trs-page-title">{escape(title)}</div>'
            f'<p class="trs-page-sub">{escape(subtitle)}</p></div>'
        )
    online = api_online()
    with right:
        label = "All systems ready" if online else "Temporarily unavailable"
        html(f'<div style="text-align:right"><span class="trs-status {"on" if online else "off"}">'
             f'<i></i>{label}</span></div>')
    return online


def offline_notice():
    banner(
        "<b>Analysis is temporarily unavailable.</b> We're having trouble reaching the analysis "
        "service. This usually fixes itself within a minute, so please try again shortly.",
        "warning",
    )
    if st.button("Try again", icon=":material/refresh:"):
        st.rerun()


def footer():
    html(
        '<div class="trs-footer"><div>Threat Response · network attack detection built on the '
        'UNSW-NB15 dataset</div><div>Predictions support analysts and do not replace them.</div></div>'
    )


CSS = """
<style>
/* ---------- Top navigation: pinned to the top, links on the right ---------- */
header[data-testid="stHeader"] { position: fixed; top: 0; left: 0; right: 0; z-index: 999990;
  border-bottom: 1px solid rgba(128,128,128,.14); box-shadow: 0 4px 24px rgba(15,23,42,.04); }
[data-testid="stTopNav"] { justify-content: flex-end; }

/* ---------- Layout ---------- */
.block-container { max-width: 1180px; padding-top: 5.5rem; padding-bottom: 2rem; }
.trs-ico { display: inline-block; flex: none; background: currentColor;
  -webkit-mask: var(--i) center / contain no-repeat; mask: var(--i) center / contain no-repeat; }
@media (max-width: 640px) { .block-container { padding-left: 1rem; padding-right: 1rem; } }

/* ---------- Text helpers ---------- */
.trs-eyebrow { font-size: .78rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
  color: #3b82f6; margin-bottom: .35rem; }
.trs-page-title { font-size: clamp(1.8rem, 3vw, 2.4rem); font-weight: 700; line-height: 1.15;
  letter-spacing: -.02em; }
.trs-page-sub { font-size: 1.05rem; opacity: .72; margin: .5rem 0 0; max-width: 680px; }
.trs-section { margin: 1.6rem 0 .2rem; }
.trs-section-title { font-size: 1.3rem; font-weight: 650; letter-spacing: -.01em; }
.trs-section-sub { opacity: .7; margin: .25rem 0 0; }
.trs-muted { opacity: .7; }

/* ---------- Status pill ---------- */
.trs-status { display: inline-flex; align-items: center; gap: .45rem; font-size: .85rem; font-weight: 500;
  padding: .3rem .75rem; border-radius: 999px; border: 1px solid rgba(128,128,128,.25); white-space: nowrap; }
.trs-status i { width: .5rem; height: .5rem; border-radius: 50%; }
.trs-status.on i { background: #10b981; box-shadow: 0 0 0 3px rgba(16,185,129,.2); }
.trs-status.off i { background: #ef4444; box-shadow: 0 0 0 3px rgba(239,68,68,.2); }

/* ---------- Cards and grids ---------- */
.trs-grid { display: grid; gap: 1rem; }
.trs-grid-tiles { grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }
.trs-grid-cards { grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.trs-grid-4 { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
.trs-card { border: 1px solid rgba(128,128,128,.22); border-radius: 16px; padding: 1.3rem 1.35rem;
  background: rgba(128,128,128,.035); height: 100%; box-sizing: border-box; }
.trs-card-title { font-weight: 650; font-size: 1.05rem; margin: .8rem 0 .3rem; }
.trs-card p { margin: 0; opacity: .75; line-height: 1.5; }
.trs-card-icon { width: 40px; height: 40px; border-radius: 12px; display: flex; align-items: center;
  justify-content: center; background: rgba(59,130,246,.12); color: #3b82f6; }
.trs-card-head { display: flex; justify-content: space-between; align-items: center; gap: .5rem; }
.trs-card-count { font-size: 1.6rem; font-weight: 700; margin-top: .6rem; }
.trs-card-count span { font-size: .85rem; font-weight: 500; opacity: .65; margin-left: .3rem; }
.trs-card-action { margin-top: .7rem; padding-top: .7rem; border-top: 1px solid rgba(128,128,128,.2);
  line-height: 1.5; }

.trs-tile { border: 1px solid rgba(128,128,128,.22); border-radius: 16px; padding: 1.1rem 1.2rem;
  background: rgba(128,128,128,.035); border-top: 4px solid var(--accent, rgba(128,128,128,.3)); }
.trs-tile-label { font-size: .85rem; opacity: .7; font-weight: 500; }
.trs-tile-value { font-size: 1.9rem; font-weight: 700; letter-spacing: -.02em; margin-top: .2rem; }
.trs-tile-note { font-size: .82rem; opacity: .65; margin-top: .1rem; }

.trs-pill { display: inline-block; font-size: .75rem; font-weight: 600; padding: .2rem .6rem;
  border-radius: 999px; color: var(--c); background: color-mix(in srgb, var(--c) 15%, transparent);
  border: 1px solid color-mix(in srgb, var(--c) 35%, transparent); white-space: nowrap; }

/* ---------- Banners ---------- */
.trs-banner { display: flex; gap: .75rem; align-items: flex-start; padding: .9rem 1.1rem;
  border-radius: 14px; border: 1px solid; margin: .4rem 0; line-height: 1.5; }
.trs-banner .trs-ico { margin-top: .15rem; }
.trs-banner code { font-size: .85em; }
.trs-banner-info { border-color: rgba(59,130,246,.35); background: rgba(59,130,246,.08); }
.trs-banner-info .trs-ico { color: #3b82f6; }
.trs-banner-warning { border-color: rgba(245,158,11,.4); background: rgba(245,158,11,.09); }
.trs-banner-warning .trs-ico { color: #f59e0b; }
.trs-banner-danger { border-color: rgba(208,59,59,.45); background: rgba(208,59,59,.09); }
.trs-banner-danger .trs-ico { color: #d03b3b; }
.trs-banner-success { border-color: rgba(16,185,129,.4); background: rgba(16,185,129,.08); }
.trs-banner-success .trs-ico { color: #10b981; }

/* ---------- Steps ---------- */
.trs-step-num { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; font-weight: 700; background: #2563eb; color: #fff; font-size: .9rem; }
.trs-step-label { display: flex; align-items: center; gap: .6rem; font-weight: 650; font-size: 1.05rem;
  margin-bottom: .3rem; }
.trs-step-label .trs-step-num { width: 26px; height: 26px; font-size: .8rem; }

/* ---------- Hero (home page) ---------- */
.st-key-hero { position: relative; overflow: hidden; isolation: isolate; border-radius: 28px;
  padding: 3.5rem 3rem 3rem !important; color: #f1f5f9;
  background: linear-gradient(135deg, #0b1f3a 0%, #102c57 55%, #1d4ed8 100%); }
/* Slowly drifting glow */
.st-key-hero::before { content: ""; position: absolute; inset: -40%; z-index: -1; pointer-events: none;
  background:
    radial-gradient(circle at 30% 30%, rgba(96,165,250,.45), transparent 22%),
    radial-gradient(circle at 72% 58%, rgba(14,165,233,.38), transparent 24%),
    radial-gradient(circle at 45% 85%, rgba(139,92,246,.30), transparent 22%);
  animation: trs-drift 22s ease-in-out infinite alternate; }
/* Moving grid, faded at the edges */
.st-key-hero::after { content: ""; position: absolute; inset: 0; z-index: -1; pointer-events: none;
  background-image: linear-gradient(rgba(255,255,255,.07) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.07) 1px, transparent 1px);
  background-size: 44px 44px;
  -webkit-mask-image: radial-gradient(ellipse at 70% 40%, #000 15%, transparent 70%);
  mask-image: radial-gradient(ellipse at 70% 40%, #000 15%, transparent 70%);
  animation: trs-grid 16s linear infinite; }
@keyframes trs-drift {
  0% { transform: translate(0, 0) rotate(0deg); }
  50% { transform: translate(7%, -5%) rotate(25deg); }
  100% { transform: translate(-6%, 5%) rotate(-15deg); } }
@keyframes trs-grid { to { background-position: 44px 44px, 44px 44px; } }

/* Radar graphic */
.trs-radar { position: relative; width: min(100%, 320px); aspect-ratio: 1; margin: 0 auto; }
.trs-ring { position: absolute; inset: 0; border-radius: 50%; border: 1px solid rgba(147,197,253,.22); }
.trs-ring.r2 { inset: 17%; } .trs-ring.r3 { inset: 34%; }
.trs-sweep { position: absolute; inset: 0; border-radius: 50%;
  background: conic-gradient(from 0deg, transparent 0deg, rgba(96,165,250,.38) 55deg, transparent 56deg);
  animation: trs-spin 6s linear infinite; }
.trs-pulse { position: absolute; inset: 38%; border-radius: 50%; border: 2px solid rgba(103,232,249,.55);
  animation: trs-pulse 3.2s ease-out infinite; }
.trs-pulse.d2 { animation-delay: 1.6s; }
.trs-blip { position: absolute; width: 10px; height: 10px; margin: -5px; border-radius: 50%;
  background: var(--c); box-shadow: 0 0 14px var(--c); opacity: 0;
  animation: trs-blip 6s ease-in-out infinite; animation-delay: var(--d); }
.trs-radar-core { position: absolute; inset: 39%; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; color: #fff; background: linear-gradient(135deg, #3b82f6, #1d4ed8);
  box-shadow: 0 0 40px rgba(59,130,246,.65); }
@keyframes trs-spin { to { transform: rotate(360deg); } }
@keyframes trs-pulse { from { transform: scale(1); opacity: .9; } to { transform: scale(3.4); opacity: 0; } }
@keyframes trs-blip { 0%, 100% { opacity: 0; transform: scale(.5); } 12%, 45% { opacity: 1; transform: scale(1); } 65% { opacity: 0; } }
@media (max-width: 640px) { .trs-radar { display: none; } }
@media (prefers-reduced-motion: reduce) {
  .st-key-hero::before, .st-key-hero::after, .trs-sweep, .trs-pulse, .trs-blip { animation: none; }
  .trs-blip { opacity: 1; } }
@media (max-width: 640px) { .st-key-hero { padding: 2rem 1.3rem !important; border-radius: 20px; } }
.trs-hero-badge { display: inline-flex; align-items: center; gap: .5rem; font-size: .82rem; font-weight: 500;
  padding: .35rem .85rem; border-radius: 999px; background: rgba(255,255,255,.1);
  border: 1px solid rgba(255,255,255,.2); color: #dbeafe; }
.trs-hero-title { font-size: clamp(2.1rem, 5vw, 3.6rem); font-weight: 700; line-height: 1.07;
  letter-spacing: -.03em; margin: 1.2rem 0 1rem; max-width: 820px; color: #f1f5f9; }
.trs-hero-title span { background: linear-gradient(90deg, #93c5fd, #67e8f9); -webkit-background-clip: text;
  background-clip: text; color: transparent; }
.trs-hero-sub { font-size: 1.15rem; line-height: 1.6; color: rgba(226,232,240,.85); max-width: 640px; margin: 0; }
.st-key-hero button[kind="secondary"], .st-key-hero [data-testid="stBaseButton-secondary"] {
  background: rgba(255,255,255,.08); color: #fff; border-color: rgba(255,255,255,.35); }
.st-key-hero button[kind="secondary"]:hover, .st-key-hero [data-testid="stBaseButton-secondary"]:hover {
  background: rgba(255,255,255,.16); color: #fff; border-color: #fff; }
.st-key-hero button { padding: .55rem 1.3rem; }

.trs-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem;
  margin-top: 2.2rem; padding-top: 1.8rem; border-top: 1px solid rgba(255,255,255,.15); }
.trs-stat-value { font-size: 2rem; font-weight: 700; letter-spacing: -.02em; color: #fff; }
.trs-stat-label { font-size: .88rem; color: rgba(226,232,240,.75); }

/* ---------- Result panel (investigate page) ---------- */
.trs-verdict { border-radius: 20px; padding: 1.6rem; border: 1px solid color-mix(in srgb, var(--c) 40%, transparent);
  background: linear-gradient(180deg, color-mix(in srgb, var(--c) 12%, transparent), transparent 70%); }
.trs-verdict-label { display: flex; align-items: center; gap: .5rem; font-weight: 650; color: var(--c); }
.trs-verdict-title { font-size: 1.8rem; font-weight: 700; letter-spacing: -.02em; margin: .4rem 0 1rem; }
.trs-score { display: flex; align-items: baseline; gap: .4rem; }
.trs-score b { font-size: 3rem; font-weight: 700; letter-spacing: -.03em; line-height: 1; }
.trs-meter { height: 10px; border-radius: 999px; background: rgba(128,128,128,.18); margin: .8rem 0 1.2rem;
  overflow: hidden; }
.trs-meter div { height: 100%; border-radius: 999px; background: var(--c); }
.trs-empty { border: 1.5px dashed rgba(128,128,128,.35); border-radius: 20px; padding: 2.5rem 1.5rem;
  text-align: center; }
.trs-empty .trs-card-icon { margin: 0 auto .8rem; }

/* ---------- Footer ---------- */
.trs-footer { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .5rem; margin-top: 4rem;
  padding-top: 1.4rem; border-top: 1px solid rgba(128,128,128,.2); font-size: .85rem; opacity: .6; }
</style>
"""

CSS = CSS.replace("</style>", _icon_css() + "\n</style>")
