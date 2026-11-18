"""Landing page: what the product does and where to start."""

import streamlit as st

from common import html, icon, section_title

with st.container(key="hero"):
    text_col, art_col = st.columns([3, 2], vertical_alignment="center", gap="large")
    with text_col:
        html(
            '<div class="trs-hero-badge">● Machine learning for network defense</div>'
            '<div class="trs-hero-title">Find the attacks hiding in your <span>network traffic</span></div>'
            '<p class="trs-hero-sub">Threat Response checks every connection, names the type of attack, '
            'ranks it by risk and tells your team exactly what to do next, so the most dangerous '
            'traffic gets handled first.</p>'
        )
        with st.container(horizontal=True, gap="small"):
            if st.button("Analyze traffic", type="primary", icon=":material/arrow_forward:", icon_position="right"):
                st.switch_page("views/analyze.py")
            if st.button("Investigate a connection"):
                st.switch_page("views/investigate.py")
    with art_col:
        # Radar sweep with threats appearing and fading (pure CSS animation)
        blips = [("24%", "66%", "0s", "#f87171"), ("70%", "28%", "1.4s", "#fbbf24"),
                 ("62%", "78%", "2.8s", "#f87171"), ("30%", "30%", "4.2s", "#34d399"),
                 ("82%", "58%", "3.5s", "#fb923c")]
        html(
            '<div class="trs-radar"><div class="trs-ring"></div><div class="trs-ring r2"></div>'
            '<div class="trs-ring r3"></div><div class="trs-sweep"></div>'
            '<div class="trs-pulse"></div><div class="trs-pulse d2"></div>'
            + "".join(f'<i class="trs-blip" style="top:{t};left:{l};--d:{d};--c:{c}"></i>' for t, l, d, c in blips)
            + f'<div class="trs-radar-core">{icon("shield", 34)}</div></div>'
        )
    html(
        '<div class="trs-stats">'
        '<div><div class="trs-stat-value">99%</div><div class="trs-stat-label">of attacks caught on held-out test traffic</div></div>'
        '<div><div class="trs-stat-value">9</div><div class="trs-stat-label">attack types recognised</div></div>'
        '<div><div class="trs-stat-value">0–100</div><div class="trs-stat-label">risk score on every connection</div></div>'
        '<div><div class="trs-stat-value">10k</div><div class="trs-stat-label">connections per analysis</div></div>'
        '</div>'
    )

section_title("Everything a security team needs to triage traffic",
              "Four steps run on every connection you send in.")
FEATURES = [
    ("shield", "Detect", "Separates attacks from normal traffic using a Random Forest trained on 175,000 labelled connections."),
    ("tag", "Classify", "Names the attack, from reconnaissance scans and fuzzing to exploits, backdoors and worms."),
    ("gauge", "Score", "Gives each connection a 0–100 risk score and a level, from Low to Critical."),
    ("bolt", "Respond", "Recommends a clear next step for every attack type, ready for your team to act on."),
]
html('<div class="trs-grid trs-grid-4">' + "".join(
    f'<div class="trs-card"><div class="trs-card-icon">{icon(i)}</div>'
    f'<div class="trs-card-title">{t}</div><p>{d}</p></div>'
    for i, t, d in FEATURES
) + "</div>")

section_title("How it works")
STEPS = [
    ("Bring your traffic", "Upload a CSV of connection records, or try it straight away with a sample of real test traffic."),
    ("Review the alerts", "See how many connections are risky, which attacks they look like and which to handle first."),
    ("Take action", "Follow the recommended response for each attack type and download the full results."),
]
html('<div class="trs-grid trs-grid-cards">' + "".join(
    f'<div class="trs-card"><div class="trs-step-num">{n}</div>'
    f'<div class="trs-card-title">{t}</div><p>{d}</p></div>'
    for n, (t, d) in enumerate(STEPS, start=1)
) + "</div>")

section_title("Good to know")
html(
    '<div class="trs-card"><p>The detector is tuned to miss as few attacks as possible. On the official '
    'UNSW-NB15 test set it also flags about <b>28% of normal connections</b>, so treat alerts as a ranked '
    'to-do list for an analyst rather than an automatic block list. The models were trained on lab traffic '
    'from 2015 and should be retrained on your own network before production use.</p></div>'
)
