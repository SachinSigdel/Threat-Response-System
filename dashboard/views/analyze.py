"""Analyze a batch of traffic: choose traffic, run the models, review alerts."""

import hashlib
from html import escape

import pandas as pd
import streamlit as st

import common as c

SAMPLE, UPLOAD = "Sample real traffic", "Upload a CSV"

c.keep_widget_state("source", "n_rows", "seed", "levels")
# Starting values for the widgets (set here so they survive page changes)
for key, value in {"source": SAMPLE if c.OFFICIAL_TEST_PATH.exists() else UPLOAD,
                   "n_rows": 2_000, "seed": 42, "levels": ["High", "Critical"]}.items():
    st.session_state.setdefault(key, value)

online = c.page_header(
    "Batch analysis", "Analyze traffic",
    "Upload connection records or sample real test traffic. Every connection is checked, "
    "scored for risk and matched with a response.",
)
if not online:
    c.offline_notice()


# ---------------- Step 1: choose traffic ----------------

with st.container(border=True):
    c.html('<div class="trs-step-label"><span class="trs-step-num">1</span>Choose your traffic</div>')
    sources = [SAMPLE, UPLOAD] if c.OFFICIAL_TEST_PATH.exists() else [UPLOAD]
    source = st.segmented_control("Traffic source", sources, key="source",
                                  label_visibility="collapsed") or sources[0]

    # traffic_key identifies the current input, so old results can be marked as out of date
    traffic, traffic_key = None, None
    if source == UPLOAD:
        uploaded = st.file_uploader(
            "CSV file with the 42 UNSW-NB15 feature columns. Extra columns are ignored.", type="csv"
        )
        if uploaded is not None:
            data = uploaded.getvalue()
            try:
                traffic = c.read_uploaded_csv(data)
                traffic_key = ("upload", hashlib.sha1(data).hexdigest())
            except Exception:
                st.error("We couldn't read this file as a CSV.")
            if traffic is not None and traffic.empty:
                st.error("This CSV file has no rows.")
                traffic, traffic_key = None, None
    else:
        st.caption("A random sample from the UNSW-NB15 test set. It includes the true answers, "
                   "so you can see how accurate the detector is.")
        col_rows, col_seed = st.columns([3, 1])
        n_rows = col_rows.slider("Number of connections", 100, 10_000, step=100, key="n_rows")
        seed = int(col_seed.number_input("Sample number", step=1, key="seed",
                                         help="Change this to draw a different random sample."))
        traffic = c.sample_official_test(n_rows, seed)
        traffic_key = ("sample", n_rows, seed)

    run = st.button("Run analysis", type="primary", icon=":material/play_arrow:",
                    disabled=traffic is None or not online)
    if run:
        results, error = c.analyze_traffic(traffic)
        if error:
            st.error(error)
        else:
            # Keep the results so filters and page changes do not re-run the analysis
            st.session_state["batch"] = {
                "key": traffic_key, "traffic": traffic.reset_index(drop=True), "results": results,
            }

batch = st.session_state.get("batch")
if not batch:
    c.html(
        f'<div class="trs-empty" style="margin-top:1.5rem"><div class="trs-card-icon">{c.icon("chart")}</div>'
        '<div class="trs-card-title">Your results will appear here</div>'
        '<p class="trs-muted">Choose some traffic above and click <b>Run analysis</b>.</p></div>'
    )
else:
    # ---------------- Step 2: results ----------------

    traffic_done, results = batch["traffic"], batch["results"]
    summary = c.summarize(results)
    levels = summary["risk_levels"]

    c.section_title("Results", f"{summary['total_connections']:,} connections analyzed")
    if traffic_key is not None and batch["key"] != traffic_key:
        c.banner("Your traffic settings have changed since this analysis, so these results are for the "
                 "previous traffic. Click <b>Run analysis</b> to update them.", "warning")
    if levels["Critical"]:
        c.banner(f"<b>{levels['Critical']:,} critical alerts</b> need attention. They are listed first below.",
                 "danger")
    elif summary["attacks_detected"] == 0:
        c.banner("<b>No attacks detected</b> in this traffic.", "success")

    c.stat_tiles([
        ("Connections checked", f"{summary['total_connections']:,}", None, None),
        ("Attacks detected", f"{summary['attacks_detected']:,}", f"{summary['attack_rate']:.1%} of traffic", "#2563eb"),
        ("Critical alerts", f"{levels['Critical']:,}", "Risk score 85 or more", c.RISK_COLOR["Critical"]),
        ("High alerts", f"{levels['High']:,}", "Risk score 60 to 85", c.RISK_COLOR["High"]),
    ])

    st.write("")
    col_a, col_b = st.columns(2)
    with col_a, st.container(border=True):
        st.markdown("**Connections by risk level**")
        st.altair_chart(c.risk_level_chart(levels), width="stretch")
    with col_b, st.container(border=True):
        st.markdown("**Detected attack types**")
        if summary["attack_types"]:
            st.altair_chart(c.attack_type_chart(summary["attack_types"]), width="stretch")
        else:
            st.info("No attacks detected.")

    # If the file has the real answers, show how well the detector did
    if "label" in traffic_done.columns:
        actual = traffic_done["label"].astype(int).values == 1
        flagged = (results["prediction"] == "Attack").values
        c.section_title("How accurate was it?", "This traffic includes the true answers, so we can check every prediction.")
        c.stat_tiles([
            ("Correct", f"{(actual == flagged).mean():.1%}", "of all connections", "#10b981"),
            ("Attacks caught", f"{flagged[actual].mean():.1%}" if actual.any() else "-",
             "of real attacks were flagged", "#10b981"),
            ("False alarms", f"{flagged[~actual].mean():.1%}" if (~actual).any() else "-",
             "of normal connections were flagged", "#f59e0b"),
        ])

    # ---------------- Step 3: what to do ----------------

    context_cols = [col for col in ["proto", "service", "state", "sbytes", "dbytes", "attack_cat"]
                    if col in traffic_done.columns]
    table = pd.concat([traffic_done[context_cols], results], axis=1).rename(columns={"attack_cat": "actual_type"})

    attacks = table[table["prediction"] == "Attack"]
    if not attacks.empty:
        c.section_title("What to do", "One recommended response per attack type, most common first.")
        groups = (attacks.groupby("attack_type")
                  .agg(count=("risk_score", "size"), typical=("risk_score", "median"),
                       action=("recommended_action", "first"))
                  .sort_values("count", ascending=False))
        cards = []
        for name, row in groups.iterrows():
            # Pill shows the risk level of a typical connection of this type
            level = c.RISK_LEVELS[sum(row["typical"] >= cut for cut in (30, 60, 85))]
            count = int(row["count"])
            cards.append(
                f'<div class="trs-card"><div class="trs-card-head"><b>{escape(name)}</b>{c.risk_pill(level)}</div>'
                f'<div class="trs-card-count">{count:,}<span>connection{"s" if count != 1 else ""}</span></div>'
                f'<div class="trs-card-action">{escape(row["action"])}</div></div>'
            )
        c.html(f'<div class="trs-grid trs-grid-cards">{"".join(cards)}</div>')

    c.section_title("Alerts", "Every flagged connection, highest risk first.")
    c.banner("The detector is tuned to miss as few attacks as possible, so it also flags about 28% of "
             "normal connections. Check alerts before acting on them.", "info")
    chosen_levels = st.multiselect("Show risk levels", c.RISK_LEVELS, key="levels")
    alerts = table[table["risk_level"].isin(chosen_levels)].sort_values("risk_score", ascending=False)

    with st.container(horizontal=True, vertical_alignment="center"):
        st.markdown(f"**{len(alerts):,}** connections")
        st.download_button("Download all results", table.to_csv(index=False).encode(),
                           file_name="threat_analysis_results.csv", mime="text/csv",
                           icon=":material/download:", width="content")
    st.dataframe(
        alerts.drop(columns="recommended_action"),
        width="stretch",
        hide_index=True,
        column_config={
            "proto": "Protocol",
            "service": "Service",
            "state": "State",
            "sbytes": st.column_config.NumberColumn("Bytes sent", format="localized"),
            "dbytes": st.column_config.NumberColumn("Bytes received", format="localized"),
            "actual_type": "Actual type",
            "prediction": "Prediction",
            "attack_type": "Attack type",
            "risk_level": "Risk level",
            "risk_score": st.column_config.ProgressColumn(
                "Risk score", min_value=0, max_value=100, format="%.1f"
            ),
        },
    )
