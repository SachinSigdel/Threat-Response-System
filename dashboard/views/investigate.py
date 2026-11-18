"""Investigate one connection: pick a real example, change it, see the verdict."""

from html import escape

import pandas as pd
import streamlit as st

import common as c

c.keep_widget_state("inv_type", "inv_example")
st.session_state.setdefault("inv_type", "Any")
st.session_state.setdefault("inv_example", 1)

online = c.page_header(
    "Single connection", "Investigate a connection",
    "Pick a real connection, adjust any detail and see how the verdict changes.",
)
if not online:
    c.offline_notice()

if not c.OFFICIAL_TEST_PATH.exists():
    c.banner("The UNSW-NB15 test file was not found in the project folder, so there are no example "
             "connections to pick from.", "warning")
else:
    official = c.load_official_test()
    options = c.category_options()

    left, right = st.columns([3, 2], gap="large")

    with left:
        with st.container(border=True):
            c.html('<div class="trs-step-label"><span class="trs-step-num">1</span>Pick a connection</div>')
            col_type, col_example = st.columns(2)
            types = ["Any"] + official["attack_cat"].value_counts().index.tolist()
            col_type.selectbox("Show examples of", types, key="inv_type",
                               on_change=lambda: st.session_state.update(inv_example=1))
            chosen_type = st.session_state["inv_type"]
            matching = official.index if chosen_type == "Any" else \
                official.index[official["attack_cat"] == chosen_type]
            st.session_state["inv_example"] = min(st.session_state["inv_example"], len(matching))
            example = col_example.number_input(f"Example (1 to {len(matching):,})", 1, len(matching),
                                               step=1, key="inv_example")
            row_index = int(matching[int(example) - 1])
            row = official.loc[row_index]
            st.caption(f"Connection #{row_index:,} from the UNSW-NB15 test set · "
                       f"actually **{row['attack_cat']}**")

        with st.container(border=True):
            c.html('<div class="trs-step-label"><span class="trs-step-num">2</span>Adjust the details</div>')
            st.caption("Optional. Change any value to see how it affects the verdict.")
            payload = {}
            cat_cols = st.columns(3)
            labels = {"proto": "Protocol", "service": "Service", "state": "Connection state"}
            for col, name in zip(cat_cols, c.CATEGORICAL_FEATURES):
                choices = options[name]
                payload[name] = col.selectbox(labels[name], choices, index=choices.index(str(row[name])),
                                              key=f"{name}_{row_index}")

            numeric = row.drop(c.NON_FEATURE_COLUMNS + c.CATEGORICAL_FEATURES)
            with st.expander(f"All {len(numeric)} traffic measurements"):
                edited = st.data_editor(
                    pd.DataFrame({"feature": numeric.index, "value": numeric.astype(float).values}),
                    hide_index=True,
                    disabled=["feature"],
                    width="stretch",
                    height=400,
                    key=f"editor_{row_index}",
                    column_config={
                        "feature": "Measurement",
                        "value": st.column_config.NumberColumn("Value", min_value=0, required=True),
                    },
                )

            empty = edited.loc[edited["value"].isna(), "feature"].tolist()
            payload.update({name: float(value) for name, value in zip(edited["feature"], edited["value"])
                            if pd.notna(value)})

            if st.button("Check this connection", type="primary", icon=":material/search:",
                         disabled=not online, width="stretch"):
                if empty:
                    st.error(f"These values cannot be empty: {', '.join(empty)}")
                else:
                    result, error = c.call_api("POST", "/predict", json=payload)
                    if error:
                        st.error(error)
                    else:
                        st.session_state["single"] = {"row": row_index, "payload": payload, "result": result}

    with right:
        # Keep the last result on screen until a different connection is picked
        single = st.session_state.get("single")
        if not single or single["row"] != row_index:
            c.html(
                f'<div class="trs-empty"><div class="trs-card-icon">{c.icon("search")}</div>'
                '<div class="trs-card-title">No verdict yet</div>'
                '<p class="trs-muted">Click <b>Check this connection</b> to see whether it looks like an '
                'attack, how risky it is and what to do about it.</p></div>'
            )
        else:
            result = single["result"]
            if single["payload"] != payload:
                c.banner("You've changed some details since this check. Run it again to update the verdict.",
                         "warning")
            level, score = result["risk_level"], result["risk_score"]
            color = c.RISK_COLOR[level]
            is_attack = result["prediction"] == "Attack"
            title = f"{escape(result['attack_type'])} attack" if is_attack else "Looks like normal traffic"
            status = "Attack detected" if is_attack else "No attack detected"
            c.html(
                f'<div class="trs-verdict" style="--c:{color}">'
                f'<div class="trs-verdict-label">{c.icon("alert" if is_attack else "check")}{status}</div>'
                f'<div class="trs-verdict-title">{title}</div>'
                f'<div class="trs-card-head"><div class="trs-score"><b>{score:.0f}</b>'
                f'<span class="trs-muted">/ 100 risk</span></div>{c.risk_pill(level)}</div>'
                f'<div class="trs-meter"><div style="width:{score:.1f}%"></div></div>'
                f'<div class="trs-tile-label">Recommended action</div>'
                f'<div style="font-weight:600;line-height:1.5;margin-top:.3rem">{escape(result["recommended_action"])}</div>'
                '</div>'
            )
            actual = row["attack_cat"]
            if (actual == "Normal") == is_attack:
                verdict, tone = "The detector got it wrong.", "info"
            elif is_attack and result["attack_type"] != actual:
                verdict, tone = "The attack was caught, but given a different type.", "info"
            else:
                verdict, tone = "The detector got it right.", "success"
            c.banner(f"The real answer for this connection is <b>{escape(actual)}</b>. {verdict}", tone)
