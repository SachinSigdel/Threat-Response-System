"""Streamlit website for the Threat Response System.

The site sends traffic to the FastAPI service and shows the results.
Start the API first, then run from the Threat_Response_System folder:
    .venv/bin/streamlit run dashboard/app.py
"""

import streamlit as st

import common

st.set_page_config(
    page_title="Threat Response",
    page_icon=str(common.ASSETS / "icon.svg"),
    layout="wide",
    initial_sidebar_state="collapsed",
)
st.logo(str(common.ASSETS / "logo.svg"), size="large")
common.html(common.CSS)

pages = [
    st.Page("views/home.py", title="Home", icon=":material/home:", default=True),
    st.Page("views/analyze.py", title="Analyze traffic", icon=":material/query_stats:", url_path="analyze"),
    st.Page("views/investigate.py", title="Investigate", icon=":material/search:", url_path="investigate"),
    st.Page("views/playbook.py", title="Playbook", icon=":material/menu_book:", url_path="playbook"),
]
st.navigation(pages, position="top").run()
common.footer()
