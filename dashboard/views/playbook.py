"""Response playbook: how risk is scored and what to do for each attack type."""

from html import escape

import common as c

online = c.page_header(
    "Playbook", "Response playbook",
    "How risk scores are worked out, and the recommended response for every attack type.",
)

try:
    info = c.get_model_info(c.api_url())
except c.APIError:
    c.offline_notice()
else:
    c.section_title("Risk levels", "Every connection gets a 0–100 score: how sure the detector is that it is an attack.")
    meaning = {
        "Low": "Very likely normal. No action needed.",
        "Medium": "Worth a look when there is time.",
        "High": "Probably an attack. Review soon.",
        "Critical": "Almost certainly an attack. Act now.",
    }
    c.html('<div class="trs-grid trs-grid-tiles">' + "".join(
        f'<div class="trs-tile" style="--accent:{c.RISK_COLOR[level]}">'
        f'<div class="trs-card-head"><b>{escape(level)}</b>{c.risk_pill(escape(rng))}</div>'
        f'<div class="trs-tile-note" style="margin-top:.6rem;font-size:.9rem">{meaning.get(level, "")}</div></div>'
        for level, rng in info["risk_levels"].items()
    ) + "</div>")

    c.section_title("Response by attack type")
    c.html('<div class="trs-grid trs-grid-cards">' + "".join(
        f'<div class="trs-card"><div class="trs-card-icon">{c.icon("shield")}</div>'
        f'<div class="trs-card-title">{escape(name)}</div><p>{escape(action)}</p></div>'
        for name, action in info["response_actions"].items()
    ) + "</div>")

    st_note = (f"A connection is flagged as an attack when the detector is at least "
               f"{info['attack_threshold']:.0%} sure. Models: {info['detector']}; {info['attack_type_model']}.")
    c.html(f'<p class="trs-muted" style="margin-top:1.2rem;font-size:.9rem">{escape(st_note)}</p>')
