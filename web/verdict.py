"""The soft verdict on the Overview tab (design.md section 8).

Kept in its own module: it needs chain_title (chain_summary) and
score_level (timeline_data), and timeline_data already imports
chain_summary, so putting it in either would make an import cycle.
"""

from web.config import VERDICT_LABELS
from web.chain_summary import chain_title
from web.timeline_data import score_level


def make_verdict(chains):
    """Work out the soft verdict for one dump from its chains.

    Input: chains, state["chains"] from chains.build_chains (the
    chains are already sorted highest score first).
    Output: {"label", "level", "reason"}. level is score_level of the
    highest chain score ("normal" 0, "flagged" 1 to 39, "high" 40+), the
    same bands as the score badges; label is its VERDICT_LABELS text
    ("Likely safe", "Suspicious", "Likely compromised"). reason names the
    strongest chain and its score, or says how many process trees had
    nothing flagged. Portal answers are not read: they never move the
    verdict.
    Used by: build_overview_tab.
    """
    if not chains["chains"]:
        level = "normal"
        reason = "Nothing was flagged in %d process trees." % len(chains["other"])
    else:
        top = chains["chains"][0]
        level = score_level(top["score"])
        reason = "Strongest chain: #1 %s, score %d." % (
            chain_title(chains["table"], top["title_finding"]), top["score"])
    return {"label": VERDICT_LABELS[level], "level": level, "reason": reason}
