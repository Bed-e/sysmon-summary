"""The two pages: the upload page ("/") and the report page ("/report/<id>").

The report page builds the header, the five tabs and the refresh timer; each
tab's content comes from web/tabs/.
"""

from nicegui import ui

from scoring.processes import build_process_scores
from web.actions import refresh_view
from web.config import REFRESH_SECONDS, UPLOAD_ERRORS, UPLOAD_FORM
from web.runtime import UPLOADS
from web.tabs.iocs import build_ioc_tab
from web.tabs.overview import build_overview_tab
from web.tabs.skipped import build_skipped_tab
from web.tabs.storylines import build_storylines_tab
from web.tabs.timeline import build_timeline_tab


def page_setup():
    """Set the title and force a light page (dark text on a white page).

    Output: nothing. Without it a browser that prefers dark mode shows dark
    text on a dark canvas. Used by: upload_page and report_page.
    """
    ui.page_title("Sysmon summary")
    ui.dark_mode(False)
    ui.query("body").style("background-color: white")


def upload_page(error: str = ""):
    """The start page (route "/"): explanation, optional error, upload form.

    Input: error, the query value ?error=<code>; only keys of UPLOAD_ERRORS
    show a message, anything else is ignored.
    Output: draws the page. Nothing is sent to any portal by uploading.
    """
    page_setup()
    ui.label("Sysmon summary").classes("text-3xl font-bold")
    ui.label("Upload a Sysmon .evtx dump. It is read, filtered and ranked on "
             "this machine. No portal is called until you press "
             "\"Enrich next N\" or a Look up button on the report page.")
    if error in UPLOAD_ERRORS:
        ui.label(UPLOAD_ERRORS[error]).classes("text-red-700 font-bold")
    ui.html(UPLOAD_FORM, sanitize=False)


def report_page(upload_id: str):
    """The report page (route "/report/<id>"): header, five tabs, timer.

    Input: upload_id, from the URL; a key of UPLOADS.
    Output: draws the page. An unknown id (for example after a server
    restart) shows a message and a link to upload again. The process scores
    are worked out once here for the storylines and the timeline.
    """
    page_setup()
    state = UPLOADS.get(upload_id)
    if state is None:
        ui.label("That report does not exist (the server may have "
                 "restarted).").classes("text-red-700 font-bold")
        ui.link("Upload again", "/")
        return
    view = {"state": state, "upload_id": upload_id,
            "process_scores": build_process_scores(state["events"]),
            "seen": (state["version"], state["run"])}
    ui.label("Sysmon summary").classes("text-3xl font-bold")
    ui.label("File: " + state["name"])
    with ui.tabs() as tabs:
        overview = ui.tab("Overview")
        iocs = ui.tab("IOCs")
        stories = ui.tab("Storylines")
        timeline = ui.tab("Timeline")
        skipped = ui.tab("Skipped")
    with ui.tab_panels(tabs, value=overview).classes("w-full"):
        with ui.tab_panel(overview):
            build_overview_tab(view)
        with ui.tab_panel(iocs):
            build_ioc_tab(view)
        with ui.tab_panel(stories):
            build_storylines_tab(view)
        with ui.tab_panel(timeline):
            build_timeline_tab(view)
        with ui.tab_panel(skipped):
            build_skipped_tab(view)
    view["timer"] = ui.timer(REFRESH_SECONDS, lambda: refresh_view(view),
                             active=(state["run"] == "running"))
