"""The two pages: the upload page ("/") and the report page ("/report/<id>").

The report page builds the header, the five tabs and the refresh timer; each
tab's content comes from web/tabs/.
"""

from nicegui import ui

from web.actions import refresh_view
from web.config import REFRESH_SECONDS, UPLOAD_ERRORS, UPLOAD_FORM
from web.enrich_jobs import progress_text, progress_value
from web.runtime import UPLOADS
from web.theme import apply_theme, build_header
from web.tabs.chains import build_chains_tab
from web.tabs.iocs import build_ioc_tab
from web.tabs.overview import build_overview_tab
from web.tabs.skipped import build_skipped_tab
from web.tabs.timeline import build_timeline_tab


def page_setup():
    """Set the title, the theme (colours, cards) and draw the top bar.

    Output: the theme dict from build_header ("is_dark" and "listeners"), so
    the report page can hand it to the tabs. The Light/Dark/System toggle in
    the bar replaces the old forced light page. The page content is centred
    and width-limited by the theme CSS. Used by: upload_page and report_page.
    """
    ui.page_title("Sysmon summary")
    apply_theme()
    return build_header()


def upload_page(error: str = ""):
    """The start page (route "/"): explanation, optional error, upload form.

    Input: error, the query value ?error=<code>; only keys of UPLOAD_ERRORS
    show a message, anything else is ignored.
    Output: draws the page. Nothing is sent to any portal by uploading.
    """
    page_setup()
    with ui.column().classes("app-card app-narrow"):
        ui.label("Upload a Sysmon dump").classes("app-title")
        ui.label("The .evtx file is read, filtered and ranked on this "
                 "machine.").classes("app-muted")
        ui.label("Nothing is sent to any portal until you press a Look up "
                 "button on the report page.").classes("app-muted")
        if error in UPLOAD_ERRORS:
            ui.label(UPLOAD_ERRORS[error]).classes("app-error")
        ui.html(UPLOAD_FORM, sanitize=False).classes("w-full")


def report_page(upload_id: str):
    """The report page (route "/report/<id>"): header, progress bar, five
    tabs, timer.

    Input: upload_id, from the URL; a key of UPLOADS.
    Output: draws the page. An unknown id (for example after a server
    restart) shows a message and a link to upload again. The process scores
    come from the state (worked out once at upload). The lookup progress bar
    sits under the file card so it shows on every tab; it is hidden until
    something has been queued, and refresh_view keeps it up to date.
    """
    theme = page_setup()
    state = UPLOADS.get(upload_id)
    if state is None:
        with ui.column().classes("app-card app-narrow"):
            ui.label("That report does not exist (the server may have "
                     "restarted).").classes("app-bad")
            ui.link("Upload again", "/")
        return
    view = {"state": state, "upload_id": upload_id,
            "process_scores": state["process_scores"],
            "seen": (state["version"], state["worker"]), "theme": theme}
    with ui.row().classes("app-card items-center justify-between"):
        ui.label("File: " + state["name"]).classes("app-title")
        ui.link("Upload another file", "/")
    text = progress_text(state)
    with ui.column().classes("app-card gap-1") as box:
        view["progress_text"] = ui.label(text)
        view["progress"] = ui.linear_progress(
            value=progress_value(state), show_value=False).props("rounded")
    box.set_visibility(bool(text))
    view["progress_box"] = box
    with ui.column().classes("app-card"):
        with ui.tabs().classes("w-full") as tabs:
            overview = ui.tab("Overview")
            iocs = ui.tab("IOCs")
            chain_tab = ui.tab("Chains")
            timeline = ui.tab("Timeline")
            skipped = ui.tab("Skipped")
        with ui.tab_panels(tabs, value=overview).classes("w-full"):
            with ui.tab_panel(overview).classes("p-0 gap-4"):
                build_overview_tab(view)
            with ui.tab_panel(iocs).classes("p-0 gap-4"):
                build_ioc_tab(view)
            with ui.tab_panel(chain_tab).classes("p-0 gap-4"):
                build_chains_tab(view)
            with ui.tab_panel(timeline).classes("p-0 gap-4"):
                build_timeline_tab(view)
            with ui.tab_panel(skipped).classes("p-0 gap-4"):
                build_skipped_tab(view)
    view["timer"] = ui.timer(REFRESH_SECONDS, lambda: refresh_view(view),
                             active=(state["worker"] == "running"))
