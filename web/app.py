"""M5: the web app (NiceGUI), with tabs.

Run from the project folder:

    python -m web.app

Open http://127.0.0.1:5000. Upload a Sysmon .evtx dump: it is parsed,
filtered and ranked locally and the report is shown in five tabs:
Overview, IOCs, Storylines, Timeline and Skipped. NO portal is called until
the analyst presses "Enrich next N" or a row's Look up button. Then ONE
background thread looks up those IOCs, one at a time, highest rank first
(the same sequential loop as M3). "Next N" means the N highest-ranked IOCs
not tried yet, so pressing it twice with N=5 covers ranks 1-5, then 6-10.
A timer on the page updates the table and status in place as answers
arrive (no page reload).

Rules kept here (design.md section 7):
- The browser never sends an IOC value back. It sends only N or a row's
  rank number, so the server only ever looks up IOCs it ranked itself.
- Only hash lookups reach VirusTotal, so only they are counted and paced.
  The limits come from data/api_limits.txt; today's count is kept in
  data/hash_usage.txt so a restart does not reset it.
- Text from a dump is shown only through NiceGUI labels and tables, which
  escape it. The one piece of raw HTML (the upload form) is a fixed string.
- The server listens on 127.0.0.1 only.

NiceGUI hands an uploaded file to its own handlers only through async
methods, which this project avoids. So the upload is a plain synchronous
POST endpoint on NiceGUI's FastAPI app, and the page uses a basic HTML form.
"""

import os

from dotenv import load_dotenv
from nicegui import app, ui

from web.pages import report_page, upload_page
from web.upload import upload_endpoint


app.add_api_route("/upload", upload_endpoint, methods=["POST"])
ui.page("/")(upload_page)
ui.page("/report/{upload_id}")(report_page)


def main():
    """Start the web server on 127.0.0.1 (this machine only).

    The port is 5000 unless the PORT environment variable says otherwise.
    """
    load_dotenv()
    ui.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
           show=False, reload=False, title="Sysmon summary",
           storage_secret="sysmon-summary-local-theme")


if __name__ == "__main__":
    main()
