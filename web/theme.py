"""Theme: the page look (colours, cards) and the Light / Dark / System toggle.

Nothing here touches dump data. The CSS is one fixed string, so the rule
"text from a dump only goes through escaping widgets" still holds.
"""

from nicegui import app, ui

# Toggle choices: stored key -> button label.
THEME_CHOICES = {"light": "Light", "dark": "Dark", "system": "System"}

# Stored key -> value for ui.dark_mode (None means "follow the system").
DARK_VALUES = {"light": False, "dark": True, "system": None}

DEFAULT_THEME = "system"

# Asks the browser whether the system prefers dark, now and whenever it
# changes, and sends the answer to the server as a "system_theme" event.
SYSTEM_WATCHER_JS = (
    "const q = window.matchMedia('(prefers-color-scheme: dark)');"
    "emitEvent('system_theme', q.matches);"
    "q.addEventListener('change', e => emitEvent('system_theme', e.matches));")

THEME_CSS = """
:root {
  --app-bg: #f3f5f9;
  --app-card: #ffffff;
  --app-border: #dde2ea;
  --app-text: #1f2937;
  --app-muted: #6b7280;
  --app-accent-soft: #e8efff;
  --app-warn-bg: #fff6dc;
  --app-warn-border: #e0b44c;
  --app-bad: #b42318;
  --app-bad-bg: #fdecea;
  --app-primary: #3b6fd6;
  --app-shadow: 0 1px 2px rgba(16, 24, 40, 0.06);
}
body.body--dark {
  --app-bg: #0f1420;
  --app-card: #182030;
  --app-border: #2a3446;
  --app-text: #e5e9f0;
  --app-muted: #9aa5b8;
  --app-accent-soft: #22304f;
  --app-warn-bg: #3a3017;
  --app-warn-border: #8a6d1f;
  --app-bad: #ff8a80;
  --app-bad-bg: #3d1f1f;
  --app-primary: #6c93ec;
  --app-shadow: none;
}
body, .q-page { background: var(--app-bg); color: var(--app-text); }
.nicegui-content { max-width: 72rem; margin: 0 auto; width: 100%; gap: 1rem; }
.app-header { background: var(--app-card) !important; color: var(--app-text) !important;
  border-bottom: 1px solid var(--app-border); }
.app-card { background: var(--app-card); border: 1px solid var(--app-border);
  border-radius: 12px; box-shadow: var(--app-shadow); padding: 1rem 1.25rem; width: 100%; }
.app-muted { color: var(--app-muted); font-size: 0.875rem; }
.app-bad { color: var(--app-bad); font-weight: 600; }
.app-error { background: var(--app-bad-bg); color: var(--app-bad); font-weight: 600;
  border: 1px solid var(--app-bad); border-radius: 8px; padding: 0.5rem 1rem; width: 100%; }
.app-narrow { max-width: 36rem; margin: 1.5rem auto 0; }
.upload-form { display: flex; flex-direction: column; gap: 1rem; width: 100%; }
.upload-drop { display: flex; flex-direction: column; gap: 0.5rem; align-items: center;
  padding: 1.5rem 1rem; border: 2px dashed var(--app-border); border-radius: 12px;
  background: var(--app-accent-soft); cursor: pointer; text-align: center; }
.upload-drop:hover { border-color: var(--app-primary); }
.upload-drop-title { font-weight: 600; }
.upload-drop input[type=file] { max-width: 100%; color: var(--app-muted); }
.upload-drop input[type=file]::file-selector-button { margin-right: 0.75rem; padding: 0.4rem 0.9rem;
  border: 1px solid var(--app-border); border-radius: 6px; background: var(--app-card);
  color: var(--app-text); cursor: pointer; }
.upload-button { padding: 0.65rem 1rem; border: 0; border-radius: 8px; cursor: pointer;
  background: var(--app-primary); color: #ffffff; font-weight: 600; font-size: 1rem; }
.upload-button:hover { filter: brightness(1.1); }
.count-grid { display: grid; gap: 0.75rem; width: 100%;
  grid-template-columns: repeat(auto-fill, minmax(11rem, 1fr)); }
.count-tile { background: var(--app-card); border: 1px solid var(--app-border);
  border-radius: 12px; padding: 0.75rem 1rem; gap: 0.1rem; box-shadow: var(--app-shadow); }
.count-value { font-size: 1.9rem; font-weight: 700; line-height: 1.1; }
.count-title { font-weight: 600; }
.app-card .q-tab-panels { background: transparent; }
.app-badge { display: inline-block; min-width: 2.2rem; text-align: center; font-weight: 700;
  font-size: 0.8rem; border-radius: 999px; padding: 0.1rem 0.6rem; }
.app-badge-normal { background: #e5e7eb; color: #374151; }
.app-badge-flagged { background: #fde7c0; color: #8a5300; }
.app-badge-high { background: #fbd5d1; color: #9b1c12; }
body.body--dark .app-badge-normal { background: #374151; color: #e5e7eb; }
body.body--dark .app-badge-flagged { background: #5a3d0a; color: #fbd38d; }
body.body--dark .app-badge-high { background: #5c1f1a; color: #ffb4ab; }
.ioc-head { font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.04em; color: var(--app-muted); padding: 0.4rem 1rem 0.4rem 0;
  border-bottom: 2px solid var(--app-border); }
.ioc-cell { padding: 0.5rem 1rem 0.5rem 0; border-bottom: 1px solid var(--app-border); }
.app-section { font-weight: 700; margin-top: 0.5rem; }
.chain-card { padding: 0.25rem 0.75rem; }
.chain-node { border-left: 3px solid var(--app-border); padding: 0.25rem 0 0.25rem 0.75rem;
  margin: 0.25rem 0; gap: 0.15rem; }
.chain-plain { color: var(--app-muted); font-size: 0.85rem; }
.process-cmd { font-family: ui-monospace, Consolas, monospace; font-size: 0.8rem;
  word-break: break-all; }
.app-notice { background: var(--app-warn-bg); border-left: 4px solid var(--app-warn-border);
  border-radius: 8px; padding: 0.5rem 1rem; width: 100%; }
.app-title { font-size: 1.15rem; font-weight: 700; }
.app-card .q-table__card, .app-card .q-tab-panels, .app-card .q-tab-panel,
.app-card .q-expansion-item { background: transparent; color: var(--app-text); }
"""


def resolve_dark(mode: str, system_dark: bool) -> bool:
    """Work out whether the page is dark right now.

    Input: mode, one of "light", "dark", "system" (the toggle's stored key);
    system_dark, True when the browser reports that the system prefers dark.
    Output: True for a dark page, False for a light one. "system" follows
    system_dark; anything unknown counts as "system".
    Used by: build_header (to tell the timeline chart which colours to use).
    """
    if mode == "dark":
        return True
    if mode == "light":
        return False
    return bool(system_dark)


def apply_theme():
    """Set the colours and the shared card styles for this page.

    Input: none. Output: nothing. Sets NiceGUI's brand colours and adds the
    fixed CSS block (light colours, dark overrides under body.body--dark, and
    the .app-card / .app-notice / .app-muted classes). Used by: page_setup,
    on every page, so later milestones can use those classes anywhere.
    """
    ui.colors(primary="#3b6fd6", secondary="#14a3a3", accent="#8a4fd6",
              negative="#b42318", positive="#2e7d32", warning="#c9a227")
    ui.add_css(THEME_CSS)


def build_header():
    """Draw the top bar: app title on the left, Light/Dark/System on the right.

    Input: none. The saved choice is read from app.storage.user["theme"]
    (default "system"). That store is kept per browser on the server (in the
    .nicegui folder; the browser's cookie is read-only once a page is sent),
    so the choice survives reloads and applies on every page.
    Output: a "theme" dict that the rest of the page can use:
    - "is_dark": True when the page is dark right now;
    - "listeners": functions called (with no arguments) after is_dark changes;
      the timeline tab adds one so its chart can be redrawn in new colours.
    Choosing a button saves the choice, sets ui.dark_mode (False, True, or
    None to follow the system) and tells the listeners. A small script reports
    the system preference so "System" works for the chart too.
    Used by: page_setup; the returned dict goes to the report tabs.
    """
    mode = app.storage.user.get("theme", DEFAULT_THEME)
    if mode not in THEME_CHOICES:
        mode = DEFAULT_THEME
    dark = ui.dark_mode(DARK_VALUES[mode])
    theme = {"mode": mode, "system_dark": False, "is_dark": False,
             "listeners": []}

    def update():
        theme["is_dark"] = resolve_dark(theme["mode"], theme["system_dark"])
        for listener in theme["listeners"]:
            listener()

    def choose(event):
        theme["mode"] = event.value
        app.storage.user["theme"] = event.value
        dark.value = DARK_VALUES[event.value]
        update()

    def system_changed(event):
        theme["system_dark"] = bool(event.args)
        update()

    ui.on("system_theme", system_changed)
    ui.run_javascript(SYSTEM_WATCHER_JS)
    with ui.header(elevated=False).classes("app-header items-center justify-between"):
        ui.label("Sysmon summary").classes("app-title")
        ui.toggle(THEME_CHOICES, value=mode, on_change=choose) \
            .props("no-caps unelevated dense")
    theme["is_dark"] = resolve_dark(mode, False)
    return theme
