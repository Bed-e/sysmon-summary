"""Upload handling: the POST endpoint, and saving, checking and parsing the file.

NiceGUI hands an uploaded file to its own handlers only through async methods,
which this project avoids. So the upload is a plain synchronous POST endpoint
on NiceGUI's FastAPI app (registered in app.py).
"""

import os
import secrets

from fastapi import UploadFile
from fastapi.responses import RedirectResponse

from parse import read_events
from web.config import EVTX_MAGIC, MAX_UPLOAD_BYTES, UPLOAD_DIR
from web.enrich_jobs import make_state
from web.runtime import UPLOADS


def save_and_parse(stream):
    """Copy an uploaded stream to a server-made file, parse it, delete it.

    Input: stream, a readable binary file object (the upload from FastAPI).
    Output: (parsed, error_code). parsed is read_events' dict, or None with
    error_code one of "size", "magic" or "read" (keys of UPLOAD_ERRORS).
    The user's file name is never used as a path. Used by: upload_endpoint.
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    path = os.path.join(UPLOAD_DIR, secrets.token_hex(8) + ".evtx")
    try:
        size = 0
        with open(path, "wb") as out:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    return None, "size"
                out.write(chunk)
        with open(path, "rb") as handle:
            if handle.read(len(EVTX_MAGIC)) != EVTX_MAGIC:
                return None, "magic"
        return read_events(path), ""
    except Exception:
        return None, "read"
    finally:
        if os.path.exists(path):
            os.remove(path)


def upload_endpoint(file: UploadFile | None = None):
    """POST /upload: the plain synchronous upload handler.

    Input: file, the form field "file" posted by the upload page's form.
    Output: a redirect: to /report/<id> on success, or to /?error=<code>
    (a key of UPLOAD_ERRORS). Parses, filters and ranks locally; no portal
    is called. The state is stored under a random upload id.
    Used by: the upload form on the start page.
    """
    if file is None or not file.filename:
        return RedirectResponse("/?error=none", status_code=303)
    if not file.filename.lower().endswith(".evtx"):
        return RedirectResponse("/?error=type", status_code=303)
    parsed, code = save_and_parse(file.file)
    if parsed is None:
        return RedirectResponse("/?error=" + code, status_code=303)
    upload_id = secrets.token_hex(8)
    UPLOADS[upload_id] = make_state(os.path.basename(file.filename), parsed)
    return RedirectResponse("/report/" + upload_id, status_code=303)
