"""Path signals: file names, user-writable folders, double extensions and odd
parent-to-child process pairs.
"""

from scoring.config import (DECOY_EXTENSIONS, DOCUMENT_VIEWERS,
    EXECUTABLE_EXTENSIONS, SCRIPT_HOSTS, USER_WRITABLE_MARKERS,
    WEIGHT_DOUBLE_EXTENSION, WEIGHT_ODD_PARENT, WEIGHT_USER_WRITABLE_PATH)


def lower_path(path):
    """Lowercase a path and use backslashes, so matching is predictable."""
    return path.lower().replace("/", "\\")


def file_name(path):
    """Lowercased last part of a path: 'C:\\A\\Word.EXE' gives 'word.exe'."""
    return lower_path(path).split("\\")[-1]


def name_without_exe(path):
    """Like file_name but without a trailing .exe: 'winword'."""
    name = file_name(path)
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def is_user_writable(path):
    """True if the lowercased path contains a user-writable marker."""
    lowered = lower_path(path)
    return any(marker in lowered for marker in USER_WRITABLE_MARKERS)


def path_signals(path):
    """User-writable location and double extension (e.g. report.pdf.exe)."""
    signals = []
    if path == "":
        return signals

    if is_user_writable(path):
        signals.append((WEIGHT_USER_WRITABLE_PATH,
                        "file runs from a user-writable path (%s)" % path))

    parts = file_name(path).split(".")
    if len(parts) >= 3 and parts[-1] in EXECUTABLE_EXTENSIONS \
            and parts[-2] in DECOY_EXTENSIONS:
        signals.append((WEIGHT_DOUBLE_EXTENSION,
                        "double extension (.%s.%s)" % (parts[-2], parts[-1])))
    return signals


def parent_child_signal(parent_image, image):
    """Odd parent-to-child pairs. Matches on lowercased file names.
    1. A document viewer / Office app starts any .exe or a script host.
    2. explorer.exe starts something from a Temp folder.
    3. services.exe starts something from a user-writable path.
    An empty parent or child fires nothing.
    """
    if parent_image == "" or image == "":
        return []

    parent = name_without_exe(parent_image)
    child_file = file_name(image)
    child = name_without_exe(image)
    shown = "%s -> %s" % (file_name(parent_image), child_file)
    signals = []

    if parent in DOCUMENT_VIEWERS and (child_file.endswith(".exe")
                                       or child in SCRIPT_HOSTS):
        signals.append((WEIGHT_ODD_PARENT,
                        "document app started a program (%s)" % shown))
    elif parent == "explorer" and "\\temp\\" in lower_path(image):
        signals.append((WEIGHT_ODD_PARENT,
                        "explorer started a program from Temp (%s)" % shown))
    elif parent == "services" and is_user_writable(image):
        signals.append((WEIGHT_ODD_PARENT,
                        "service started a program from a user-writable "
                        "path (%s)" % shown))
    return signals
