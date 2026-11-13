"""Scoring settings: the weights, thresholds and word lists the signals use.

All the numbers are placeholders to tune freely. Every signal module imports
its settings from here, so a number is changed in exactly one place.
"""

# ---- Weights (placeholders, tune freely) ----
WEIGHT_USER_WRITABLE_PATH = 20
WEIGHT_DOUBLE_EXTENSION = 50  # disguise has no benign use: heaviest single signal
WEIGHT_ODD_PARENT = 25
WEIGHT_REGISTRY_AUTORUN = 40
WEIGHT_FAILED_LOOKUPS = 15
WEIGHT_RARE_NETWORK_PROCESS = 20
WEIGHT_UNUSUAL_PORT = 10
WEIGHT_BEACONING = 25
WEIGHT_ODD_DNS_LABEL = 20
WEIGHT_LOOKALIKE = 30
WEIGHT_REGISTRY_REFERENCE = 40
WEIGHT_ENUMERATION = 30

# ---- Thresholds (placeholders) ----
FAILED_LOOKUP_MIN = 5          # failed lookups by one process
LONG_LABEL_LENGTH = 30         # a DNS label this long is odd
ENTROPY_MIN_LENGTH = 12        # entropy is only judged on labels this long
ENTROPY_THRESHOLD = 3.5        # bits per character
LOOKALIKE_MAX_DISTANCE = 2     # edits away from a well-known name
BEACON_MIN_COUNT = 5           # connections needed to judge timing
BEACON_MIN_MEAN_GAP = 1.0      # seconds; faster than this is just a busy link
BEACON_MAX_SPREAD = 0.2        # (largest gap - smallest gap) / mean gap
ENUM_MIN_COUNT = 3             # discovery commands from one parent ...
ENUM_WINDOW_SECONDS = 300      # ... started within this many seconds

# ---- Lists (lowercase) ----
# One definition of "user-writable", used by path_signals and rule 3 of
# parent_child_signal.
USER_WRITABLE_MARKERS = ["\\temp\\", "\\downloads\\", "\\users\\"]

# A double extension is a document/media name followed by an executable one.
DECOY_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
                    "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "avi",
                    "zip"]
EXECUTABLE_EXTENSIONS = ["exe", "scr", "com", "bat", "cmd", "js", "vbs", "ps1"]

# Names (without .exe) of programs that rarely have a reason to reach the
# internet, but that attackers use to download files or call home. An
# outbound connection from one of them is a finding. Normal programs
# (browsers, OneDrive, Teams, svchost) are not listed, so they never fire.
RARE_NETWORK_PROCESSES = ["powershell", "pwsh", "cmd", "wscript", "cscript",
                          "mshta", "rundll32", "regsvr32", "certutil",
                          "bitsadmin", "msiexec", "installutil", "regasm",
                          "regsvcs", "msbuild"]

DOCUMENT_VIEWERS = ["winword", "excel", "powerpnt", "outlook", "acrord32",
                    "acrobat", "foxitreader"]
SCRIPT_HOSTS = ["cmd", "powershell", "wscript", "cscript", "mshta"]

# A registry key containing one of these is an autorun location. The Run
# and RunOnce markers end in a backslash so they match only those keys
# themselves: "\currentversion\run" alone would also match unrelated keys
# such as RunNotification (toast settings, not an autorun).
AUTORUN_MARKERS = ["\\currentversion\\run\\",
                   "\\currentversion\\runonce\\",
                   "\\currentversion\\runonceex\\",
                   "\\currentversion\\runservices\\",
                   "\\currentversion\\runservicesonce\\",
                   "\\windows nt\\currentversion\\winlogon\\shell",
                   "\\windows nt\\currentversion\\winlogon\\userinit"]

# Image File Execution Options is only a hijack when a Debugger value is
# set (other values there, such as AuditLevel, are normal settings).
IFEO_MARKER = "\\image file execution options\\"
IFEO_HIJACK_VALUE = "\\debugger"

# Programs (without .exe) an attacker runs to look around a machine. A burst
# of them from one parent is the enumeration finding.
DISCOVERY_COMMANDS = ["whoami", "ipconfig", "net", "net1", "systeminfo",
                      "nltest", "tasklist", "netstat", "quser", "query",
                      "arp", "route", "hostname", "nslookup", "dsquery",
                      "klist", "cmdkey", "wmic"]

NORMAL_PORTS = ["80", "443", "53"]
REGISTRY_EVENT_IDS = [12, 13, 14]
