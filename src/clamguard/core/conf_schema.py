"""A typed catalogue of every ClamAV configuration option we can edit.

The Configuration page is generated entirely from this table: the input widget,
the validation, the grouping and the search index all come from here. Adding a
new option to the UI means adding one `opt(...)` line and nothing else.

What this file deliberately does *not* contain is help text. ClamAV ships an
excellent description of every option as comments inside clamd.conf and
freshclam.conf, and `ConfFile.documentation()` reads it at runtime, so the help
you see always matches the installed version. The `hint` field here is only for
the occasional extra warning ClamGuard wants to add on top.

The option list was taken from `clamconf` on ClamAV 1.5.x. Options unknown to
an older or newer ClamAV simply do not appear in that installation's config
file; the UI marks them as "not recognised by this ClamAV" rather than hiding
them, so nothing is silently lost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Kinds
# --------------------------------------------------------------------------

BOOL = "bool"          # yes / no
INT = "int"            # a plain number
SIZE = "size"          # bytes, optionally with a K or M suffix
SECONDS = "seconds"    # a timeout
TEXT = "text"          # free text
PATH = "path"          # a single file
DIR = "dir"            # a single directory
ENUM = "enum"          # one of `choices`
MULTI = "multi"        # a repeatable option (one line per value)
REGEX = "regex"        # a repeatable option whose values are regexes

#: Which config file an option belongs to.
CLAMD = "clamd.conf"
FRESHCLAM = "freshclam.conf"


@dataclass(frozen=True)
class ConfOption:
    """One editable setting."""

    key: str
    kind: str
    label: str
    group: str
    file: str
    default: object = None
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    unit: str = ""
    advanced: bool = False
    #: True when a wrong value can stop the daemon or weaken protection.
    sensitive: bool = False
    #: A note from ClamGuard, shown under ClamAV's own description.
    hint: str = ""
    #: Restarting clamd is needed for the change to take effect.
    needs_restart: bool = True

    @property
    def is_repeatable(self) -> bool:
        return self.kind in (MULTI, REGEX)

    @property
    def search_text(self) -> str:
        return f"{self.key} {self.label} {self.group} {self.hint}".lower()


def opt(key: str, kind: str, label: str, group: str, file: str, **kwargs) -> ConfOption:
    """Shorthand used by the tables below."""
    return ConfOption(key=key, kind=kind, label=label, group=group, file=file, **kwargs)


# --------------------------------------------------------------------------
# Groups, in the order the UI shows them
# --------------------------------------------------------------------------

CLAMD_GROUPS = (
    "Scan targets",
    "Detection",
    "Scan limits",
    "Real-time protection",
    "Daemon",
    "Logging",
    "Bytecode",
    "Database",
    "Events",
    "Developer",
)

FRESHCLAM_GROUPS = (
    "Updates",
    "Mirrors",
    "Network",
    "Logging",
    "Service",
    "Events",
)


# --------------------------------------------------------------------------
# clamd.conf
# --------------------------------------------------------------------------

_CLAMD: tuple[ConfOption, ...] = (
    # -- Scan targets: which file formats get unpacked and inspected --------
    opt("ScanPE", BOOL, "Windows executables (PE)", "Scan targets", CLAMD, default=True),
    opt("ScanELF", BOOL, "Linux executables (ELF)", "Scan targets", CLAMD, default=True),
    opt("ScanOLE2", BOOL, "Legacy Office documents (OLE2)", "Scan targets", CLAMD, default=True),
    opt("ScanPDF", BOOL, "PDF documents", "Scan targets", CLAMD, default=True),
    opt("ScanSWF", BOOL, "Flash files (SWF)", "Scan targets", CLAMD, default=True),
    opt("ScanXMLDOCS", BOOL, "Modern Office documents (OOXML)", "Scan targets", CLAMD, default=True),
    opt("ScanHWP3", BOOL, "Hangul Word Processor documents", "Scan targets", CLAMD, default=True),
    opt("ScanOneNote", BOOL, "OneNote sections", "Scan targets", CLAMD, default=True),
    opt("ScanMail", BOOL, "Mail files and attachments", "Scan targets", CLAMD, default=True),
    opt("ScanPartialMessages", BOOL, "Reassemble partial mail messages", "Scan targets", CLAMD,
        default=False, advanced=True),
    opt("ScanHTML", BOOL, "HTML files", "Scan targets", CLAMD, default=True),
    opt("ScanArchive", BOOL, "Archives (zip, rar, 7z, tar…)", "Scan targets", CLAMD, default=True),
    opt("ScanImage", BOOL, "Images", "Scan targets", CLAMD, default=True),
    opt("ScanImageFuzzyHash", BOOL, "Image fuzzy hashing", "Scan targets", CLAMD, default=True,
        advanced=True),
    opt("CrossFilesystems", BOOL, "Cross filesystem boundaries", "Scan targets", CLAMD, default=True),
    opt("FollowDirectorySymlinks", BOOL, "Follow directory symlinks", "Scan targets", CLAMD,
        default=False, hint="Leaving this off avoids scanning the same tree twice."),
    opt("FollowFileSymlinks", BOOL, "Follow file symlinks", "Scan targets", CLAMD, default=False),
    opt("ExcludePath", REGEX, "Never scan paths matching", "Scan targets", CLAMD,
        hint="Regular expressions, not globs. ^/proc/ excludes the proc filesystem."),

    # -- Detection ---------------------------------------------------------
    opt("DetectPUA", BOOL, "Detect potentially unwanted applications", "Detection", CLAMD,
        default=False,
        hint="PUA covers adware, packers and remote-access tools. Expect more false alarms."),
    opt("IncludePUA", MULTI, "Only these PUA categories", "Detection", CLAMD, advanced=True),
    opt("ExcludePUA", MULTI, "Ignore these PUA categories", "Detection", CLAMD, advanced=True),
    opt("HeuristicAlerts", BOOL, "Report heuristic detections", "Detection", CLAMD, default=True),
    opt("HeuristicScanPrecedence", BOOL, "Stop at the first heuristic match", "Detection", CLAMD,
        default=False, advanced=True),
    opt("AlgorithmicDetection", BOOL, "Algorithmic detection", "Detection", CLAMD, default=True),
    opt("AlertBrokenExecutables", BOOL, "Alert on broken executables", "Detection", CLAMD, default=False),
    opt("AlertBrokenMedia", BOOL, "Alert on broken media files", "Detection", CLAMD, default=False),
    opt("AlertEncrypted", BOOL, "Alert on encrypted archives and documents", "Detection", CLAMD,
        default=False),
    opt("AlertEncryptedArchive", BOOL, "Alert on encrypted archives", "Detection", CLAMD, default=False),
    opt("AlertEncryptedDoc", BOOL, "Alert on encrypted documents", "Detection", CLAMD, default=False),
    opt("AlertOLE2Macros", BOOL, "Alert on Office macros", "Detection", CLAMD, default=False,
        hint="Flags any document containing a macro, malicious or not."),
    opt("AlertPartitionIntersection", BOOL, "Alert on overlapping partitions", "Detection", CLAMD,
        default=False),
    opt("AlertExceedsMax", BOOL, "Alert when a scan limit is hit", "Detection", CLAMD, default=False,
        hint="Turns a skipped-because-too-big file into a visible alert instead of silence."),
    opt("AlertPhishingSSLMismatch", BOOL, "Alert on phishing SSL mismatch", "Detection", CLAMD,
        default=False),
    opt("AlertPhishingCloak", BOOL, "Alert on cloaked phishing URLs", "Detection", CLAMD, default=False),
    opt("PhishingSignatures", BOOL, "Use phishing signatures", "Detection", CLAMD, default=True),
    opt("PhishingScanURLs", BOOL, "Scan URLs in documents", "Detection", CLAMD, default=True),
    opt("PhishingAlwaysBlockSSLMismatch", BOOL, "Always block SSL mismatch", "Detection", CLAMD,
        default=False, advanced=True),
    opt("PhishingAlwaysBlockCloak", BOOL, "Always block cloaked URLs", "Detection", CLAMD,
        default=False, advanced=True),
    opt("OLE2BlockMacros", BOOL, "Block all OLE2 macros", "Detection", CLAMD, default=False,
        advanced=True),
    opt("ArchiveBlockEncrypted", BOOL, "Block encrypted archives", "Detection", CLAMD, default=False,
        advanced=True),
    opt("PartitionIntersection", BOOL, "Detect partition intersections", "Detection", CLAMD,
        default=False, advanced=True),
    opt("BlockMax", BOOL, "Treat exceeded limits as a detection", "Detection", CLAMD, default=False,
        advanced=True),
    opt("StructuredDataDetection", BOOL, "Detect credit card and SSN data", "Detection", CLAMD,
        default=False, hint="Data-loss prevention, not malware detection."),
    opt("StructuredMinCreditCardCount", INT, "Minimum card numbers to alert", "Detection", CLAMD,
        default=3, minimum=1, maximum=10000, advanced=True),
    opt("StructuredMinSSNCount", INT, "Minimum SSNs to alert", "Detection", CLAMD,
        default=3, minimum=1, maximum=10000, advanced=True),
    opt("StructuredSSNFormatNormal", BOOL, "Match SSNs as xxx-yy-zzzz", "Detection", CLAMD,
        default=True, advanced=True),
    opt("StructuredSSNFormatStripped", BOOL, "Match SSNs as xxxyyzzzz", "Detection", CLAMD,
        default=False, advanced=True),
    opt("StructuredCCOnly", BOOL, "Only check credit card numbers", "Detection", CLAMD,
        default=False, advanced=True),

    # -- Scan limits -------------------------------------------------------
    opt("MaxScanSize", SIZE, "Maximum data examined per file", "Scan limits", CLAMD,
        default="400M", sensitive=True,
        hint="Malware hidden past this point in a large archive will be missed."),
    opt("MaxFileSize", SIZE, "Maximum size of a single file", "Scan limits", CLAMD,
        default="100M", sensitive=True),
    opt("MaxRecursion", INT, "Maximum archive nesting depth", "Scan limits", CLAMD,
        default=17, minimum=1, maximum=200),
    opt("MaxFiles", INT, "Maximum files per container", "Scan limits", CLAMD,
        default=10000, minimum=1, maximum=1000000),
    opt("MaxScanTime", INT, "Maximum time per file", "Scan limits", CLAMD,
        default=120000, minimum=0, unit="ms"),
    opt("MaxDirectoryRecursion", INT, "Maximum directory depth", "Scan limits", CLAMD,
        default=15, minimum=0, maximum=1000),
    opt("MaxEmbeddedPE", SIZE, "Maximum embedded executable size", "Scan limits", CLAMD,
        default="40M", advanced=True),
    opt("MaxHTMLNormalize", SIZE, "Maximum HTML normalised size", "Scan limits", CLAMD,
        default="40M", advanced=True),
    opt("MaxHTMLNoTags", SIZE, "Maximum tag-stripped HTML size", "Scan limits", CLAMD,
        default="8M", advanced=True),
    opt("MaxScriptNormalize", SIZE, "Maximum script normalised size", "Scan limits", CLAMD,
        default="20M", advanced=True),
    opt("MaxZipTypeRcg", SIZE, "Maximum ZIP type-recognition size", "Scan limits", CLAMD,
        default="1M", advanced=True),
    opt("MaxPartitions", INT, "Maximum partitions per image", "Scan limits", CLAMD,
        default=50, minimum=1, advanced=True),
    opt("MaxIconsPE", INT, "Maximum icons inspected per executable", "Scan limits", CLAMD,
        default=100, minimum=0, advanced=True),
    opt("MaxRecHWP3", INT, "Maximum HWP3 recursion", "Scan limits", CLAMD,
        default=16, minimum=1, advanced=True),
    opt("PCREMatchLimit", INT, "PCRE match limit", "Scan limits", CLAMD,
        default=100000, minimum=0, advanced=True),
    opt("PCRERecMatchLimit", INT, "PCRE recursion limit", "Scan limits", CLAMD,
        default=2000, minimum=0, advanced=True),
    opt("PCREMaxFileSize", SIZE, "Maximum file size for PCRE rules", "Scan limits", CLAMD,
        default="100M", advanced=True),

    # -- Real-time protection ---------------------------------------------
    opt("OnAccessMountPath", MULTI, "Watch these mount points", "Real-time protection", CLAMD,
        sensitive=True,
        hint="Watches an entire mounted filesystem. Cannot be combined with prevention on some kernels."),
    opt("OnAccessIncludePath", MULTI, "Watch these directories", "Real-time protection", CLAMD,
        sensitive=True),
    opt("OnAccessExcludePath", MULTI, "Never watch these directories", "Real-time protection", CLAMD),
    opt("OnAccessExcludeUID", MULTI, "Ignore activity from these user IDs", "Real-time protection",
        CLAMD, sensitive=True),
    opt("OnAccessExcludeUname", MULTI, "Ignore activity from these usernames", "Real-time protection",
        CLAMD, sensitive=True,
        hint="clamonacc refuses to start unless at least one exclusion is set — "
             "normally the clamav user, so the scanner does not scan itself forever."),
    opt("OnAccessExcludeRootUID", BOOL, "Ignore activity from root", "Real-time protection", CLAMD,
        default=False, sensitive=True),
    opt("OnAccessPrevention", BOOL, "Block access to infected files", "Real-time protection", CLAMD,
        default=False, sensitive=True,
        hint="Without this, real-time protection only reports; it does not stop anything."),
    opt("OnAccessDenyOnError", BOOL, "Deny access when a scan fails", "Real-time protection", CLAMD,
        default=False),
    opt("OnAccessExtraScanning", BOOL, "Also scan on file creation and move", "Real-time protection",
        CLAMD, default=False, hint="Catches more, costs more CPU."),
    opt("OnAccessDisableDDD", BOOL, "Disable dynamic directory watching", "Real-time protection",
        CLAMD, default=False, advanced=True),
    opt("OnAccessMaxFileSize", SIZE, "Maximum file size to scan on access", "Real-time protection",
        CLAMD, default="5M"),
    opt("OnAccessMaxThreads", INT, "Threads for on-access scanning", "Real-time protection", CLAMD,
        default=5, minimum=1, maximum=256),
    opt("OnAccessRetryAttempts", INT, "Retries after a failed scan", "Real-time protection", CLAMD,
        default=0, minimum=0, maximum=100, advanced=True),
    opt("OnAccessCurlTimeout", INT, "On-access transfer timeout", "Real-time protection", CLAMD,
        default=5000, minimum=0, unit="ms", advanced=True),

    # -- Daemon ------------------------------------------------------------
    opt("User", TEXT, "Run the daemon as", "Daemon", CLAMD, default="clamav", sensitive=True,
        hint="Changing this can make the daemon unable to read its own database."),
    opt("Foreground", BOOL, "Stay in the foreground", "Daemon", CLAMD, default=False, advanced=True),
    opt("PidFile", PATH, "PID file", "Daemon", CLAMD, advanced=True),
    opt("TemporaryDirectory", DIR, "Temporary directory", "Daemon", CLAMD),
    opt("LocalSocket", PATH, "Unix socket", "Daemon", CLAMD, sensitive=True,
        hint="This is how ClamGuard and clamdscan talk to the daemon."),
    opt("LocalSocketGroup", TEXT, "Socket group", "Daemon", CLAMD, advanced=True),
    opt("LocalSocketMode", TEXT, "Socket permissions", "Daemon", CLAMD, advanced=True,
        hint="Octal, like 660. Tighter than 666 means only the socket group can scan."),
    opt("FixStaleSocket", BOOL, "Remove a stale socket on start", "Daemon", CLAMD, default=True),
    opt("TCPSocket", INT, "TCP port", "Daemon", CLAMD, minimum=1, maximum=65535, sensitive=True,
        hint="Only enable this if something on the network must scan through this daemon."),
    opt("TCPAddr", TEXT, "TCP bind address", "Daemon", CLAMD, sensitive=True,
        hint="Leave at 127.0.0.1 unless you really mean to expose the scanner."),
    opt("MaxConnectionQueueLength", INT, "Connection queue length", "Daemon", CLAMD,
        default=200, minimum=1, advanced=True),
    opt("MaxThreads", INT, "Worker threads", "Daemon", CLAMD, default=10, minimum=1, maximum=1024),
    opt("MaxQueue", INT, "Queued scan requests", "Daemon", CLAMD, default=100, minimum=1,
        advanced=True),
    opt("IdleTimeout", SECONDS, "Idle thread timeout", "Daemon", CLAMD, default=30, minimum=0,
        advanced=True),
    opt("ReadTimeout", SECONDS, "Read timeout", "Daemon", CLAMD, default=120, minimum=0,
        advanced=True),
    opt("CommandReadTimeout", SECONDS, "Command read timeout", "Daemon", CLAMD, default=30,
        minimum=0, advanced=True),
    opt("SendBufTimeout", INT, "Send buffer timeout", "Daemon", CLAMD, default=200, minimum=0,
        unit="ms", advanced=True),
    opt("ExitOnOOM", BOOL, "Exit if out of memory", "Daemon", CLAMD, default=False, advanced=True),
    opt("SelfCheck", SECONDS, "Database self-check interval", "Daemon", CLAMD, default=600,
        minimum=0),
    opt("ConcurrentDatabaseReload", BOOL, "Reload the database without pausing", "Daemon", CLAMD,
        default=True, hint="Uses roughly twice the memory during a reload."),
    opt("ForceToDisk", BOOL, "Always unpack to disk", "Daemon", CLAMD, default=False, advanced=True),
    opt("DisableCache", BOOL, "Disable the scan result cache", "Daemon", CLAMD, default=False,
        advanced=True),
    opt("CacheSize", INT, "Cached scan results", "Daemon", CLAMD, default=65536, minimum=0,
        advanced=True),
    opt("StreamMaxLength", SIZE, "Maximum streamed data", "Daemon", CLAMD, default="100M",
        advanced=True),
    opt("StreamMinPort", INT, "Stream port range start", "Daemon", CLAMD, default=1024,
        minimum=1024, maximum=65535, advanced=True),
    opt("StreamMaxPort", INT, "Stream port range end", "Daemon", CLAMD, default=2048,
        minimum=1024, maximum=65535, advanced=True),
    opt("AllowAllMatchScan", BOOL, "Allow ALLMATCHSCAN command", "Daemon", CLAMD, default=True,
        advanced=True),
    opt("EnableReloadCommand", BOOL, "Allow RELOAD over the socket", "Daemon", CLAMD, default=True,
        hint="ClamGuard uses RELOAD to apply new signatures without a restart."),
    opt("EnableShutdownCommand", BOOL, "Allow SHUTDOWN over the socket", "Daemon", CLAMD,
        default=False, sensitive=True,
        hint="Anyone who can reach the socket could stop the daemon."),
    opt("EnableStatsCommand", BOOL, "Allow STATS over the socket", "Daemon", CLAMD, default=True),
    opt("EnableVersionCommand", BOOL, "Allow VERSION over the socket", "Daemon", CLAMD, default=True),

    # -- Logging -----------------------------------------------------------
    opt("LogFile", PATH, "Log file", "Logging", CLAMD),
    opt("LogFileUnlock", BOOL, "Do not lock the log file", "Logging", CLAMD, default=False,
        advanced=True),
    opt("LogFileMaxSize", SIZE, "Rotate the log at", "Logging", CLAMD, default="1M"),
    opt("LogRotate", BOOL, "Rotate logs", "Logging", CLAMD, default=False),
    opt("LogTime", BOOL, "Timestamp every line", "Logging", CLAMD, default=False),
    opt("LogClean", BOOL, "Log clean files too", "Logging", CLAMD, default=False,
        hint="Very noisy. Useful only when proving a scan actually looked at something."),
    opt("LogSyslog", BOOL, "Also log to syslog", "Logging", CLAMD, default=False),
    opt("LogFacility", TEXT, "Syslog facility", "Logging", CLAMD, default="LOG_LOCAL6",
        advanced=True),
    opt("LogVerbose", BOOL, "Verbose logging", "Logging", CLAMD, default=False),
    opt("ExtendedDetectionInfo", BOOL, "Log file size and hash with detections", "Logging", CLAMD,
        default=True),
    opt("GenerateMetadataJson", BOOL, "Write a JSON scan report", "Logging", CLAMD, default=False,
        advanced=True),
    opt("JsonStoreHTMLURIs", BOOL, "Include HTML URIs in JSON", "Logging", CLAMD, default=False,
        advanced=True),
    opt("JsonStorePDFURIs", BOOL, "Include PDF URIs in JSON", "Logging", CLAMD, default=False,
        advanced=True),
    opt("JsonStoreExtraHashes", BOOL, "Include extra hashes in JSON", "Logging", CLAMD,
        default=False, advanced=True),
    opt("LeaveTemporaryFiles", BOOL, "Keep unpacked temporary files", "Logging", CLAMD,
        default=False, advanced=True,
        hint="Leaves extracted malware on disk. For debugging only."),

    # -- Bytecode ----------------------------------------------------------
    opt("Bytecode", BOOL, "Run bytecode signatures", "Bytecode", CLAMD, default=True,
        hint="Bytecode signatures catch families that simple patterns cannot."),
    opt("BytecodeSecurity", ENUM, "Bytecode trust level", "Bytecode", CLAMD,
        default="TrustSigned", choices=("TrustSigned", "Paranoid")),
    opt("BytecodeTimeout", INT, "Bytecode timeout", "Bytecode", CLAMD, default=10000, minimum=0,
        unit="ms"),
    opt("BytecodeUnsigned", BOOL, "Run unsigned bytecode", "Bytecode", CLAMD, default=False,
        sensitive=True, hint="Only for testing signatures you wrote yourself."),
    opt("BytecodeMode", ENUM, "Bytecode engine", "Bytecode", CLAMD, default="Auto",
        choices=("Auto", "ForceJIT", "ForceInterpreter", "Test"), advanced=True),

    # -- Database ----------------------------------------------------------
    opt("DatabaseDirectory", DIR, "Signature database directory", "Database", CLAMD,
        sensitive=True, hint="Must match freshclam.conf, or updates will land somewhere clamd never reads."),
    opt("CVDCertsDirectory", DIR, "CVD certificate directory", "Database", CLAMD, advanced=True),
    opt("OfficialDatabaseOnly", BOOL, "Official signatures only", "Database", CLAMD, default=False,
        hint="Ignores any third-party signatures you have added."),
    opt("FailIfCvdOlderThan", INT, "Refuse to start if signatures are older than", "Database",
        CLAMD, minimum=0, unit="days", advanced=True),
    opt("DisableCertCheck", BOOL, "Skip signature certificate checks", "Database", CLAMD,
        default=False, sensitive=True, advanced=True),
    opt("FIPSCryptoHashLimits", BOOL, "FIPS hash restrictions", "Database", CLAMD, default=False,
        advanced=True),

    # -- Events ------------------------------------------------------------
    opt("VirusEvent", TEXT, "Run this command on detection", "Events", CLAMD, sensitive=True,
        hint="Runs as the daemon user on every detection. "
             "%v is the threat name and %f the file path."),

    # -- Developer ---------------------------------------------------------
    opt("Debug", BOOL, "Debug output", "Developer", CLAMD, default=False, advanced=True),
    opt("DevACOnly", BOOL, "Aho-Corasick matcher only", "Developer", CLAMD, default=False,
        advanced=True),
    opt("DevACDepth", INT, "Aho-Corasick depth", "Developer", CLAMD, minimum=0, advanced=True),
    opt("DevLiblog", BOOL, "libclamav logging", "Developer", CLAMD, default=False, advanced=True),
    opt("DevPerformance", BOOL, "Performance counters", "Developer", CLAMD, default=False,
        advanced=True),
    opt("PreludeEnable", BOOL, "Prelude SIEM output", "Developer", CLAMD, default=False,
        advanced=True),
    opt("PreludeAnalyzerName", TEXT, "Prelude analyzer name", "Developer", CLAMD,
        default="ClamAV", advanced=True),
)


# --------------------------------------------------------------------------
# freshclam.conf
# --------------------------------------------------------------------------

_FRESHCLAM: tuple[ConfOption, ...] = (
    # -- Updates -----------------------------------------------------------
    opt("Checks", INT, "Update checks per day", "Updates", FRESHCLAM,
        default=12, minimum=1, maximum=50, needs_restart=False,
        hint="ClamAV publishes several times a day; 12 checks means roughly every two hours."),
    opt("ScriptedUpdates", BOOL, "Download incremental updates", "Updates", FRESHCLAM,
        default=True, needs_restart=False,
        hint="Downloads only the daily difference instead of the whole 20 MB file."),
    opt("TestDatabases", BOOL, "Verify databases before installing", "Updates", FRESHCLAM,
        default=True, needs_restart=False),
    opt("CompressLocalDatabase", BOOL, "Compress the local database", "Updates", FRESHCLAM,
        default=False, advanced=True),
    opt("Bytecode", BOOL, "Download bytecode signatures", "Updates", FRESHCLAM, default=True),
    opt("ExtraDatabase", MULTI, "Extra official databases", "Updates", FRESHCLAM, advanced=True),
    opt("ExcludeDatabase", MULTI, "Databases to skip", "Updates", FRESHCLAM, advanced=True),
    opt("MaxAttempts", INT, "Attempts per mirror", "Updates", FRESHCLAM, default=3, minimum=1,
        maximum=20),
    opt("DatabaseOwner", TEXT, "Database files owned by", "Updates", FRESHCLAM, default="clamav",
        sensitive=True, hint="Must be a user clamd can read as."),
    opt("DatabaseDirectory", DIR, "Download signatures into", "Updates", FRESHCLAM, sensitive=True,
        hint="Must match clamd.conf."),
    opt("CVDCertsDirectory", DIR, "CVD certificate directory", "Updates", FRESHCLAM, advanced=True),
    opt("FIPSCryptoHashLimits", BOOL, "FIPS hash restrictions", "Updates", FRESHCLAM,
        default=False, advanced=True),

    # -- Mirrors -----------------------------------------------------------
    opt("DatabaseMirror", MULTI, "Mirrors, in order of preference", "Mirrors", FRESHCLAM,
        sensitive=True,
        hint="database.clamav.net is the official CDN. Listing it last is a common mistake."),
    opt("PrivateMirror", MULTI, "Private mirrors", "Mirrors", FRESHCLAM, advanced=True),
    opt("DatabaseCustomURL", MULTI, "Custom signature URLs", "Mirrors", FRESHCLAM, advanced=True,
        hint="Third-party signature feeds. Each URL is downloaded verbatim."),
    opt("DNSDatabaseInfo", TEXT, "DNS record for version checks", "Mirrors", FRESHCLAM,
        default="current.cvd.clamav.net", advanced=True),

    # -- Network -----------------------------------------------------------
    opt("ConnectTimeout", SECONDS, "Connection timeout", "Network", FRESHCLAM, default=30,
        minimum=1, maximum=600),
    opt("ReceiveTimeout", SECONDS, "Download timeout", "Network", FRESHCLAM, default=0, minimum=0,
        hint="0 means no limit."),
    opt("HTTPProxyServer", TEXT, "Proxy server", "Network", FRESHCLAM),
    opt("HTTPProxyPort", INT, "Proxy port", "Network", FRESHCLAM, minimum=1, maximum=65535),
    opt("HTTPProxyUsername", TEXT, "Proxy username", "Network", FRESHCLAM),
    opt("HTTPProxyPassword", TEXT, "Proxy password", "Network", FRESHCLAM, sensitive=True,
        hint="Stored in plain text in freshclam.conf, which root can read."),
    opt("HTTPUserAgent", TEXT, "User agent", "Network", FRESHCLAM, advanced=True,
        hint="Changing this can get you blocked by the official mirrors."),
    opt("LocalIPAddress", TEXT, "Bind to local address", "Network", FRESHCLAM, advanced=True),

    # -- Logging -----------------------------------------------------------
    opt("UpdateLogFile", PATH, "Update log file", "Logging", FRESHCLAM),
    opt("LogFileMaxSize", SIZE, "Rotate the log at", "Logging", FRESHCLAM, default="1M"),
    opt("LogRotate", BOOL, "Rotate logs", "Logging", FRESHCLAM, default=False),
    opt("LogTime", BOOL, "Timestamp every line", "Logging", FRESHCLAM, default=False),
    opt("LogVerbose", BOOL, "Verbose logging", "Logging", FRESHCLAM, default=False),
    opt("LogSyslog", BOOL, "Also log to syslog", "Logging", FRESHCLAM, default=False),
    opt("LogFacility", TEXT, "Syslog facility", "Logging", FRESHCLAM, default="LOG_LOCAL6",
        advanced=True),
    opt("Debug", BOOL, "Debug output", "Logging", FRESHCLAM, default=False, advanced=True),

    # -- Service -----------------------------------------------------------
    opt("Foreground", BOOL, "Stay in the foreground", "Service", FRESHCLAM, default=False,
        advanced=True,
        hint="systemd runs freshclam in the foreground; changing this breaks the unit."),
    opt("PidFile", PATH, "PID file", "Service", FRESHCLAM, advanced=True),
    opt("NotifyClamd", PATH, "Tell clamd about new signatures", "Service", FRESHCLAM,
        hint="Point this at clamd.conf so the daemon reloads without a restart."),

    # -- Events ------------------------------------------------------------
    opt("OnUpdateExecute", TEXT, "Run after a successful update", "Events", FRESHCLAM,
        sensitive=True),
    opt("OnErrorExecute", TEXT, "Run after a failed update", "Events", FRESHCLAM, sensitive=True),
    opt("OnOutdatedExecute", TEXT, "Run when ClamAV itself is outdated", "Events", FRESHCLAM,
        sensitive=True, hint="%v is replaced with the new version number."),
)


# --------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Schema:
    """The option table for one configuration file."""

    file: str
    groups: tuple[str, ...]
    options: tuple[ConfOption, ...]
    _by_key: dict[str, ConfOption] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        self._by_key.update({option.key.lower(): option for option in self.options})

    def get(self, key: str) -> ConfOption | None:
        return self._by_key.get(key.lower())

    def in_group(self, group: str, *, include_advanced: bool = True) -> list[ConfOption]:
        return [
            option
            for option in self.options
            if option.group == group and (include_advanced or not option.advanced)
        ]

    def search(self, needle: str) -> list[ConfOption]:
        words = needle.lower().split()
        if not words:
            return list(self.options)
        return [o for o in self.options if all(w in o.search_text for w in words)]

    def unknown_keys(self, keys: list[str]) -> list[str]:
        """Keys present in a file that this table does not describe."""
        return [key for key in keys if self.get(key) is None]


CLAMD_SCHEMA = Schema(CLAMD, CLAMD_GROUPS, _CLAMD)
FRESHCLAM_SCHEMA = Schema(FRESHCLAM, FRESHCLAM_GROUPS, _FRESHCLAM)

SCHEMAS = {CLAMD: CLAMD_SCHEMA, FRESHCLAM: FRESHCLAM_SCHEMA}


def schema_for(file: str) -> Schema:
    return SCHEMAS[file]


# --------------------------------------------------------------------------
# Value handling
# --------------------------------------------------------------------------

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KkMmGg])?\s*$")
_SIZE_UNITS = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}


def parse_size(text: str) -> int | None:
    """``"400M"`` -> 419430400. None if it is not a size ClamAV would accept."""
    match = _SIZE_RE.match(text or "")
    if not match:
        return None
    amount = float(match.group(1))
    suffix = (match.group(2) or "").lower()
    return int(amount * _SIZE_UNITS.get(suffix, 1))


def format_size(byte_count: int) -> str:
    """419430400 -> ``"400M"``, choosing the largest exact unit."""
    for suffix, factor in (("G", 1024 ** 3), ("M", 1024 ** 2), ("K", 1024)):
        if byte_count and byte_count % factor == 0:
            return f"{byte_count // factor}{suffix}"
    return str(byte_count)


def validate(option: ConfOption, value: str) -> str | None:
    """Check a value the user typed. Returns an error message, or None if fine."""
    text = (value or "").strip()

    if option.kind in (INT, SECONDS):
        if not text:
            return None
        if not text.lstrip("-").isdigit():
            return "must be a whole number"
        number = int(text)
        if option.minimum is not None and number < option.minimum:
            return f"must be at least {option.minimum}"
        if option.maximum is not None and number > option.maximum:
            return f"must be at most {option.maximum}"
        return None

    if option.kind == SIZE:
        if not text:
            return None
        if parse_size(text) is None:
            return "use a number, optionally followed by K, M or G"
        return None

    if option.kind == ENUM:
        if text and text not in option.choices:
            return "must be one of: " + ", ".join(option.choices)
        return None

    if option.kind in (PATH, DIR):
        if text and not text.startswith("/"):
            return "must be an absolute path"
        return None

    if option.kind == REGEX:
        try:
            re.compile(text)
        except re.error as error:
            return f"not a valid regular expression: {error}"
        return None

    return None
