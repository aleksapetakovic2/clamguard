"""Every filesystem location ClamGuard touches, decided in exactly one place.

Nothing else in the codebase should contain a hard-coded path. If you need a
new file, add it here so that it shows up in the uninstall story and in the
"where is my data" section of the user guide.

Distributions disagree about where ClamAV keeps its configuration (Debian and
Arch use /etc/clamav/, Fedora and the upstream build use /etc/ directly), so
the ClamAV paths are *discovered* at import time rather than assumed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

# --------------------------------------------------------------------------
# ClamGuard's own data, under the XDG base directories.
# --------------------------------------------------------------------------

APP_DIRNAME = "clamguard"


def _xdg(env_var: str, fallback: str) -> Path:
    """Return an XDG base directory, honouring the environment variable."""
    value = os.environ.get(env_var)
    base = Path(value) if value else Path.home() / fallback
    return base / APP_DIRNAME


CONFIG_DIR = _xdg("XDG_CONFIG_HOME", ".config")
DATA_DIR = _xdg("XDG_DATA_HOME", ".local/share")
CACHE_DIR = _xdg("XDG_CACHE_HOME", ".cache")

SETTINGS_FILE = CONFIG_DIR / "settings.json"
SCHEDULES_FILE = CONFIG_DIR / "schedules.json"

QUARANTINE_DIR = DATA_DIR / "quarantine"
QUARANTINE_VAULT = QUARANTINE_DIR / "vault"
QUARANTINE_META = QUARANTINE_DIR / "meta"
HISTORY_DB = DATA_DIR / "history.db"
REPORTS_DIR = DATA_DIR / "reports"
LOG_DIR = DATA_DIR / "logs"
APP_LOG = LOG_DIR / "clamguard.log"

#: Directories the app creates on first run. Order does not matter.
OWNED_DIRECTORIES = (
    CONFIG_DIR,
    DATA_DIR,
    CACHE_DIR,
    QUARANTINE_VAULT,
    QUARANTINE_META,
    REPORTS_DIR,
    LOG_DIR,
)


def ensure_directories() -> None:
    """Create ClamGuard's own directories. Safe to call repeatedly."""
    for directory in OWNED_DIRECTORIES:
        directory.mkdir(parents=True, exist_ok=True)
    # The vault holds live malware payloads. Keep it out of other users' reach
    # even on a machine with a permissive umask.
    for private in (QUARANTINE_DIR, QUARANTINE_VAULT, QUARANTINE_META):
        try:
            private.chmod(0o700)
        except OSError:
            # Non-POSIX filesystems (NTFS, exFAT) ignore modes. Not fatal.
            pass


# --------------------------------------------------------------------------
# The privileged helper. Installed by hand; see packaging/install-helper.sh.
# --------------------------------------------------------------------------

HELPER_PATH = Path("/usr/local/lib/clamguard/clamguard-helper")
HELPER_POLICY_PATH = Path("/usr/share/polkit-1/actions/org.clamguard.helper.policy")
HELPER_LOG = Path("/var/log/clamguard-helper.log")


# --------------------------------------------------------------------------
# ClamAV's paths, discovered rather than assumed.
# --------------------------------------------------------------------------

_CONFIG_DIR_CANDIDATES = (
    Path("/etc/clamav"),
    Path("/etc/clamd.d"),
    Path("/usr/local/etc/clamav"),
    Path("/usr/local/etc"),
    Path("/etc"),
)

_DB_DIR_CANDIDATES = (
    Path("/var/lib/clamav"),
    Path("/usr/local/share/clamav"),
    Path("/var/clamav"),
)


def _ask_clamconf_for_config_dir() -> Path | None:
    """Ask `clamconf` where it looks for configuration.

    Its first line is ``Checking configuration files in /etc/clamav``. That is
    the authoritative answer for this installation, so we prefer it over
    guessing. Returns None if clamconf is missing or says something we do not
    recognise.
    """
    executable = shutil.which("clamconf")
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, "-n"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        marker = "Checking configuration files in "
        if line.startswith(marker):
            candidate = Path(line[len(marker):].strip())
            if candidate.is_dir():
                return candidate
    return None


def discover_clamav_config_dir() -> Path:
    """Best guess at the directory holding clamd.conf and freshclam.conf."""
    from_clamconf = _ask_clamconf_for_config_dir()
    if from_clamconf is not None:
        return from_clamconf
    for candidate in _CONFIG_DIR_CANDIDATES:
        if (candidate / "clamd.conf").is_file() or (candidate / "freshclam.conf").is_file():
            return candidate
    return _CONFIG_DIR_CANDIDATES[0]


def discover_clamav_database_dir(clamd_conf: Path | None = None) -> Path:
    """Where the .cvd/.cld signature databases live.

    A DatabaseDirectory line in clamd.conf wins; otherwise we probe the usual
    locations.
    """
    if clamd_conf and clamd_conf.is_file():
        try:
            for raw in clamd_conf.read_text(errors="replace").splitlines():
                line = raw.strip()
                if line.lower().startswith("databasedirectory"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        candidate = Path(parts[1].strip())
                        if candidate.is_dir():
                            return candidate
        except OSError:
            pass
    for candidate in _DB_DIR_CANDIDATES:
        if candidate.is_dir():
            return candidate
    return _DB_DIR_CANDIDATES[0]


CLAMAV_CONFIG_DIR = discover_clamav_config_dir()
CLAMD_CONF = CLAMAV_CONFIG_DIR / "clamd.conf"
FRESHCLAM_CONF = CLAMAV_CONFIG_DIR / "freshclam.conf"
MILTER_CONF = CLAMAV_CONFIG_DIR / "clamav-milter.conf"

CLAMAV_DB_DIR = discover_clamav_database_dir(CLAMD_CONF)
CLAMAV_LOG_DIR = Path("/var/log/clamav")

#: Files the privileged helper is allowed to read or write. Kept here so the
#: GUI and the helper agree; the helper has its own copy of this list and does
#: not trust anything the GUI sends.
EDITABLE_CONFIG_FILES = (CLAMD_CONF, FRESHCLAM_CONF, MILTER_CONF)

READABLE_LOG_FILES = (
    CLAMAV_LOG_DIR / "clamd.log",
    CLAMAV_LOG_DIR / "freshclam.log",
    CLAMAV_LOG_DIR / "clamonacc.log",
)


def package_resource(*parts: str) -> Path:
    """Path to a file shipped inside the package (icons, stylesheets)."""
    return Path(__file__).resolve().parent.parent / "resources" / Path(*parts)
