"""Scan options, and how they turn into command-line arguments.

One important asymmetry, which the UI has to be honest about:

* ``clamscan`` takes every option on the command line, so a profile applies in
  full.
* ``clamdscan`` hands the work to the running daemon, which uses **its own**
  configuration from clamd.conf. Only a handful of clamdscan flags exist, and
  none of them change how a file is inspected.

So when a scan runs through the daemon, the profile's depth settings are not in
effect — clamd.conf's are. ClamGuard says so on the scan page rather than
pretending otherwise, and offers "Scan directly" for when the profile matters
more than the speed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .conf_schema import parse_size


@dataclass(frozen=True)
class ScanProfile:
    """A named set of scan options."""

    id: str
    name: str
    description: str

    # -- depth ------------------------------------------------------------
    scan_archives: bool = True
    max_file_size: str = "100M"
    max_scan_size: str = "400M"
    max_recursion: int = 17
    max_files: int = 10000
    max_scan_time_ms: int = 120000

    # -- what counts as a detection --------------------------------------
    detect_pua: bool = False
    heuristic_alerts: bool = True
    alert_broken: bool = False
    alert_encrypted: bool = False
    alert_macros: bool = False
    alert_exceeds_max: bool = False

    # -- file types -------------------------------------------------------
    scan_pe: bool = True
    scan_elf: bool = True
    scan_ole2: bool = True
    scan_pdf: bool = True
    scan_html: bool = True
    scan_mail: bool = True
    scan_swf: bool = True
    scan_xmldocs: bool = True
    scan_image: bool = True

    # -- traversal --------------------------------------------------------
    follow_dir_symlinks: bool = False
    follow_file_symlinks: bool = False
    cross_filesystems: bool = False

    # -- other ------------------------------------------------------------
    bytecode: bool = True
    exclude_patterns: tuple[str, ...] = field(default_factory=tuple)

    # ---------------------------------------------------------------------

    @property
    def max_file_bytes(self) -> int:
        """The size limit as a number, for deciding what to enumerate."""
        return parse_size(self.max_file_size) or 0

    def clamscan_args(self) -> list[str]:
        """Command-line flags for a direct clamscan run."""
        yes_no = lambda flag, value: f"--{flag}={'yes' if value else 'no'}"  # noqa: E731

        args = [
            "--stdout",
            yes_no("scan-archive", self.scan_archives),
            yes_no("detect-pua", self.detect_pua),
            yes_no("heuristic-alerts", self.heuristic_alerts),
            yes_no("alert-broken", self.alert_broken),
            yes_no("alert-encrypted", self.alert_encrypted),
            yes_no("alert-macros", self.alert_macros),
            yes_no("alert-exceeds-max", self.alert_exceeds_max),
            yes_no("scan-pe", self.scan_pe),
            yes_no("scan-elf", self.scan_elf),
            yes_no("scan-ole2", self.scan_ole2),
            yes_no("scan-pdf", self.scan_pdf),
            yes_no("scan-html", self.scan_html),
            yes_no("scan-mail", self.scan_mail),
            yes_no("scan-swf", self.scan_swf),
            yes_no("scan-xmldocs", self.scan_xmldocs),
            yes_no("scan-image", self.scan_image),
            yes_no("bytecode", self.bytecode),
            yes_no("cross-fs", self.cross_filesystems),
            f"--max-filesize={self.max_file_size}",
            f"--max-scansize={self.max_scan_size}",
            f"--max-recursion={self.max_recursion}",
            f"--max-files={self.max_files}",
            f"--max-scantime={self.max_scan_time_ms}",
            f"--follow-dir-symlinks={2 if self.follow_dir_symlinks else 0}",
            f"--follow-file-symlinks={2 if self.follow_file_symlinks else 0}",
        ]
        for pattern in self.exclude_patterns:
            args.append(f"--exclude={pattern}")
        return args

    def clamdscan_args(self, *, fdpass: bool = True, multiscan: bool = True) -> list[str]:
        """Flags for a daemon scan.

        These are the only ones that exist. Everything about *how* files are
        inspected comes from clamd.conf, not from here.
        """
        args = ["--stdout"]
        if fdpass:
            # Without this the daemon, running as the clamav user, cannot open
            # files in the user's home directory.
            args.append("--fdpass")
        if multiscan:
            # Roughly an order of magnitude faster: clamd scans in parallel.
            args.append("--multiscan")
        return args

    def summary_lines(self) -> list[str]:
        """Short human descriptions of what this profile does differently."""
        notes = []
        notes.append("Archives are unpacked and scanned" if self.scan_archives
                     else "Archives are not opened")
        notes.append(f"Files up to {self.max_file_size} are scanned")
        if self.detect_pua:
            notes.append("Adware and unwanted programs are reported")
        if self.alert_encrypted:
            notes.append("Encrypted archives are reported")
        if self.alert_macros:
            notes.append("Documents containing macros are reported")
        if self.follow_dir_symlinks or self.follow_file_symlinks:
            notes.append("Symlinks are followed")
        return notes

    def with_changes(self, **changes) -> "ScanProfile":
        """A copy with some fields replaced."""
        return replace(self, **changes)


FAST = ScanProfile(
    id="fast",
    name="Fast",
    description="Skips archives and large files. Good for a quick look at a "
                "downloads folder.",
    scan_archives=False,
    max_file_size="25M",
    max_scan_size="50M",
    max_recursion=8,
    max_scan_time_ms=30000,
    detect_pua=False,
    scan_image=False,
)

BALANCED = ScanProfile(
    id="balanced",
    name="Balanced",
    description="ClamAV's normal settings. What you want almost all the time.",
)

THOROUGH = ScanProfile(
    id="thorough",
    name="Thorough",
    description="Deep archive recursion, unwanted-program detection and alerts "
                "on anything suspicious. Slower, and more false alarms.",
    max_file_size="500M",
    max_scan_size="2000M",
    max_recursion=30,
    max_files=50000,
    max_scan_time_ms=600000,
    detect_pua=True,
    alert_broken=True,
    alert_encrypted=True,
    alert_macros=True,
    alert_exceeds_max=True,
    cross_filesystems=True,
)

#: The profiles offered in the scan page, in order.
PRESETS: tuple[ScanProfile, ...] = (FAST, BALANCED, THOROUGH)

PRESETS_BY_ID = {profile.id: profile for profile in PRESETS}
DEFAULT_PROFILE_ID = BALANCED.id


def profile(profile_id: str) -> ScanProfile:
    """Look up a preset, falling back to Balanced."""
    return PRESETS_BY_ID.get(profile_id, BALANCED)
