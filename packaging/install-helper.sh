#!/usr/bin/env bash
#
# Installs the ClamGuard privileged helper. Run this yourself, with sudo:
#
#     sudo ./packaging/install-helper.sh
#
# ClamGuard never runs this for you. Until it has been run, the app works
# normally but cannot change system configuration, control ClamAV's services,
# or trigger a signature update — it will tell you so and point back here.
#
# To remove everything this installs:
#
#     sudo ./packaging/install-helper.sh --uninstall
#
set -euo pipefail

HELPER_DIR=/usr/local/lib/clamguard
HELPER_PATH="$HELPER_DIR/clamguard-helper"
POLICY_PATH=/usr/share/polkit-1/actions/org.clamguard.helper.policy
LOG_PATH=/var/log/clamguard-helper.log
# Where the helper keeps its own account of what it quarantined. Restoring a
# file trusts this and nothing else, so it must be root-only.
RECORD_DIR=/var/lib/clamguard/records
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then
    echo "This script needs root. Run: sudo $0" >&2
    exit 1
fi

if [[ "${1:-}" == "--uninstall" ]]; then
    rm -f "$HELPER_PATH" "$POLICY_PATH"
    rmdir --ignore-fail-on-non-empty "$HELPER_DIR" 2>/dev/null || true
    echo "Removed the ClamGuard helper and its polkit policy."
    echo
    echo "Left in place, because removing them loses information:"
    echo "  $LOG_PATH  (what the helper did, and when)"
    if [[ -d "$RECORD_DIR" ]]; then
        echo "  $RECORD_DIR  ($(find "$RECORD_DIR" -name '*.json' | wc -l) quarantine records)"
        echo
        echo "Delete the records only once you have restored or discarded anything"
        echo "still in your quarantine — without them a privileged restore cannot"
        echo "know where a file came from."
    fi
    exit 0
fi

for required in "$SOURCE_DIR/clamguard-helper" "$SOURCE_DIR/org.clamguard.helper.policy"; do
    [[ -f "$required" ]] || { echo "Missing $required" >&2; exit 1; }
done

if [[ -f "$HELPER_PATH" ]]; then
    echo "Replacing the helper already installed at $HELPER_PATH."
    echo "(No need to uninstall first — this overwrites it in place.)"
else
    echo "Installing the ClamGuard privileged helper."
fi
echo "  helper  -> $HELPER_PATH"
echo "  policy  -> $POLICY_PATH"
echo "  records -> $RECORD_DIR"
echo

install -d -m 0755 "$HELPER_DIR"
install -m 0755 -o root -g root "$SOURCE_DIR/clamguard-helper" "$HELPER_PATH"
install -m 0644 -o root -g root "$SOURCE_DIR/org.clamguard.helper.policy" "$POLICY_PATH"

touch "$LOG_PATH"
chmod 0640 "$LOG_PATH"
chown root:root "$LOG_PATH"

# Created here rather than on first use so its permissions never depend on
# whatever umask the helper happened to inherit.
install -d -m 0700 -o root -g root "$RECORD_DIR"

# Refuse to leave a helper that does not even parse.
if ! python3 -c "import ast,sys; ast.parse(open('$HELPER_PATH').read())"; then
    echo "The installed helper does not parse; removing it again." >&2
    rm -f "$HELPER_PATH"
    exit 1
fi

echo "Done. Checking that it responds:"
"$HELPER_PATH" status | head -4

cat <<'NOTE'

The helper is now installed. ClamGuard will ask polkit for permission each time
it needs to do something privileged, and every such action is logged to
/var/log/clamguard-helper.log.

Read /usr/local/lib/clamguard/clamguard-helper if you have not already; it is
the only part of ClamGuard that runs as root.
NOTE
