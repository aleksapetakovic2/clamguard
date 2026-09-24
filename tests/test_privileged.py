"""The privilege bridge, and the helper script's own shape.

The helper is not executed here — that would need root — but its source is
checked, because a typo in its allow-lists is a security problem and a syntax
error in it makes every privileged feature fail at the worst moment.
"""

from __future__ import annotations

import ast
import unittest

from .support import REPO_ROOT, qt_application

from clamguard.core.privileged import (
    HelperAvailability,
    PrivilegedHelper,
    describe,
    install_command,
    parse_json_output,
)

HELPER = REPO_ROOT / "packaging" / "clamguard-helper"
POLICY = REPO_ROOT / "packaging" / "org.clamguard.helper.policy"


class TestAvailability(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()

    def test_probing_never_runs_the_helper(self) -> None:
        """Running it would put a password prompt on screen at start-up."""
        helper = PrivilegedHelper()
        self.assertIsInstance(helper.available, bool)

    def test_every_missing_piece_has_an_explanation(self) -> None:
        cases = [
            HelperAvailability(False, False, False),
            HelperAvailability(False, False, True),
            HelperAvailability(True, False, True),
            HelperAvailability(True, True, True),
        ]
        for availability in cases:
            self.assertTrue(availability.reason().endswith("."), availability)

    def test_usable_needs_the_helper_and_pkexec(self) -> None:
        self.assertTrue(HelperAvailability(True, True, True).usable)
        self.assertTrue(HelperAvailability(True, False, True).usable)
        self.assertFalse(HelperAvailability(False, True, True).usable)
        self.assertFalse(HelperAvailability(True, True, False).usable)

    def test_the_install_command_points_at_the_real_script(self) -> None:
        command = install_command()
        self.assertTrue(command.startswith("sudo "))
        self.assertIn("install-helper.sh", command)


class TestDescriptions(unittest.TestCase):
    def test_every_verb_is_described_in_plain_words(self) -> None:
        self.assertIn("/etc/clamav/clamd.conf",
                      describe("write-config", ["/etc/clamav/clamd.conf"]))
        self.assertIn("clamav-daemon.service",
                      describe("service", ["restart", "clamav-daemon.service"]))
        self.assertIn("signatures", describe("update-db", []))
        self.assertIn("quarantine", describe("quarantine", ["/tmp/x", "/vault/y"]))
        self.assertTrue(describe("something-new", []))


class TestJsonOutput(unittest.TestCase):
    def test_plain_json(self) -> None:
        self.assertEqual(parse_json_output('{"written": "/etc/x"}'),
                         {"written": "/etc/x"})

    def test_json_after_other_output(self) -> None:
        self.assertEqual(parse_json_output('noise\nmore noise\n{"a": 1}'), {"a": 1})

    def test_nothing_parseable(self) -> None:
        self.assertEqual(parse_json_output("not json at all"), {})
        self.assertEqual(parse_json_output(""), {})


class TestHelperSource(unittest.TestCase):
    """The helper runs as root, so its shape is part of the test suite."""

    def setUp(self) -> None:
        self.source = HELPER.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_it_parses(self) -> None:
        self.assertTrue(self.tree.body)

    def test_it_imports_nothing_from_clamguard(self) -> None:
        """The root helper must not depend on the application it serves."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                self.assertFalse(name.startswith("clamguard"), name)
                self.assertFalse(name.startswith("PySide6"), name)

    def test_every_verb_has_a_handler(self) -> None:
        namespace: dict = {}
        exec(compile(self.source.replace('if __name__ == "__main__":', "if False:"),
                     "helper", "exec"), namespace)
        self.assertEqual(set(namespace["VERBS"]), set(namespace["HANDLERS"]))

    def test_the_allow_lists_are_not_empty(self) -> None:
        namespace: dict = {}
        exec(compile(self.source.replace('if __name__ == "__main__":', "if False:"),
                     "helper", "exec"), namespace)
        self.assertTrue(namespace["CONFIG_FILES"])
        self.assertTrue(namespace["UNITS"])
        self.assertTrue(namespace["UNIT_ACTIONS"])
        # Only ClamAV's own units, nothing else on the system.
        for unit in namespace["UNITS"]:
            self.assertTrue("clam" in unit or "freshclam" in unit, unit)
        # Only ClamAV's own configuration, nothing else in /etc.
        for path in namespace["CONFIG_FILES"]:
            self.assertTrue(path.startswith("/etc/") or path.startswith("/usr/local/etc/"),
                            path)
            self.assertTrue("clam" in path or "freshclam" in path, path)

    def test_it_refuses_to_run_unprivileged(self) -> None:
        self.assertIn("os.geteuid() != 0", self.source)

    def test_dangerous_restore_targets_are_blocked(self) -> None:
        namespace: dict = {}
        exec(compile(self.source.replace('if __name__ == "__main__":', "if False:"),
                     "helper", "exec"), namespace)
        forbidden = namespace["FORBIDDEN_RESTORE_PREFIXES"]
        for prefix in ("/usr/", "/bin/", "/etc/sudoers", "/etc/pam.d/"):
            self.assertIn(prefix, forbidden)

    def test_the_polkit_policy_points_at_the_installed_helper(self) -> None:
        import xml.dom.minidom

        document = xml.dom.minidom.parse(str(POLICY))
        annotations = document.getElementsByTagName("annotate")
        paths = [node.firstChild.data for node in annotations
                 if node.getAttribute("key").endswith("exec.path")]
        self.assertEqual(paths, ["/usr/local/lib/clamguard/clamguard-helper"])

    def test_the_policy_requires_administrator_authentication(self) -> None:
        text = POLICY.read_text()
        self.assertIn("auth_admin", text)
        self.assertNotIn("<allow_any>yes</allow_any>", text)
        self.assertNotIn("<allow_active>yes</allow_active>", text)


if __name__ == "__main__":
    unittest.main()
