"""The one architectural rule, enforced.

`clamguard.core` must not import QtWidgets, QtGui or anything from
`clamguard.ui`. That is what keeps the logic testable without a display, and
it is easy to break by accident with a stray import, so it is a test.
"""

from __future__ import annotations

import ast
import unittest

from .support import REPO_ROOT

FORBIDDEN_PREFIXES = ("PySide6.QtWidgets", "PySide6.QtGui", "clamguard.ui")
CORE = REPO_ROOT / "src" / "clamguard" / "core"


class TestLayering(unittest.TestCase):
    def test_core_does_not_import_the_ui_layer(self) -> None:
        offences = []
        for path in sorted(CORE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                    # A relative import inside core can never reach ui, since ui
                    # is a sibling package: "from ..ui import x" would be level 2.
                    if node.level and node.level >= 2 and (node.module or "").startswith("ui"):
                        names.append("clamguard.ui")
                else:
                    continue
                for name in names:
                    if any(name.startswith(prefix) for prefix in FORBIDDEN_PREFIXES):
                        offences.append(f"{path.name}:{node.lineno} imports {name}")

        self.assertEqual(
            offences, [],
            "core/ must stay free of widgets so it can be tested headless:\n  "
            + "\n  ".join(offences),
        )

    def test_every_core_module_has_a_docstring(self) -> None:
        missing = [
            path.name for path in sorted(CORE.rglob("*.py"))
            if not ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")))
        ]
        self.assertEqual(missing, [],
                         "every module explains what it is for: " + ", ".join(missing))


if __name__ == "__main__":
    unittest.main()
