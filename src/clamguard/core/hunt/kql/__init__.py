"""A Kusto Query Language implementation, in Python, for local log files.

The public surface is small::

    from clamguard.core.hunt.kql import run, parse, check

    table = run("Logs | where Level == 'error' | take 50", connection)

Everything else — the lexer, the AST, the pushdown planner, the function
library — is an implementation detail of those three.

Why write this rather than bind to an existing engine: ``kusto-loco`` is the
right project and the wrong runtime. It is C# on .NET; ClamGuard is Python
with PySide6 and a hard rule against new dependencies. So the language is
ours. Its operator coverage is what this aims at.

What is deliberately *not* implemented: anything that reaches outside the
store. There is no ``externaldata``, no ``evaluate`` plugin, no
``http_request``, and no user-supplied Python. A query is a pure function from
the local database to a table.
"""

from .errors import KqlError
from .parser import parse
from .engine import Engine, check, describe_plan, run

__all__ = ["Engine", "KqlError", "check", "describe_plan", "parse", "run"]
