"""Hunt — find every log on this machine, convert it, and query it in KQL.

The package has four layers and they only ever point downwards:

    indexer  ──▶ discovery ──▶ formats      find files, work out what they are
       │     ──▶ store                      write normalised events to SQLite
       │
    kql/     ──▶ store                      read them back, fast

Nothing here imports Qt except :mod:`indexer`, which is the thread wrapper.
See ``ARCHITECTURE.md`` for how the pieces fit and ``docs/KQL.md`` for the
query language.
"""
