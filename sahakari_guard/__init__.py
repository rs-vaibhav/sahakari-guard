"""Sahakari-Guard: a watch-only fraud watchdog, privacy shield and
6-hour cyber-incident reporting kit for India's co-operative banks.

The package is organised in layers that depend only "downwards":

    api / cli / demo            <- entry points (I/O, HTTP, threads)
    service                     <- orchestration, transactions, persistence
    engine / incidents / reports / notify / privacy / ingest
    models / money / timeutil   <- pure data types and helpers

The detection engine (``sahakari_guard.engine``) is pure Python with no I/O,
which keeps it deterministic and easy to test.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
