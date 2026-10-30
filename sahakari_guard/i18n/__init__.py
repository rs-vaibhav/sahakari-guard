"""Translations (English, Tamil, Hindi).

One JSON file per language holds every user-facing string, used both by the
server (alert text, reports, notifications) and by the web dashboard. Missing
keys fall back to English, and missing placeholders are left visible rather
than raising an error.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from sahakari_guard.config import SUPPORTED_LANGUAGES
from sahakari_guard.money import format_inr
from sahakari_guard.timeutil import fmt_ist, parse_ts

DEFAULT_LANG = "en"


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


@lru_cache(maxsize=None)
def catalog(lang: str) -> dict[str, Any]:
    if lang not in SUPPORTED_LANGUAGES:
        lang = DEFAULT_LANG
    text = resources.files("sahakari_guard.i18n").joinpath(f"{lang}.json").read_text(encoding="utf-8")
    return json.loads(text)


def normalise_lang(lang: str | None) -> str:
    lang = (lang or DEFAULT_LANG).lower()[:2]
    return lang if lang in SUPPORTED_LANGUAGES else DEFAULT_LANG


def t(lang: str, key: str, **params: Any) -> Any:
    """Translate ``key``. Lists (e.g. recommended actions) are returned as lists."""
    value = catalog(normalise_lang(lang)).get(key)
    if value is None:
        value = catalog(DEFAULT_LANG).get(key, key)
    if isinstance(value, str) and params:
        return value.format_map(_SafeDict(params))
    return value


AMOUNT_KEYS = ("amount", "switch_amount", "ledger_amount")


def render_alert(lang: str, rule_id: str, params: dict[str, Any]) -> dict[str, str]:
    """Return {'name', 'message'} for an alert, with amounts formatted in rupees."""
    lang = normalise_lang(lang)
    fmt = dict(params)
    for key in AMOUNT_KEYS:
        if isinstance(fmt.get(key), int):
            fmt[key] = format_inr(fmt[key])
    if fmt.get("direction"):
        fmt["direction_word"] = t(lang, "word.debit" if fmt["direction"] == "DR" else "word.credit")
    if fmt.get("feed"):
        fmt["feed_name"] = t(lang, f"word.feed.{fmt['feed']}")
    if rule_id == "SG-R5":
        variant = fmt.get("variant", "account")
        message = t(lang, f"rule.SG-R5.{variant}.message", **fmt)
    else:
        message = t(lang, f"rule.{rule_id}.message", **fmt)
    return {"name": t(lang, f"rule.{rule_id}.name"), "message": message}


def format_event_time(value: str | None) -> str:
    if not value:
        return "-"
    return fmt_ist(parse_ts(value))
