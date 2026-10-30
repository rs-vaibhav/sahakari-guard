"""Runtime configuration.

Settings come from (lowest to highest priority):

1. built-in defaults below,
2. an optional TOML file (``SG_CONFIG`` env var or ``--config``),
3. environment variables (``SG_DATA_DIR``, ``SG_TOKEN_SECRET``, ...).

See ``sahakari_guard.example.toml`` in the repository root.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = None  # type: ignore[assignment]


@dataclass(frozen=True)
class BankProfile:
    """Identity of the reporting entity, printed on incident reports."""

    name: str = "Demo Urban Co-operative Bank Ltd."
    code: str = "DEMO-UCB-001"
    location: str = "Chengalpattu, Tamil Nadu"
    regulator_category: str = "Urban Co-operative Bank (Tier 2)"
    reporting_officer: str = "Chief Information Security Officer"
    officer_email: str = "ciso@demo-ucb.example"
    officer_phone: str = "+91-44-0000-0000"


@dataclass(frozen=True)
class EngineSettings:
    """Detection thresholds. All durations are in seconds."""

    # A switch approval and its ledger posting must meet within this window.
    match_window_seconds: int = 180
    # How long evaluated transactions are kept so late postings can auto-resolve alerts.
    retention_seconds: int = 48 * 3600
    # Velocity (burst) rule, per account.
    velocity_window_seconds: int = 600
    velocity_debit_threshold: int = 8
    velocity_credit_threshold: int = 30
    # Bank-wide foreign cash-out pattern.
    foreign_window_seconds: int = 900
    foreign_count_threshold: int = 25
    foreign_country_threshold: int = 5
    # A burst keeps updating the same alert until it has been quiet this long.
    velocity_cooldown_seconds: int = 1800
    home_country: str = "IN"
    # Maximum masked evidence rows kept per alert.
    evidence_limit: int = 25


@dataclass(frozen=True)
class IncidentSettings:
    # Alerts of the same family closer than this (event time) join one incident.
    group_window_seconds: int = 3600
    # RBI (DAKSH) and CERT-In both expect reporting within six hours of detection.
    reporting_deadline_hours: int = 6


@dataclass(frozen=True)
class Settings:
    bank: BankProfile = field(default_factory=BankProfile)
    engine: EngineSettings = field(default_factory=EngineSettings)
    incidents: IncidentSettings = field(default_factory=IncidentSettings)
    data_dir: Path = Path("data")
    default_language: str = "en"
    # HMAC key for pseudonymous account tokens. Generated and stored on first run.
    token_secret: str = ""
    # Optional HTTPS endpoint (SMS gateway / chat webhook) for alert delivery.
    webhook_url: str = ""
    # Optional API key; when set every /api call must send X-API-Key.
    api_key: str = ""

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sahakari_guard.db"


SUPPORTED_LANGUAGES = ("en", "ta", "hi")


def _coerce(section_cls: type, values: dict[str, Any]) -> Any:
    """Build a frozen dataclass from a dict, ignoring unknown keys but checking types."""
    known = {f.name: f for f in fields(section_cls)}
    kwargs: dict[str, Any] = {}
    for key, value in values.items():
        if key not in known:
            raise ValueError(f"unknown setting '{key}' in [{section_cls.__name__}]")
        default = getattr(section_cls(), key)
        if isinstance(default, bool):
            kwargs[key] = bool(value)
        elif isinstance(default, int):
            kwargs[key] = int(value)
            if kwargs[key] < 0:
                raise ValueError(f"setting '{key}' must not be negative")
        else:
            kwargs[key] = str(value)
    return section_cls(**kwargs)


def _load_or_create_secret(data_dir: Path) -> str:
    data_dir.mkdir(parents=True, exist_ok=True)
    secret_file = data_dir / ".token_secret"
    if secret_file.exists():
        value = secret_file.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_hex(32)
    secret_file.write_text(value, encoding="utf-8")
    try:
        os.chmod(secret_file, 0o600)
    except OSError:  # pragma: no cover - e.g. Windows
        pass
    return value


def load_settings(config_path: str | os.PathLike[str] | None = None, *, data_dir: str | os.PathLike[str] | None = None) -> Settings:
    """Load settings from defaults, optional TOML and environment variables."""
    settings = Settings()
    path = config_path or os.environ.get("SG_CONFIG")
    if path:
        if tomllib is None:  # pragma: no cover
            raise RuntimeError("TOML config files need Python 3.11+; use environment variables instead")
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
        settings = replace(
            settings,
            bank=_coerce(BankProfile, raw.get("bank", {})),
            engine=_coerce(EngineSettings, raw.get("engine", {})),
            incidents=_coerce(IncidentSettings, raw.get("incidents", {})),
        )
        general = raw.get("general", {})
        if "data_dir" in general:
            settings = replace(settings, data_dir=Path(general["data_dir"]))
        if "default_language" in general:
            settings = replace(settings, default_language=str(general["default_language"]))
        if "webhook_url" in general:
            settings = replace(settings, webhook_url=str(general["webhook_url"]))

    env = os.environ
    if data_dir is not None:
        settings = replace(settings, data_dir=Path(data_dir))
    elif env.get("SG_DATA_DIR"):
        settings = replace(settings, data_dir=Path(env["SG_DATA_DIR"]))
    if env.get("SG_WEBHOOK_URL"):
        settings = replace(settings, webhook_url=env["SG_WEBHOOK_URL"])
    if env.get("SG_API_KEY"):
        settings = replace(settings, api_key=env["SG_API_KEY"])
    if env.get("SG_LANGUAGE"):
        settings = replace(settings, default_language=env["SG_LANGUAGE"])

    if settings.default_language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"default_language must be one of {SUPPORTED_LANGUAGES}")

    secret = env.get("SG_TOKEN_SECRET") or _load_or_create_secret(settings.data_dir)
    settings = replace(settings, token_secret=secret)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return settings
