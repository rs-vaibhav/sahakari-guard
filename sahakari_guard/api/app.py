"""HTTP API and static dashboard (FastAPI).

Run with ``python -m sahakari_guard serve``. By default the server listens on
127.0.0.1 only. Set ``SG_API_KEY`` to require an ``X-API-Key`` header on every
API call when exposing it on a bank LAN.
"""

from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sahakari_guard import __version__
from sahakari_guard.config import SUPPORTED_LANGUAGES, Settings, load_settings
from sahakari_guard.i18n import catalog, normalise_lang
from sahakari_guard.incidents.manager import InvalidTransition, NotFound
from sahakari_guard.ingest.parsers import IngestError, write_ledger_csv, write_settlement_csv, write_switch_csv
from sahakari_guard.models import event_sort_key
from sahakari_guard.service import Busy, GuardService
from sahakari_guard.simulator.scenarios import SCENARIOS, build_day

log = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_MASK_BYTES = 20 * 1024 * 1024
MAX_TEXT_CHARS = 200_000

WEB_DIR = Path(str(resources.files("sahakari_guard").joinpath("web")))

DASHBOARD_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)
REPORT_CSP = (
    "default-src 'none'; img-src 'self' data:; font-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


# ---------------------------------------------------------------------- request bodies

class OfficerAction(BaseModel):
    officer: str = Field(..., min_length=2, max_length=120)
    note: str = Field("", max_length=500)


class DismissBody(BaseModel):
    officer: str = Field(..., min_length=2, max_length=120)
    reason: str = Field(..., min_length=3, max_length=500)


class ReportedBody(BaseModel):
    officer: str = Field(..., min_length=2, max_length=120)
    daksh_ref: str = Field(..., min_length=2, max_length=80)
    certin_ref: str = Field("", max_length=80)


class DemoBody(BaseModel):
    scenario: str
    speed: int = 120
    seed: int = Field(42, ge=0, le=10_000_000)
    transactions: int = Field(12_000, ge=1000, le=200_000)
    instant: bool = False


class NetworkBody(BaseModel):
    online: bool


class MaskTextBody(BaseModel):
    text: str = Field(..., max_length=MAX_TEXT_CHARS)


class BenchBody(BaseModel):
    seed: int = Field(42, ge=0, le=10_000_000)
    transactions: int = Field(12_000, ge=1000, le=100_000)


# ---------------------------------------------------------------------- helpers

async def _read_limited(upload: UploadFile, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise PayloadTooLarge(f"{upload.filename}: file is larger than {limit // (1024 * 1024)} MB")
        chunks.append(chunk)
    return b"".join(chunks)


class PayloadTooLarge(ValueError):
    pass


@lru_cache(maxsize=16)
def _sample_csv(scenario: str, kind: str) -> str:
    day = build_day(scenario, seed=7, transactions=1500)
    if kind == "switch":
        return write_switch_csv(sorted(day.switch, key=event_sort_key))
    if kind == "ledger":
        return write_ledger_csv(sorted(day.ledger, key=event_sort_key))
    return write_settlement_csv(sorted(day.settlement, key=event_sort_key))


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


# ---------------------------------------------------------------------- app factory

def create_app(settings: Settings | None = None, service: GuardService | None = None, *, background: bool = True) -> FastAPI:
    settings = settings or (service.settings if service else load_settings())
    svc = service or GuardService(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if background:
            svc.start_background()
        try:
            yield
        finally:
            if background:
                svc.stop_background()

    app = FastAPI(
        title="Sahakari-Guard",
        version=__version__,
        description="Watch-only fraud watchdog, privacy shield and 6-hour incident kit for co-operative banks.",
        lifespan=lifespan,
    )
    app.state.service = svc

    # ------------------------------------------------------------ middleware

    @app.middleware("http")
    async def security(request: Request, call_next):
        path = request.url.path
        if settings.api_key and path.startswith("/api/") and path != "/api/health":
            supplied = request.headers.get("x-api-key") or request.query_params.get("key") or ""
            if not hmac.compare_digest(supplied.encode(), settings.api_key.encode()):
                return _error(401, "missing or invalid API key")
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if path not in ("/docs", "/redoc", "/docs/oauth2-redirect"):  # FastAPI's API explorer loads its own assets
            response.headers.setdefault("Content-Security-Policy", REPORT_CSP if path.endswith("/report.html") else DASHBOARD_CSP)
        if path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # ------------------------------------------------------------ errors

    @app.exception_handler(NotFound)
    async def _not_found(_: Request, exc: NotFound):
        return _error(404, f"not found: {exc.args[0] if exc.args else ''}")

    @app.exception_handler(InvalidTransition)
    async def _conflict(_: Request, exc: InvalidTransition):
        return _error(409, str(exc))

    @app.exception_handler(Busy)
    async def _busy(_: Request, exc: Busy):
        return _error(409, str(exc))

    @app.exception_handler(PayloadTooLarge)
    async def _too_large(_: Request, exc: PayloadTooLarge):
        return _error(413, str(exc))

    @app.exception_handler(IngestError)
    async def _ingest(_: Request, exc: IngestError):
        return _error(400, str(exc))

    @app.exception_handler(ValueError)
    async def _value(_: Request, exc: ValueError):
        return _error(400, str(exc))

    # ------------------------------------------------------------ pages

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    # ------------------------------------------------------------ meta

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return svc.config()

    @app.get("/api/i18n/{lang}")
    def i18n(lang: str) -> dict[str, Any]:
        if lang not in SUPPORTED_LANGUAGES:
            raise NotFound(lang)
        return catalog(lang)

    @app.get("/api/summary")
    def summary(lang: str = "en") -> dict[str, Any]:
        return svc.summary(lang)

    # ------------------------------------------------------------ alerts

    @app.get("/api/alerts")
    def alerts(
        lang: str = "en",
        severity: str | None = None,
        rule: str | None = None,
        status: str | None = None,
        incident: str | None = None,
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        return svc.list_alerts(
            lang, severity=severity, rule_id=rule, status=status, incident_id=incident, limit=limit, offset=offset
        )

    @app.get("/api/alerts/{alert_id}")
    def alert(alert_id: str, lang: str = "en") -> dict[str, Any]:
        return svc.get_alert(alert_id, lang)

    # ------------------------------------------------------------ incidents

    @app.get("/api/incidents")
    def incidents(lang: str = "en", status: str | None = None) -> list[dict[str, Any]]:
        return svc.list_incidents(lang, status)

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str, lang: str = "en") -> dict[str, Any]:
        return svc.get_incident(incident_id, lang)

    @app.post("/api/incidents/{incident_id}/confirm")
    def confirm(incident_id: str, body: OfficerAction) -> dict[str, Any]:
        return svc.confirm_incident(incident_id, body.officer, body.note)

    @app.post("/api/incidents/{incident_id}/dismiss")
    def dismiss(incident_id: str, body: DismissBody) -> dict[str, Any]:
        return svc.dismiss_incident(incident_id, body.officer, body.reason)

    @app.post("/api/incidents/{incident_id}/reported")
    def reported(incident_id: str, body: ReportedBody) -> dict[str, Any]:
        return svc.mark_reported(incident_id, body.officer, body.daksh_ref, body.certin_ref)

    @app.get("/api/incidents/{incident_id}/report.json")
    def report_json(incident_id: str, lang: str = "en", download: bool = False) -> JSONResponse:
        report = svc.report(incident_id, normalise_lang(lang))
        headers = {"Content-Disposition": f'attachment; filename="{incident_id}-{report["language"]}.json"'} if download else {}
        return JSONResponse(report, headers=headers)

    @app.get("/api/incidents/{incident_id}/report.html", response_class=HTMLResponse)
    def report_html(incident_id: str, lang: str = "en") -> HTMLResponse:
        return HTMLResponse(svc.report_html(incident_id, normalise_lang(lang)))

    # ------------------------------------------------------------ ingest

    @app.post("/api/upload")
    async def upload(files: list[UploadFile] = File(...)) -> dict[str, Any]:
        if len(files) > 3:
            raise IngestError("upload at most three files: switch log, ledger and settlement")
        payload = [(f.filename or "upload.csv", await _read_limited(f, MAX_UPLOAD_BYTES)) for f in files]
        return svc.scan_uploads(payload)

    @app.get("/api/samples/{scenario}/{kind}.csv")
    def sample(scenario: str, kind: str) -> Response:
        if scenario not in SCENARIOS or kind not in ("switch", "ledger", "settlement"):
            raise NotFound(f"{scenario}/{kind}")
        filename = {"switch": "switch_log", "ledger": "cbs_ledger", "settlement": "settlement"}[kind]
        return Response(
            _sample_csv(scenario, kind),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{scenario}_{filename}.csv"'},
        )

    # ------------------------------------------------------------ demo & benchmark

    @app.post("/api/demo/start")
    def demo_start(body: DemoBody) -> dict[str, Any]:
        return svc.demo.start(body.scenario, body.speed, body.seed, body.transactions, body.instant)

    @app.post("/api/demo/stop")
    def demo_stop() -> dict[str, Any]:
        return svc.demo.stop()

    @app.get("/api/demo/status")
    def demo_status() -> dict[str, Any]:
        return svc.demo.status()

    @app.post("/api/reset")
    def reset() -> dict[str, Any]:
        svc.reset()
        return {"ok": True}

    @app.get("/api/benchmark")
    def benchmark() -> dict[str, Any]:
        return svc.bench.status()

    @app.post("/api/benchmark/run")
    def benchmark_run(body: BenchBody) -> dict[str, Any]:
        return svc.bench.start(body.seed, body.transactions)

    # ------------------------------------------------------------ privacy

    @app.post("/api/privacy/mask-text")
    def privacy_text(body: MaskTextBody) -> dict[str, Any]:
        return svc.mask_text(body.text)

    @app.post("/api/privacy/mask-csv")
    async def privacy_csv(file: UploadFile = File(...)) -> dict[str, Any]:
        data = await _read_limited(file, MAX_MASK_BYTES)
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise IngestError(f"{file.filename}: file is not UTF-8 text") from exc
        result = svc.mask_csv(text)
        result["filename"] = (Path(file.filename or "data.csv").stem or "data") + "_masked.csv"
        return result

    # ------------------------------------------------------------ outbox / network

    @app.get("/api/outbox")
    def outbox(limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
        return {"online": svc.network.online, "items": svc.outbox(limit), "counts": svc.repo.outbox_counts()}

    @app.post("/api/network")
    def network(body: NetworkBody) -> dict[str, Any]:
        return svc.set_network(body.online)

    @app.post("/api/outbox/flush")
    def flush() -> dict[str, Any]:
        return svc.flush_outbox()

    return app
