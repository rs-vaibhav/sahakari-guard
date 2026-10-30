"""Command-line interface.

    python -m sahakari_guard serve                  # dashboard on http://127.0.0.1:8000
    python -m sahakari_guard simulate --scenario cosmos --out sample_data/cosmos
    python -m sahakari_guard scan --switch s.csv --ledger l.csv [--settlement n.csv]
    python -m sahakari_guard watch --inbox ./inbox [--clock wall]
    python -m sahakari_guard mask input.csv --out masked.csv
    python -m sahakari_guard bench [--out docs/BENCHMARK.md]
    python -m sahakari_guard report INC-20261101-0001 --lang ta --out report.html
    python -m sahakari_guard reset
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from sahakari_guard import __version__
from sahakari_guard.config import SUPPORTED_LANGUAGES, load_settings


def _settings(args: argparse.Namespace):
    return load_settings(args.config, data_dir=args.data_dir)


def _service(args: argparse.Namespace):
    from sahakari_guard.service import GuardService

    return GuardService(_settings(args))


def _print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:  # e.g. Windows console without UTF-8
        print(text.encode("ascii", "replace").decode("ascii"))


# ---------------------------------------------------------------------- commands

def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from sahakari_guard.api.app import create_app
    from sahakari_guard.service import GuardService

    settings = _settings(args)
    service = GuardService(settings)
    watcher = None
    if args.watch_inbox:
        from sahakari_guard.watcher import FolderWatcher

        watcher = FolderWatcher(service, args.watch_inbox, interval=args.interval, clock=args.clock)
        watcher.start()
    app = create_app(settings, service)
    _print(f"Sahakari-Guard {__version__} - open http://{args.host}:{args.port} in your browser (Ctrl+C to stop)")
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    finally:
        if watcher:
            watcher.stop()
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    from sahakari_guard.simulator.scenarios import build_day

    day = build_day(args.scenario, seed=args.seed, transactions=args.transactions)
    paths = day.write_csvs(args.out)
    _print(f"Wrote synthetic '{args.scenario}' day ({len(day.switch)} switch, {len(day.ledger)} ledger, "
           f"{len(day.settlement)} settlement lines):")
    for kind, path in paths.items():
        _print(f"  {kind:<10} {path}")
    if day.injection:
        truth = Path(args.out) / "ground_truth.json"
        truth.write_text(json.dumps({
            "scenario": day.injection.scenario,
            "start": day.injection.start.isoformat(),
            "end": day.injection.end.isoformat(),
            "attack_rrns": sorted(day.injection.rrns),
            "expected_rules": sorted(day.injection.expected_rules),
        }, indent=2), encoding="utf-8")
        _print(f"  {'truth':<10} {truth}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from sahakari_guard.i18n import render_alert

    svc = _service(args)
    paths = [p for p in (args.switch, args.ledger, args.settlement) if p]
    uploads = [(Path(p).name, Path(p).read_bytes()) for p in paths]
    result = svc.scan_uploads(uploads)
    if args.json:
        _print(json.dumps(result, indent=2, default=str))
        return 0
    stats = result["stats"]
    _print(f"Run {result['run_id']}: {stats['events']} lines, {stats['matched']} matched, "
           f"{stats['mismatched']} mismatched, {result['new_alerts']} new alerts, "
           f"{len(result['new_incidents'])} new incidents")
    for f in result["files"]:
        _print(f"  {f['kind']:<10} {f['name']}: {f['parsed']}/{f['rows']} rows parsed, {f['rejected']} rejected")
        for err in f["errors"][:5]:
            _print(f"      line {err['line']}: {err['message']}")
    alerts, total = svc.repo.list_alerts(status="OPEN", limit=args.limit)
    if total:
        _print(f"\nOpen alerts ({total}, showing {len(alerts)}):")
        for a in alerts:
            text = render_alert(args.lang, a["rule_id"], a["params"])
            _print(f"  [{a['severity']:<8}] {a['rule_id']} {a['rrn'] or '-':<14} {text['message']}")
    for inc in svc.repo.list_incidents():
        if inc["incident_id"] in result["new_incidents"]:
            _print(f"\nIncident {inc['incident_id']} ({inc['family']}, {inc['severity']}) - report due by {inc['deadline_at'] or 'n/a'}")
    return 1 if total and args.fail_on_alert else 0


def cmd_watch(args: argparse.Namespace) -> int:
    from sahakari_guard.watcher import FolderWatcher

    svc = _service(args)
    svc.start_background()
    watcher = FolderWatcher(svc, args.inbox, interval=args.interval, clock=args.clock)
    _print(f"Watching {args.inbox} (Ctrl+C to stop). Open the dashboard with 'serve' to see alerts.")
    try:
        watcher.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop_background()
    return 0


def cmd_mask(args: argparse.Namespace) -> int:
    from sahakari_guard.privacy.masker import mask_csv_text, mask_text
    from sahakari_guard.privacy.tokenizer import Tokenizer

    src = Path(args.input)
    content = src.read_text(encoding="utf-8-sig")
    out = Path(args.out) if args.out else src.with_name(src.stem + "_masked" + src.suffix)
    if src.suffix.lower() == ".csv":
        settings = _settings(args)
        masked, report = mask_csv_text(content, tokenizer=Tokenizer(settings.token_secret))
        out.write_text(masked, encoding="utf-8", newline="")
        _print(f"Masked {report.rows} rows -> {out}")
        _print("Column policies: " + ", ".join(f"{k}={v}" for k, v in report.columns.items()))
        _print("Identifiers masked: " + (", ".join(f"{k}={v}" for k, v in report.counts.items()) or "none"))
    else:
        result = mask_text(content)
        out.write_text(result.text, encoding="utf-8")
        _print(f"Masked text -> {out}; identifiers masked: {dict(result.counts) or 'none'}")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from sahakari_guard.bench import run_benchmark, to_markdown

    result = run_benchmark(seed=args.seed, transactions=args.transactions)
    md = to_markdown(result)
    _print(md)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(md, encoding="utf-8")
        _print(f"Saved {args.out}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
        _print(f"Saved {args.json}")
    missed = [r["scenario"] for r in result["results"] if r["detected"] is False]
    return 1 if missed else 0


def cmd_report(args: argparse.Namespace) -> int:
    svc = _service(args)
    if args.format == "json":
        text = json.dumps(svc.report(args.incident_id, args.lang), indent=2, ensure_ascii=False)
    else:
        text = svc.report_html(args.incident_id, args.lang)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        _print(f"Saved {args.out}")
    else:
        _print(text)
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    svc = _service(args)
    svc.reset()
    _print("All alerts, incidents, runs and statistics deleted.")
    return 0


# ---------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    from sahakari_guard.simulator.scenarios import SCENARIOS

    parser = argparse.ArgumentParser(prog="sahakari-guard", description="Sahakari-Guard command line")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", help="TOML settings file (default: SG_CONFIG env var)")
    parser.add_argument("--data-dir", help="folder for the database and keys (default: ./data or SG_DATA_DIR)")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the web dashboard and API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--watch-inbox", help="also watch this folder for new log lines")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--clock", choices=["event", "wall"], default="event")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("simulate", help="write a synthetic day of logs to CSV files")
    p.add_argument("--scenario", choices=list(SCENARIOS), default="cosmos")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--transactions", type=int, default=12_000)
    p.add_argument("--out", default="sample_data")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("scan", help="check a switch log against a ledger (and settlement) file")
    p.add_argument("--switch", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--settlement")
    p.add_argument("--lang", choices=SUPPORTED_LANGUAGES, default="en")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.add_argument("--fail-on-alert", action="store_true", help="exit with status 1 if alerts are open")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("watch", help="watch an inbox folder and check new log lines continuously")
    p.add_argument("--inbox", required=True)
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--clock", choices=["event", "wall"], default="event")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("mask", help="mask Aadhaar/PAN/card/account numbers in a CSV or text file")
    p.add_argument("input")
    p.add_argument("--out")
    p.set_defaults(func=cmd_mask)

    p = sub.add_parser("bench", help="measure detection on synthetic scenarios")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--transactions", type=int, default=12_000)
    p.add_argument("--out", help="write a Markdown table (e.g. docs/BENCHMARK.md)")
    p.add_argument("--json", help="write raw results as JSON")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("report", help="export the pre-filled incident report")
    p.add_argument("incident_id")
    p.add_argument("--lang", choices=SUPPORTED_LANGUAGES, default="en")
    p.add_argument("--format", choices=["html", "json"], default="html")
    p.add_argument("--out")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("reset", help="delete all alerts, incidents and runs")
    p.set_defaults(func=cmd_reset)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose or args.command == "watch" else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        return int(args.func(args) or 0)
    except (ValueError, FileNotFoundError) as exc:
        _print(f"error: {exc}")
        return 2
    except KeyError as exc:
        _print(f"error: not found: {exc}")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
