# HTTP API

The dashboard uses this JSON API; other systems can too. Interactive documentation is served at `/docs` while the server runs. When `SG_API_KEY` is set, send it as the `X-API-Key` header (or `?key=` for links such as report downloads). Every response for an error has the shape `{"error": "message"}`.

Most read endpoints accept `lang=en|ta|hi` and return alert and incident text in that language.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness, version (never needs the key) |
| GET | `/api/config` | bank profile, languages, engine settings, rule catalogue, scenarios |
| GET | `/api/i18n/{lang}` | the full string catalogue |
| GET | `/api/summary` | status colour, KPIs, top incident, alert counts, latest alerts, network, demo status |
| GET | `/api/alerts` | list; filters `severity`, `rule`, `status`, `incident`, paging `limit` (≤500), `offset` |
| GET | `/api/alerts/{id}` | one alert with masked evidence |
| GET | `/api/incidents` | list; filter `status` |
| GET | `/api/incidents/{id}` | incident, first 200 alerts, timeline, recommended actions |
| POST | `/api/incidents/{id}/confirm` | `{"officer", "note"}` |
| POST | `/api/incidents/{id}/dismiss` | `{"officer", "reason"}` |
| POST | `/api/incidents/{id}/reported` | `{"officer", "daksh_ref", "certin_ref"}` |
| GET | `/api/incidents/{id}/report.json` | draft report (`download=true` for a file) |
| GET | `/api/incidents/{id}/report.html` | printable draft report |
| POST | `/api/upload` | multipart `files` (2-3 CSVs: switch, ledger, optional settlement) |
| GET | `/api/samples/{scenario}/{switch\|ledger\|settlement}.csv` | synthetic sample files |
| POST | `/api/demo/start` | `{"scenario", "speed", "seed", "transactions", "instant"}` |
| POST | `/api/demo/stop` | stop playback |
| GET | `/api/demo/status` | phase, simulated clock, progress |
| POST | `/api/reset` | delete alerts, incidents, runs and statistics |
| GET / POST | `/api/benchmark`, `/api/benchmark/run` | latest result / start a run in the background |
| POST | `/api/privacy/mask-text` | `{"text"}` → masked text and counts |
| POST | `/api/privacy/mask-csv` | multipart `file` → masked CSV text and column report |
| GET | `/api/outbox` | queued and sent messages |
| POST | `/api/network` | `{"online": false}` simulates an outage |
| POST | `/api/outbox/flush` | try to send queued messages now |

Status codes: `400` invalid input or file, `401` missing key, `404` unknown ID, `409` invalid status change or another run in progress, `413` file too large, `422` missing fields.
