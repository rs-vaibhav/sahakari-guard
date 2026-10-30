# Security

## Deployment guidance

* Run Sahakari-Guard inside the bank's network on a machine that receives **read-only copies** of logs. It needs no credentials for the switch, CBS or payment network.
* The server listens on `127.0.0.1` by default. Before binding to another interface (`--host 0.0.0.0` or Docker), set `SG_API_KEY`; every `/api` call then requires the `X-API-Key` header.
* Keep the data folder (`SG_DATA_DIR`, default `./data`) on an encrypted disk with access limited to the operators. It contains the SQLite database and `.token_secret`, the key for account tokens. Back it up like any other bank system.
* Set `SG_TOKEN_SECRET` explicitly if several instances must produce the same tokens.
* Put the dashboard behind the bank's HTTPS reverse proxy if it is used from other machines.

## What the application does to protect data

* Masks Aadhaar, PAN, card, account and mobile numbers, e-mail addresses and UPI IDs inside the engine, before evidence is stored, displayed or exported.
* Stores SHA-256 hashes of uploaded files and embeds a SHA-256 of each report's content.
* Sends a strict Content-Security-Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on API responses.
* Escapes all dynamic content in the dashboard and in reports; loads no third-party scripts, styles or fonts.
* Limits upload sizes (50 MB per log file, 20 MB for masking) and validates every row.

## Known limitations

* The optional API key is a shared secret, not per-user authentication; officer names in the incident timeline are entered by the user. Integrating the bank's single sign-on is planned before production.
* The tool has not yet had an independent security assessment; one is part of the pilot plan.

## Reporting a vulnerability

Please do not open a public issue. E-mail the maintainers (see the README team section) with steps to reproduce; we aim to respond within 7 days.
