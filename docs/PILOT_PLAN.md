# Implementation plan and scalability

## Where we are

| Item | Status |
|---|---|
| Detection engine with 8 rules, privacy shield, incident workflow, draft reports in 3 languages | Built and tested on synthetic data |
| Benchmark: 6 attack patterns + 2 no-attack days | 100% of injected transactions flagged, 0 false alerts on synthetic data (see [BENCHMARK.md](BENCHMARK.md)) |
| Real bank data | Not yet - the pilot below is the next step |

## Phases

| Phase | When | What | Done when |
|---|---|---|---|
| 0. Synthetic validation | Oct - Nov 2026 | Prototype, benchmark, demo lab, documentation | Benchmark passes in CI; demo video recorded |
| 1. Shadow pilot, one bank | Dec 2026 - Feb 2027 | One urban co-operative bank or DCCB near Chengalpattu / Chennai. The bank exports **masked or read-only copies** of one month of switch, CBS and settlement logs; we write the adapter and run Sahakari-Guard beside existing processes. No connection to live systems. | False alerts per day measured; time-to-detect compared with the bank's current reconciliation; officers' feedback on the Tamil interface |
| 2. Small multi-bank pilot | Mar - May 2027 | 3-5 banks across two districts, at least two different CBS / switch vendors. Independent security review (VAPT) of the tool. Native-speaker review of Tamil and Hindi text. | Adapters for two vendor formats; false alerts below an agreed threshold; audit findings closed |
| 3. Distribution | From mid-2027 | Offer through shared-service platforms for co-operative banks and through technology service providers that host CBS and switches for many small banks | First provider-level deployment |

## Success measures for the pilot

| Measure | Target |
|---|---|
| Time from a switch–ledger mismatch to an alert | under 5 minutes (versus next-day reconciliation) |
| Injected test patterns detected in the bank's own data | at least 95% |
| Open false alerts per day after one week of tuning | at most 5 |
| Time to prepare a draft incident report | under 30 minutes, well inside the six-hour window |
| Unmasked Aadhaar / PAN / card / account numbers in stored data and reports | zero (automated scan) |

## Why it scales

* **Same logs everywhere.** Every bank connected to NPCI networks produces a switch log, a CBS journal and settlement files. Only the export format differs, and banks on the same CBS / switch vendor share it, so one adapter serves all of them.
* **One deployment can serve many banks.** Many small co-operative and regional rural banks use shared technology service providers (the 2024 C-Edge incident affected about 300 of them at once). Running Sahakari-Guard at the provider covers all its client banks.
* **Light enough to run anywhere.** About 30,000 log lines per second on one CPU core; a small bank produces tens of thousands of lines a day.
* **Fits national efforts.** It works as a bank-side sensor that masks data before logs go to a shared Security Operations Centre, rather than competing with one.
* **Language is data, not code.** Adding a language is adding one JSON file.

## Cost

Estimates for planning; confirm with real quotes.

**Development and pilot (6 months), about ₹1.45 lakh**

| Item | Estimate |
|---|---:|
| Test appliance (mini PC) | ₹20,000 |
| Cloud test environment | ₹15,000 |
| Independent security review (VAPT) | ₹60,000 |
| Pilot travel (Chengalpattu / Kanchipuram / Chennai) | ₹15,000 |
| Language review and documentation | ₹10,000 |
| Contingency | ₹25,000 |

**Per bank in production**

* Software: open source, no licence fee.
* Hardware: none if run as a VM on an existing server; optional mini-PC appliance about ₹20,000 one-time.
* Support and updates: proposed about ₹12,000 per bank per year.
* Paid by the bank's IT budget, or collectively through a shared-services contract.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Banks cannot share live data | Shadow mode on masked log copies; the Privacy Shield runs inside the bank before anything is shared |
| Vendor export formats vary | Canonical CSV format plus small per-vendor adapters; parser reports bad rows instead of failing |
| Too many alerts from timing quirks | Configurable match window, automatic closing on late postings, burst episodes instead of repeated alerts |
| Tool itself becomes an attack surface | Watch-only, local-first, API key, strict web security headers, independent VAPT before production |
| Regulatory expectations change | Report fields and rules are data-driven; reports are drafts for an officer, not an automated filing |
