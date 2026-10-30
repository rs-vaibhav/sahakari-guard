# Demo script (2½ minutes)

Use this for the internal round, the judges and the video. Start the dashboard first (`scripts\run.bat` or `./scripts/run.sh`) and open http://127.0.0.1:8000. In **Demo lab**, press **Clear all data** so you start from "No data yet".

| Time | On screen | Say |
|---|---|---|
| 0:00 - 0:20 | Overview showing "No data yet" | "In 2018 attackers took about ₹94 crore from a co-operative bank in two days. The switch approved the withdrawals, but the core-banking ledger never saw them. Most small banks only compare the two the next morning." |
| 0:20 - 0:40 | Demo lab: select **Proxy-switch cash-out**, speed ×300, press **Play scenario** | "This is a synthetic day at a small co-operative bank. At 2 a.m., cloned cards start withdrawing cash at foreign ATMs, and a malicious switch approves them without debiting anyone." |
| 0:40 - 1:05 | Switch to Overview. The band turns red, alerts appear, the six-hour clock starts | "Sahakari-Guard only reads copies of the logs. Within about two minutes it sees withdrawals in many countries, and three minutes after each approval it knows the ledger never got the debit. RBI now expects banks to report a cyber incident on DAKSH within six hours - this clock shows how much time is left." |
| 1:05 - 1:25 | Click an alert row: the drawer shows Switch ₹12,000 / Ledger ₹0 / Network ₹12,000 | "Every alert is explained in plain language, with the evidence. Account and card numbers are already masked." |
| 1:25 - 1:45 | Open the incident; click **தமிழ்** report | "Four hundred transactions are one incident, not four hundred emails. The officer gets recommended actions and a draft report in English, Tamil or Hindi, with hashes of the evidence." |
| 1:45 - 2:05 | Demo lab: switch on **Simulate network outage**; show the queued message count; switch it off and watch it send | "Village branches lose internet. Detection keeps running on this computer and messages wait in a queue until the line returns." |
| 2:05 - 2:20 | Privacy shield: **Load sample**, **Mask text** | "Before any log leaves the bank - to a vendor, an auditor or a shared security centre - Aadhaar, PAN, card and account numbers are masked. Reference numbers stay so investigators can still work." |
| 2:20 - 2:30 | Benchmark page | "On synthetic data it caught every attack pattern we injected, with no false alerts, about 3 minutes after each transaction instead of the next morning. Next we want to prove it on masked logs from one bank near Chengalpattu." |

## If something goes wrong

* **Port already in use:** `python -m sahakari_guard serve --port 8010`.
* **A demo is still running:** press **Stop** in the Demo lab, then **Clear all data**.
* **No internet at the venue:** nothing changes; the app needs none.
* **Need a quick result without waiting:** press **Run instantly** instead of **Play scenario**.
