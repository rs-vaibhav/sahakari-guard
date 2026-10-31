# Demo scripts

Choose either the classic Cosmos proxy-switch demo or the new Bhavnagar Sunday attack demo. Start the dashboard first (`scripts\run.bat` or `./scripts/run.sh`) and open http://127.0.0.1:8000. In **Demo lab**, press **Clear all data** so you start from "No data yet".

---

## 2-minute script: Bhavnagar Sunday attack (March 2026 pattern)

This demonstrates the new 2026 attack pattern: insider/admin mobile number tampering on a Sunday followed by rapid UPI/IMPS outward transfers, and the **Money Saved by Early Alert** calculation.

| Time | On screen | Say |
|---|---|---|
| 0:00 - 0:20 | Overview: "No data yet" | "In March 2026, attackers compromised administrative credentials at Bhavnagar District Co-op Bank. On a quiet Sunday morning between 9:00 and 9:20, they changed registered mobile numbers on 4 high-balance accounts so all OTPs and SMS alerts went to the attackers. Then starting at 10:00, they moved approximately ₹7.34 crore to ~135 mule accounts. Because core banking debited each account cleanly, conventional switch-ledger reconcilers stayed completely silent." |
| 0:20 - 0:35 | Demo lab: select **Mobile hijack & Sunday drain** (`bhavnagar`), speed ×300, press **Play scenario** | "Watch the demo clock advance through Sunday morning. At 09:00, the customer profile changes log records the mobile updates. At 10:00, rapid outward IMPS/UPI debits begin." |
| 0:35 - 0:55 | Overview: turns RED within minutes of the first transfer; 6-hour clock starts | "Within 30 seconds of the first transfer, Sahakari-Guard flags Rule SG-R9: 'Contact changed, then money out'. Notice the dashboard turns RED immediately and the RBI 6-hour DAKSH reporting countdown begins." |
| 0:55 - 1:15 | Click the open SG-R9 alert | "Open the alert drawer: it correlates the core-banking audit log with the outward switch payments. The officer sees the exact staff ID that changed the phone number, the masked old/new numbers (keeping only the last two digits for privacy), and the rapid outward transfers." |
| 1:15 - 1:35 | Open the Incident page; click **தமிழ்** (Tamil) report | "All alerts across the compromised accounts are grouped into one Cyber Incident. With one click, the officer gets a complete, pre-filled RBI/CERT-In incident report in Tamil (or English/Hindi) with SHA-256 evidence hashes." |
| 1:35 - 2:00 | Incident / Demo lab: point to **Money saved by early alert** panel | "Here is the critical save: in the real world, the attack was only discovered on Monday at 10:00 AM, losing all ₹7.34 crore. With Sahakari-Guard's alert within minutes, if the duty officer blocks the 4 accounts within 15 minutes, over ₹5.5 crore of the ₹7.34 crore is saved before it leaves the bank." |

---

## Classic script: Cosmos Bank proxy-switch cash-out (2½ minutes)

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
