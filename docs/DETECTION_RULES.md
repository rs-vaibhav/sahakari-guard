# Detection rules

All thresholds are configurable in `[engine]` of `sahakari_guard.example.toml`. Defaults are shown.

Families decide how alerts are grouped into incidents and whether the six-hour reporting clock applies:

| Family | Rules | Six-hour clock |
|---|---|---|
| Unauthorised debits / cash-out | SG-R1, SG-R5 (debit bursts), SG-R6, SG-R7, SG-R9, SG-R11 | Yes |
| Credits without funding | SG-R2, SG-R5 (credit bursts) | Yes |
| Duplicate or tampered transactions / Integrity | SG-R3, SG-R4, SG-R10 | Yes |
| Customer credit not posted | SG-R8 | No - operational issue, resolve within the RBI turnaround time |

---

## SG-R1 Approval without ledger debit (Critical)

**What:** the switch approved a debit (ATM, POS, UPI or IMPS outward) but no matching debit reached the core-banking ledger within the match window.

**Why it matters:** this is how a proxy or malicious switch drains a bank: it answers withdrawal requests itself and core banking never sees them. In the 2018 Cosmos Bank attack the bank stated its core banking was not affected while about ₹94 crore left through the switch.

**Logic:** at the RRN's deadline, `switch_net > 0` and `ledger_net ≤ 0` for a debit.

**Tuning:** `match_window_seconds = 180`. Raise it if the CBS legitimately posts later; late postings close the alert automatically anyway.

## SG-R2 Credit without funding (Critical)

**What:** an inward credit was posted to a customer although the network transaction failed or was reversed.

**Why it matters:** the 2023 UCO Bank IMPS incident credited about ₹820 crore over several days without matching debits at the originating banks.

**Logic:** credit direction, `ledger_net > 0` and `switch_net = 0` (no approval, or approval fully reversed).

## SG-R3 Duplicate or replayed transaction (High)

**What:** the same RRN was approved twice by the switch, or posted twice (non-reversal postings with different journal IDs) in the ledger.

**Logic:** raised immediately on the second posting or approval. If a reversal later brings the books back in balance, the alert closes itself. Byte-identical lines (same journal ID) are treated as a re-exported file, not a replay, and ignored.

## SG-R4 Amount mismatch (High)

**What:** switch and ledger agree that a transaction happened but disagree on the amount.

**Logic:** both sides non-zero and unequal (suppressed when SG-R3 already explains the difference).

## SG-R5 Abnormal burst (High)

Two variants, each an *episode* that updates one alert until it has been quiet for `velocity_cooldown_seconds = 1800`:

* **Per account:** more than `velocity_debit_threshold = 8` approved debits, or more than `velocity_credit_threshold = 30` approved credits, within `velocity_window_seconds = 600`. The credit threshold is higher because busy merchant accounts receive many UPI credits legitimately.
* **Bank-wide foreign spread:** at least `foreign_count_threshold = 25` approved withdrawals at foreign terminals, or terminals in at least `foreign_country_threshold = 5` different countries, within `foreign_window_seconds = 900`. This is the signature of card-cloning cash-outs, and fires within about two minutes in the benchmark, before the per-transaction rules.

Burst alerts describe money already counted by per-transaction alerts, so they are excluded from an incident's amount at risk unless they are the only evidence.

## SG-R6 Settled by network, never approved by bank (Critical)

**What:** the payment network's settlement file contains a debit for this bank that the bank's own switch log never approved.

**Why it matters:** if attackers answer requests completely outside the bank's switch logging, only the network side records them.

**Logic:** debit direction, `settled > 0` and no successful approval for the RRN. Evaluated one match window after the settlement record arrives, to allow for switch logs that are delivered slightly later. The alert's event time uses the original transaction time (`txn_ts`) when the settlement file carries it.

**Limit:** detection is bounded by how often settlement files arrive (every two hours in the simulator).

## SG-R7 Ledger debit without approval (Medium)

**What:** the ledger debited a customer for a switch-channel payment that the switch never approved.

**Why it matters:** an insider posting fake outward transfers, or an interface debiting customers for declined transactions.

## SG-R8 Customer credit missing (Medium, not a cyber incident)

**What:** the network confirmed an inward credit but the customer's account was not credited.

**Why it matters:** customers wait for money that has already left the remitter; banks must credit or return within the RBI turnaround time. Grouped separately so it never triggers the cyber-incident clock.

## SG-R9 Contact changed, then money out (Critical)

**What:** an account's registered mobile number or email address was changed, and within 24 hours the account experienced significant outward debit activity.

**Why it matters:** real incident: Bhavnagar District Co-op Bank, March 2026. Attackers used compromised staff credentials to change registered mobile numbers on 4 high-balance accounts early on a Sunday morning (diverting OTPs and transaction SMS alerts to the attackers). They then drained approximately ₹7.34 crore across ~150 rapid IMPS/UPI transfers to ~135 mule accounts. Because the ledger posted each debit cleanly, standard ledger-to-switch reconciliation (SG-R1) remained silent.

**Logic:** watches the `profile_changes` audit log for changes to `MOBILE` or `EMAIL`. If, within `contact_change_window_hours = 24`, the account has approved outward debits totalling $\ge$ `contact_change_amount_threshold = 10000000` (₹1,00,000) OR $\ge$ `contact_change_count_threshold = 3` debits, raise one Critical alert. Later debits update the existing alert as an episode. Evaluates cleanly even when feeds arrive out of order (debits first, audit log second). Additionally flags an extra risk parameter `admin_multi_account = true` if the same operator changed $\ge 3$ customer accounts within 1 hour.

**Tuning:** `contact_change_window_hours = 24`, `contact_change_amount_threshold = 10000000` (₹1,00,000 in paise), `contact_change_count_threshold = 3`. Mobile numbers in evidence are masked preserving only the last two digits (e.g. `XXXXXXXX42`).

## SG-R10 Outgoing payment file does not match the bank's book (Critical / Medium)

**What:** an outward payment file (NEFT/RTGS CSV or XML) submitted to the payment network does not match the bank's core-banking ledger instructions for the same UTR.

**Why it matters:** real incident: Ballari DCC Bank, Karnataka, January 2025. Attackers altered beneficiary account numbers and IFSC codes directly inside outgoing NEFT/RTGS batch XML files before transmission to the clearing house. ₹2.34 crore was diverted to 25 mule accounts, discovered 3 days later only when customers complained of missing funds.

**Logic:** matches `OutwardPayment` records to CBS `LedgerEntry` instructions using the Unique Transaction Reference (`utr`) within `match_window_seconds = 180`.
* **Critical:** if beneficiary account number, beneficiary IFSC, or payment amount differs between the core ledger and the outgoing payment file, or if a payment file row has no ledger instruction at all (`orphan outward file payment`). Evidence records both values side-by-side (with beneficiary accounts masked).
* **Medium:** if a core ledger NEFT/RTGS instruction has no outgoing file row after the match window (`instruction not sent`). If the file row arrives later within retention, the alert auto-resolves.

**Tuning:** `match_window_seconds = 180`. Parses both CSV and XML outward payment formats (with strict entity/DTD rejection).

## SG-R11 Unusual money-out for this kind of day (High)

**What:** the bank's cumulative approved outward debits today significantly exceed the statistical baseline for that specific day type and hour.

**Why it matters:** real incident: in the Bhavnagar Sunday attack, staff only noticed the fraud hours later when Sunday outward volume crossed ₹7 crore—on a quiet holiday where normal daytime volume rarely exceeds ₹70–80 lakh.

**Logic:** classifies each date into `WEEKDAY`, `SATURDAY` (1st, 3rd, 5th Saturday), or `HOLIDAY` (Sundays, 2nd & 4th Saturdays, and statutory bank holidays listed in `holidays`). Compares today's cumulative outward debits up to the current hour against the baseline 95th percentile ($p_{95}$). Triggers when:
$$\text{cumulative\_today} > \max(\text{baseline\_multiplier} \times p_{95}, \text{baseline\_floor})$$
Where defaults are `baseline_multiplier = 3.0` and `baseline_floor = 250000000` (₹25,00,000). If no baseline is available, falls back to `quiet_day_outward_limit = 500000000` (₹50,00,000) for holidays. Emits one episode alert per day and updates the amount as activity progresses.

**Tuning:** Build baseline from historical switch/ledger files using `python -m sahakari_guard baseline build <files...>`. Requires $\ge 4$ sample days per day type; logs a warning if insufficient history is provided.

---

## What the engine deliberately ignores

* Declined authorisations with no posting.
* Approvals reversed before posting, and postings reversed after a reversal.
* Ledger postings without an RRN (cash deposits, interest, charges) - counted as `ledger_unlinked`.
* Re-exported identical lines.
* Postings that arrive late but within retention: they close their alert instead of raising new ones.
