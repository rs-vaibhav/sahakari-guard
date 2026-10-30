# Detection rules

All thresholds are configurable in `[engine]` of `sahakari_guard.example.toml`. Defaults are shown.

Families decide how alerts are grouped into incidents and whether the six-hour reporting clock applies:

| Family | Rules | Six-hour clock |
|---|---|---|
| Unauthorised debits / cash-out | SG-R1, SG-R5 (debit bursts), SG-R6, SG-R7 | Yes |
| Credits without funding | SG-R2, SG-R5 (credit bursts) | Yes |
| Duplicate or tampered transactions | SG-R3, SG-R4 | Yes |
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

---

## What the engine deliberately ignores

* Declined authorisations with no posting.
* Approvals reversed before posting, and postings reversed after a reversal.
* Ledger postings without an RRN (cash deposits, interest, charges) - counted as `ledger_unlinked`.
* Re-exported identical lines.
* Postings that arrive late but within retention: they close their alert instead of raising new ones.
