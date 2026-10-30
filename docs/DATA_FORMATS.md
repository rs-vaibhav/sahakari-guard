# Data formats

Sahakari-Guard reads three CSV feeds (UTF-8, with or without BOM, comma separated, header row required). Column names are case-insensitive. Extra columns are ignored. A row that cannot be parsed is reported with its line number and skipped; it never stops the run. A file missing a required column is rejected as a whole with a clear message.

Banks export logs in vendor-specific formats. During a pilot, a small **adapter** script converts the bank's switch and CBS exports into these canonical columns. The feed type is detected from the header, so file names do not matter (except in watch mode, where names are used as a fallback hint).

Timestamps: ISO 8601 (`2026-11-01T10:15:00+05:30`, `2026-11-01 10:15:00`). Times without an offset are treated as IST. Amounts: rupees with up to two decimals; commas and the ₹ sign are accepted.

## 1. Switch log (`switch_log.csv`)

One line per message handled by the ATM / POS / UPI / IMPS switch.

| Column | Required | Example | Notes |
|---|---|---|---|
| `ts` | yes | `2026-11-01T02:00:09+05:30` | message time |
| `rrn` | yes | `630502012000` | retrieval reference number (up to 32 letters/digits) |
| `channel` | yes | `ATM` | `ATM`, `POS`, `UPI`, `IMPS` |
| `direction` | yes | `DR` | `DR`/`DEBIT`/`OUT` (customer pays) or `CR`/`CREDIT`/`IN` (customer receives) |
| `msg_type` | yes | `AUTH` | `AUTH` (also `0100`, `0200`, `0210`) or `REVERSAL` (also `0400`, `0420`, `0430`) |
| `response_code` | yes | `00` | `00` = approved / accepted; anything else = declined or failed |
| `amount` | yes | `12000.00` | rupees |
| `account_no` | yes | `00101100000042` | customer account (masked before storage) |
| `card_no` | no | `6080011234567896` | card number (masked before storage) |
| `terminal_id` | no | `ATMCGL004` | |
| `terminal_country` | no | `IN` | ISO country code; used by the foreign cash-out rule |
| `counterparty` | no | `ravi.k@oksbi` | VPA or IFSC/account of the other party (masked in evidence) |

## 2. Core-banking ledger (`cbs_ledger.csv`)

One line per posting.

| Column | Required | Example | Notes |
|---|---|---|---|
| `ts` | yes | `2026-11-01T02:00:11+05:30` | posting time |
| `journal_id` | yes | `JNL2611010000123` | unique posting ID; used to ignore re-exported lines |
| `rrn` | yes (may be empty) | `630502012000` | empty for postings that did not come from the switch (cash, interest) |
| `channel` | yes | `ATM` | `ATM`, `POS`, `UPI`, `IMPS`, or `BRANCH` for ledger-only postings |
| `account_no` | yes | `00101100000042` | |
| `drcr` | yes | `DR` | debit or credit to the customer account |
| `amount` | yes | `12000.00` | |
| `is_reversal` | no | `0` | `1/true/yes` for reversal postings |
| `narration` | no | `ATM WDL ATMCGL004 630502012000` | free text, scanned and masked |

## 3. Network settlement file (`settlement.csv`)

One line per transaction the payment network settled for the bank in a settlement cycle.

| Column | Required | Example | Notes |
|---|---|---|---|
| `cycle_id` | yes | `20261101-C02` | settlement cycle |
| `settled_at` | yes | `2026-11-01T04:20:00+05:30` | when the file for the cycle was produced |
| `rrn` | yes | `630502012000` | |
| `channel` | yes | `ATM` | |
| `direction` | yes | `DR` | |
| `amount` | yes | `12000.00` | |
| `status` | no | `SETTLED` | rows with other statuses are kept as evidence but not counted as settled |
| `txn_ts` | no | `2026-11-01T02:00:09+05:30` | original transaction time, if the network file has it |
| `account_no` | no | `00101100000042` | issuer-side account/card reference, if available |

## Masked output

`python -m sahakari_guard mask file.csv` and the Privacy Shield page choose a policy per column from its name:

| Column name contains | Policy | Example output |
|---|---|---|
| `account`, `acct`, `ac` | keep last 4 digits + `<col>_token` | `XXXXXXXXXX0042`, `tok_3f9a1c0b2d7e` |
| `card` | card mask + token | `XXXX-XXXX-XXXX-7896` |
| `aadhaar`, `uid` | Aadhaar mask | `XXXX-XXXX-0124` |
| `pan` | PAN mask (or card mask if the value is a card number) | `XXXXXX234F` |
| `mobile`, `phone`, `contact` | keep last 4 | `XXXXXX3210` |
| `email`, `mail` | keep first letter and domain | `s***@example.com` |
| `name` | initials | `K*** R***` |
| `rrn`, `utr`, `ref`, `amount`, `ts`, `channel` ... | kept | unchanged |
| anything else | scanned for identifiers | identifiers masked in place |

Tokens are `HMAC-SHA256(secret, value)`; the secret is generated on first run and stored in the data folder, so tokens are stable inside one bank but meaningless outside it.
