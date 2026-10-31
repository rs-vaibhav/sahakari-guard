# Benchmark results

Generated 2026-10-30T21:19:35+00:00 by Sahakari-Guard 0.1.0 (seed 42, 12,000 normal transactions per synthetic day, match window 180 s).

All data is synthetic. Times are event time with a 15-second heartbeat (as in live operation). The last column assumes the usual practice of reconciling the switch with the ledger at 10:00 the next morning.

| Scenario | Attack txns | Detected | Flagged | False alerts | Auto-resolved | First alert | Median time to detect | 95th percentile | Next-morning reconciliation |
|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|
| normal | 0 | - | - | 0 | 0 | - | - | - | - |
| slowcbs | 0 | - | - | 0 | 247 | - | - | - | - |
| cosmos | 420 | yes | 100.0% | 0 | 0 | 1m 51s | 3m 09s | 2h 04m | 1d 8h |
| uco | 1801 | yes | 100.0% | 0 | 0 | 3m 06s | 3m 09s | 3m 13s | 13h 15m |
| replay | 20 | yes | 100.0% | 0 | 0 | 29s | 22s | 37s | 22h 52m |
| tamper | 15 | yes | 100.0% | 0 | 0 | 3m 04s | 3m 03s | 3m 10s | 19h 54m |
| ghost | 12 | yes | 100.0% | 0 | 0 | 3m 07s | 3m 02s | 3m 11s | 20h 52m |
| missing | 18 | yes | 100.0% | 0 | 0 | 3m 04s | 3m 02s | 3m 13s | 23h 37m |
| bhavnagar | 150 | yes | 100.0% | 0 | 0 | 0s | 0s | 0s | 23h 59m |
| ballari | 25 | yes | 100.0% | 0 | 0 | 0s | 0s | 0s | 22h 29m |

`normal` and `slowcbs` contain no attack: `slowcbs` delays core-banking postings by 4-8 minutes for 20 minutes, so alerts are raised and must close themselves when the late postings arrive (shown as auto-resolved). In `cosmos`, a quarter of the withdrawals bypass the bank's switch log entirely and can only be caught from the network settlement file, which arrives every two hours; that is why its 95th percentile is longer. In `bhavnagar`, registered mobile numbers are changed on a Sunday followed by rapid outward transfers. In `ballari`, beneficiary account and IFSC details in the outward payment file are altered vs the core ledger.

Engine throughput: **58,202 events per second** on one CPU core (switch, ledger and settlement lines combined).

Rules fired per scenario:

* `normal`: none (expected: none)
* `slowcbs`: none (expected: none)
* `cosmos`: SG-R1, SG-R11, SG-R5, SG-R6 (expected: SG-R1, SG-R5, SG-R6)
* `uco`: SG-R2, SG-R5 (expected: SG-R2, SG-R5)
* `replay`: SG-R3 (expected: SG-R3)
* `tamper`: SG-R4 (expected: SG-R4)
* `ghost`: SG-R7 (expected: SG-R7)
* `missing`: SG-R8 (expected: SG-R8)
* `bhavnagar`: SG-R11, SG-R5, SG-R9 (expected: SG-R11, SG-R5, SG-R9)
* `ballari`: SG-R10 (expected: SG-R10)

Reproduce with `python -m sahakari_guard bench`.
