# Sample data (synthetic)

Each folder is one synthetic day at a small co-operative bank (3,000 normal transactions, seed 7), in the canonical CSV formats described in [docs/DATA_FORMATS.md](../docs/DATA_FORMATS.md). All identifiers are randomly generated and belong to no one.

| Folder | Contents | Expected result |
|---|---|---|
| `normal/` | ordinary traffic with declines, reversals and late postings | no alerts |
| `cosmos/` | + proxy-switch ATM cash-out at night (420 withdrawals, 22 countries) | SG-R1, SG-R5, SG-R6 - one critical incident |
| `uco/` | + inward IMPS credits posted although the remitter leg was reversed | SG-R2, SG-R5 - one critical incident |

`ground_truth.json` lists the injected reference numbers.

Try them in the dashboard (**Upload logs**) or on the command line:

```bash
python -m sahakari_guard scan --switch sample_data/cosmos/switch_log.csv --ledger sample_data/cosmos/cbs_ledger.csv --settlement sample_data/cosmos/settlement.csv
```

Regenerate with `python -m sahakari_guard simulate --scenario cosmos --transactions 3000 --seed 7 --out sample_data/cosmos`.
