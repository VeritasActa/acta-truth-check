# acta-truth-check

Independent external verification of [Veritas Acta](https://veritasacta.com) instance claims.

Runs entirely outside the operator's infrastructure. No privileged access. No secrets. Read-only.

## What it checks

| # | Check | What it verifies |
|---|-------|-----------------|
| 1 | Manifest | `/.well-known/acta-instance.json` exists and is well-formed |
| 2 | Endpoints | All advertised endpoints respond with 200 |
| 3 | Anchor freshness | Latest anchor is less than 25 hours old |
| 4 | Anchor signature | Ed25519 signature is valid against known public key |
| 5 | Merkle root | Recomputed from chain heads matches claimed root |
| 6 | Witness | External witness is active and references the latest anchor |
| 7 | Conformance honesty | Self-reported conformance matches actual state |
| 8 | Chain integrity | Full independent hash chain verification of an exported topic |
| 9 | Identity binding | Anchor includes charter and protocol spec hashes |

## Run locally

```bash
npm install
node check.js https://veritasacta.com
```

JSON report goes to stdout. Human-readable progress goes to stderr.

## Automated

This repo runs a GitHub Action twice daily that:
1. Fetches all public Acta surfaces
2. Independently verifies every check
3. Commits a JSON report to `reports/latest.json`
4. Archives historical reports in `reports/archive/`

## Latest report

See [`reports/latest.json`](reports/latest.json)

## Why this exists

Infrastructure earns that label through external verification, not self-assessment. This checker closes the loop: the operator publishes claims, this tool independently verifies them, and the results are public.

## License

MIT
