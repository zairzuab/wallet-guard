# Wallet Guard 🛡️

A read-only guard for BSC wallets. Give it a wallet address and it checks
the wallet's token approvals — unlimited allowances, approvals to unknown
contracts or plain wallets (EOAs), stale approvals — and tells you, in plain
language, what is at risk and how to revoke it.

**Agent Games (zkVerify) — Wildcard track submission.**
Live demo: https://wallet-guard.naylafeb02099.workers.dev

## Why this exists

The most common way wallets get drained is not a hack of the wallet itself —
it is an approval the owner granted months ago and forgot: an *unlimited*
allowance to a contract that later turns malicious, or to a plain wallet
(EOA) that can move the funds directly. Existing approval checkers need an
indexer API key or a wallet connection. Wallet Guard needs neither: it reads
allowances straight from the chain and explains the risk in plain language.

## What it does

`GET /scan?address=0x...` returns a JSON report:

- **Balances** of the curated tokens the wallet holds.
- **Approvals** — every nonzero allowance for the checked tokens × spenders,
  each with: the spender (named when known), whether the allowance is
  unlimited, whether the spender is an EOA or a contract, the balance at
  risk, and the USD exposure (capped at the balance — an unlimited allowance
  on an empty wallet is not a million-dollar exposure).
- **Findings** in plain language, one per risk, with a severity level.
- **Score 0–100, grade A–F, verdict** (SAFE / LOW RISK / REVIEW / AT RISK /
  CRITICAL).
- **Revoke guidance** — links to BscScan's Token Approval Checker and
  revoke.cash. Revoking costs a little BNB gas and is done from the user's
  own wallet; this agent never signs or submits anything.

`GET /` is a small demo page (type an address, see the report).
`GET /health` is a liveness check.

Optional parameters: `&tokens=0x…,0x…` and `&spenders=0x…,0x…` extend the
curated lists for one scan.

## How it works

1. **One batched read.** All balances and allowances are fetched in a single
   `Multicall3.aggregate3` `eth_call` — no indexer, no API key, no event
   logs. The ABI encoding is hand-rolled (no dependencies); the encoding was
   verified against live BSC nodes before shipping.
2. **RPC failover.** The Worker tries several public BSC endpoints in order
   (`bsc-dataseed1/2/4`, PublicNode, 1RPC) and uses the first that answers.
   Public `eth_getLogs` was tested and rejected: every free endpoint either
   rate-limits it, caps the range at 50 blocks, or requires a contract
   address filter — so the guard reads current allowances instead of
   reconstructing history from events.
3. **Spender intelligence.** For every spender with a nonzero allowance, the
   agent checks `eth_getCode`: no code means the spender is an EOA (a person,
   not a contract) — the highest-risk counterparty after unlimited. Known
   spenders are labelled from verified addresses only (PancakeSwap docs,
   Etherscan); anything else is treated as unknown, which is itself a signal.
4. **Prices, best effort.** USD values come from the CoinGecko free API with
   a short timeout; if it fails, the report still works and says the USD
   value is unavailable.
5. **Transparent scoring.** Unlimited +40, EOA spender +30, unknown contract
   +15, stale approval +5, exposure over $5,000 +10. Score = 100 − points.
   The rules are listed here and in the code — nothing hidden.

## Key decisions

- **Read-only by design.** No wallet connection, no signing, no private data.
  A guard that can move funds is a guard you have to trust; this one cannot.
- **Curated coverage, stated honestly.** The scan covers 7 major tokens × 5
  well-known spenders. An approval to a spender outside that list is *not*
  seen, and every report says exactly what was checked. A guard that
  pretends to be exhaustive is more dangerous than one that states its
  limits. (The `tokens`/`spenders` parameters let anyone extend the scan.)
- **Exposure capped at the balance.** An unlimited allowance is 2²⁵⁶−1
  tokens on paper; the amount actually at risk is what the wallet holds.
  The first version printed a $10⁶¹ exposure — fixed before shipping.
- **No zkVerify (yet).** The Wildcard track makes zkVerify optional, and a
  proof only helps if it makes a real claim checkable. The checkable claim
  here would be "this report matches the chain state at block N" — a zkTLS
  attestation of the RPC responses. That is the natural next step, not a
  bolt-on for the submission.

## Known limits

- ERC-20 approvals only in v1. NFT operator approvals (`setApprovalForAll`)
  are not scanned: without an indexer the agent cannot enumerate which NFT
  collections a wallet holds.
- Curated token/spender lists (see above). Use `?tokens=` / `?spenders=` or
  BscScan's approval checker for full coverage.
- Prices are best-effort and can be missing.

## Run it

```bash
npx wrangler dev      # local test at http://127.0.0.1:8787
npx wrangler deploy   # deploys to <name>.<your-subdomain>.workers.dev
```

Single file, no dependencies, no build step: `worker.js` + `wrangler.toml`.

## Verified live

- `0x670799b408172cc8688EfA62C101B8634f362A16` — score 100/A/SAFE, 0
  approvals (matches an independent on-chain allowance audit of that wallet).
- `0xF977814e90dA44bFA03b6295A0616a897441aceC` (Binance hot wallet) — balances
  read correctly (200,000,111 USDT, 200,000,000 USDC, 21,300 BTCB, …), 0
  approvals.
- `0x550054270db2d05fe4b8ea1a4e420a6db6def1c6` (a live PancakeSwap user) —
  score 60/C/REVIEW: 1 unlimited WBNB approval to the PancakeSwap V2
  Router, $154.94 actually at risk.
