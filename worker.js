// Wallet Guard — a read-only BSC wallet approval scanner.
// Agent Games (zkVerify) — Wildcard track submission.
//
// What it does: given a BSC wallet address, it checks the wallet's ERC-20
// token allowances against a curated set of spenders and produces a plain
// language risk report: unlimited approvals, approvals to EOAs or unknown
// contracts, stale approvals, and the USD value at risk.
//
// How it works: every check is a read-only eth_call, batched into ONE
// Multicall3 aggregate3 call (no indexer, no API key, no logs). The agent
// never asks for a wallet connection, never signs anything, and never moves
// funds. Public RPC failover across several BSC endpoints.
//
// Honest limits (stated in every report): the scan covers a curated list of
// tokens x spenders. An approval to a spender outside that list is not seen
// by this scan; the report says exactly what was checked.

const MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11";
const CHAIN = { id: 56, name: "BNB Smart Chain", short: "BSC" };
const MAX_UINT = (2n ** 256n) - 1n;

const RPCS = [
  "https://bsc-dataseed1.bnbchain.org",
  "https://bsc-dataseed2.bnbchain.org",
  "https://bsc-dataseed4.bnbchain.org",
  "https://bsc.publicnode.com",
  "https://1rpc.io/bnb",
];

// Curated tokens: the highest-value BEP-20s on BSC. All 18 decimals.
// Users can add more with ?tokens=0x...,0x...
const TOKENS = [
  { symbol: "USDT", address: "0x55d398326f99059fF775485246999027B3197955", decimals: 18, coingecko: "tether" },
  { symbol: "USDC", address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", decimals: 18, coingecko: "usd-coin" },
  { symbol: "WBNB", address: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bC095c", decimals: 18, coingecko: "wbnb" },
  { symbol: "BUSD", address: "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", decimals: 18, coingecko: "binance-usd" },
  { symbol: "BTCB", address: "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", decimals: 18, coingecko: "bitcoin" },
  { symbol: "ETH",  address: "0x2170Ed0880ac9A755fd29B2688956BD959F933F8", decimals: 18, coingecko: "ethereum" },
  { symbol: "CAKE", address: "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", decimals: 18, coingecko: "pancakeswap-token" },
];

// Curated spenders: contracts a BSC wallet most commonly approves.
// Verified addresses only (PancakeSwap docs, Etherscan). Anything not in
// this list is treated as UNKNOWN by the scorer, which is itself a signal.
const SPENDERS = [
  { name: "PancakeSwap V2 Router", address: "0x10ED43C718714eb63d5aA57B78B54704E256024E", trust: "trusted", note: "The most used DEX router on BSC." },
  { name: "PancakeSwap V3 Universal Router", address: "0x1A0A18AC4BECDDbd6389559687d1A73d8927E416", trust: "trusted", note: "PancakeSwap v3 router (official docs)." },
  { name: "PancakeSwap Infinity Router", address: "0xd9C500DfF816a1Da21A48A732d3498Bf09dc9AEB", trust: "trusted", note: "PancakeSwap Infinity router (official docs)." },
  { name: "1inch Aggregation Router V5", address: "0x1111111254EEB25477B68fb85Ed929f73A960582", trust: "trusted", note: "1inch aggregator, same address on all EVM chains." },
  { name: "WBNB", address: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bC095c", trust: "trusted", note: "Wrapping / unwrapping BNB." },
];

// ---------- tiny ABI helpers (no dependencies) ----------
const hexPad = (n, len = 64) => n.toString(16).padStart(len, "0");
const encAddr = (a) => "000000000000000000000000" + a.slice(2).toLowerCase();
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const hexToBytes = (hex) => {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const encBytes = (bytes) => {
  const h = bytesToHex(bytes);
  return hexPad(bytes.length) + h + "0".repeat((64 - (h.length % 64)) % 64);
};
const SEL = {
  balanceOf: "70a08231",
  allowance: "dd62ed3e",
  aggregate3: "82ad56cb",
};

function encodeAggregate3(calls) {
  // calls: [{target, allowFailure, callData: Uint8Array}]
  const elems = calls.map(({ target, allowFailure, callData }) =>
    encAddr(target) + hexPad(allowFailure ? 1 : 0) + hexPad(96) + encBytes(callData)
  );
  const parts = [hexPad(0x20), hexPad(calls.length)];
  let off = calls.length * 32;
  for (const e of elems) { parts.push(hexPad(off)); off += e.length / 2; }
  parts.push(...elems);
  return "0x" + SEL.aggregate3 + parts.join("");
}

function decodeAggregate3(hex) {
  const raw = hexToBytes(hex);
  const u32 = (p) => {
    let v = 0n;
    for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(raw[p + i]);
    return Number(v);
  };
  const n = u32(32);
  const out = [];
  for (let i = 0; i < n; i++) {
    const o = u32(64 + i * 32);
    const base = 64 + o;
    const success = u32(base) === 1;
    const doff = u32(base + 32);
    const dstart = base + doff;
    const dlen = u32(dstart);
    out.push({ success, data: raw.slice(dstart + 32, dstart + 32 + dlen) });
  }
  return out;
}

const toBig = (buf) => (buf.length === 0 ? 0n : BigInt("0x" + bytesToHex(buf)));
const fmtAmount = (raw, decimals) => {
  const s = raw.toString(10).padStart(decimals + 1, "0");
  const int = s.slice(0, -decimals).replace(/^0+(?=\d)/, "") || "0";
  const frac = s.slice(-decimals).replace(/0+$/, "");
  return frac ? `${int}.${frac}` : int;
};

// ---------- RPC ----------
async function rpc(rpcUrl, method, params, timeoutMs = 9000) {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "user-agent": "WalletGuard/1.0 (+https://github.com/zairzuab/wallet-guard)",
    },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const j = await res.json();
  if (j.error) throw new Error(`RPC ${method} failed on ${rpcUrl}: ${j.error.message || JSON.stringify(j.error)}`);
  return j.result;
}

async function rpcAny(method, params) {
  let lastErr = null;
  for (const url of RPCS) {
    try {
      const r = await rpc(url, method, params);
      return { rpc: url, result: r };
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error("all RPC endpoints failed");
}

async function multicall(calls) {
  const data = encodeAggregate3(calls);
  const { rpc: usedRpc, result } = await rpcAny("eth_call", [{ to: MULTICALL3, data }, "latest"]);
  return { rpc: usedRpc, results: decodeAggregate3(result) };
}

// ---------- prices (best effort, CoinGecko free API) ----------
async function fetchPrices(ids) {
  try {
    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${ids.join(",")}&vs_currencies=usd`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000), headers: { "user-agent": "WalletGuard/1.0" } });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

// ---------- scoring ----------
function scoreApproval(a) {
  const findings = [];
  let points = 0;
  if (a.unlimited) {
    points += 40;
    findings.push({ level: "critical", text: "UNLIMITED approval — this spender can move any amount of this token, at any time, until you revoke it." });
  }
  if (a.spenderIsEOA) {
    points += 30;
    findings.push({ level: "high", text: "Spender is an externally-owned account (a person, not a contract). It can drain the allowance directly with no contract logic in the way." });
  } else if (a.spenderTrust === "unknown") {
    points += 15;
    findings.push({ level: "medium", text: "Spender is an unknown contract — not on the guard's list of well-known protocols. Treat it as untrusted until verified." });
  } else {
    findings.push({ level: "info", text: `Spender is a well-known protocol (${a.spenderName}). The risk here is the size of the allowance, not the counterparty.` });
  }
  if (a.balanceRaw === 0n) {
    points += 5;
    findings.push({ level: "low", text: "Stale approval: you hold none of this token right now, but any future deposit could be taken up to the allowance. Revoke it." });
  }
  if (a.exposureUsd !== null && a.exposureUsd > 5000) {
    points += 10;
    findings.push({ level: "high", text: `Large exposure: over $${Math.round(a.exposureUsd).toLocaleString()} of this token is within the allowance.` });
  }
  return { findings, points: Math.max(0, points) };
}

function grade(score) {
  if (score >= 90) return { grade: "A", verdict: "SAFE" };
  if (score >= 75) return { grade: "B", verdict: "LOW RISK" };
  if (score >= 50) return { grade: "C", verdict: "REVIEW" };
  if (score >= 25) return { grade: "D", verdict: "AT RISK" };
  return { grade: "F", verdict: "CRITICAL" };
}

// ---------- the scan ----------
function parseAddressList(raw) {
  if (!raw) return [];
  return raw.split(",").map((s) => s.trim()).filter((s) => /^0x[0-9a-fA-F]{40}$/.test(s));
}

async function scanWallet(address, extraTokens, extraSpenders) {
  const wallet = address.toLowerCase();
  const tokens = [...TOKENS];
  for (const t of extraTokens) {
    if (!tokens.some((x) => x.address.toLowerCase() === t.toLowerCase())) {
      tokens.push({ symbol: "CUSTOM", address: t, decimals: 18, coingecko: null });
    }
  }
  const spenders = [...SPENDERS];
  for (const s of extraSpenders) {
    if (!spenders.some((x) => x.address.toLowerCase() === s.toLowerCase())) {
      spenders.push({ name: "Custom spender", address: s, trust: "unknown", note: "Supplied by the caller." });
    }
  }

  // One Multicall3 call: balances + every (token x spender) allowance.
  const calls = [];
  const plan = [];
  for (const t of tokens) {
    calls.push({ target: t.address, allowFailure: true, callData: hexToBytes(SEL.balanceOf + encAddr(wallet)) });
    plan.push({ kind: "balance", token: t });
  }
  for (const t of tokens) {
    for (const s of spenders) {
      calls.push({ target: t.address, allowFailure: true, callData: hexToBytes(SEL.allowance + encAddr(wallet) + encAddr(s.address)) });
      plan.push({ kind: "allowance", token: t, spender: s });
    }
  }
  const { rpc: usedRpc, results } = await multicall(calls);

  const balances = new Map();
  const allowances = [];
  results.forEach((r, i) => {
    const p = plan[i];
    if (!r.success) return;
    const v = toBig(r.data);
    if (p.kind === "balance") balances.set(p.token.address.toLowerCase(), v);
    else allowances.push({ token: p.token, spender: p.spender, raw: v });
  });

  // Prices (best effort) for USD exposure.
  const priceIds = [...new Set(tokens.map((t) => t.coingecko).filter(Boolean))];
  const prices = priceIds.length ? await fetchPrices(priceIds) : null;
  const priceOf = (t) => {
    if (!t.coingecko || !prices || !prices[t.coingecko]) return null;
    return prices[t.coingecko].usd;
  };

  // Spender code check: is each nonzero spender an EOA (no code) or a contract?
  const nonzero = allowances.filter((a) => a.raw > 0n);
  const spenderAddrs = [...new Set(nonzero.map((a) => a.spender.address.toLowerCase()))];
  const codeMap = new Map();
  await Promise.all(spenderAddrs.map(async (s) => {
    try {
      const { result } = await rpcAny("eth_getCode", [s, "latest"]);
      codeMap.set(s, result && result !== "0x" ? "contract" : "eoa");
    } catch { codeMap.set(s, "unknown"); }
  }));

  const approvals = nonzero.map((a) => {
    const balanceRaw = balances.get(a.token.address.toLowerCase()) || 0n;
    const price = priceOf(a.token);
    const balanceUsd = price === null ? null : Number(fmtAmount(balanceRaw, a.token.decimals)) * price;
    const allowanceUsd = price === null ? null : Number(fmtAmount(a.raw, a.token.decimals)) * price;
    // Exposure is capped at the balance: a spender can take at most what the
    // wallet holds right now. (For an unlimited allowance the raw allowance
    // value is 2^256-1, which would otherwise print an absurd dollar figure.)
    const exposureUsd = (allowanceUsd === null || balanceUsd === null) ? null : Math.min(allowanceUsd, balanceUsd);
    const unlimited = a.raw === MAX_UINT;
    const item = {
      token: a.token.symbol,
      tokenAddress: a.token.address,
      spender: a.spender.address,
      spenderName: a.spender.name,
      spenderTrust: a.spender.trust,
      spenderIsEOA: codeMap.get(a.spender.address.toLowerCase()) === "eoa",
      allowance: fmtAmount(a.raw, a.token.decimals),
      allowanceRaw: a.raw.toString(),
      unlimited,
      balance: fmtAmount(balanceRaw, a.token.decimals),
      balanceUsd: balanceUsd === null ? null : Math.round(balanceUsd * 100) / 100,
      exposureUsd: exposureUsd === null ? null : Math.round(exposureUsd * 100) / 100,
    };
    const scored = scoreApproval(item);
    return { ...item, riskPoints: scored.points, findings: scored.findings };
  });

  approvals.sort((x, y) => y.riskPoints - x.riskPoints || (y.exposureUsd || 0) - (x.exposureUsd || 0));
  const totalPoints = approvals.reduce((s, a) => s + a.riskPoints, 0);
  const score = Math.max(0, 100 - totalPoints);
  const { grade: g, verdict } = grade(score);

  return {
    wallet: address,
    chain: `${CHAIN.name} (chain ${CHAIN.id})`,
    scannedAt: new Date().toISOString(),
    rpc: usedRpc,
    coverage: {
      method: "Multicall3 aggregate3 eth_call (read-only, no indexer, no API key)",
      tokensChecked: tokens.map((t) => `${t.symbol} (${t.address})`),
      spendersChecked: spenders.map((s) => `${s.name} (${s.address})`),
      note: "This scan covers the curated tokens x spenders above. An approval to a spender outside this list is NOT seen here — for a full history-based view, use BscScan's Token Approval Checker.",
    },
    balances: tokens.map((t) => ({
      token: t.symbol,
      address: t.address,
      balance: fmtAmount(balances.get(t.address.toLowerCase()) || 0n, t.decimals),
    })).filter((b) => b.balance !== "0"),
    approvals,
    summary: {
      score,
      grade: g,
      verdict,
      approvalsFound: approvals.length,
      unlimitedCount: approvals.filter((a) => a.unlimited).length,
      eoaSpenderCount: approvals.filter((a) => a.spenderIsEOA).length,
      unknownSpenderCount: approvals.filter((a) => a.spenderTrust === "unknown").length,
      totalExposureUsd: approvals.reduce((s, a) => s + (a.exposureUsd || 0), 0),
    },
    revoke: {
      how: "Revoking an approval costs a small amount of BNB gas and sets the allowance back to zero. You revoke from your own wallet — this agent never signs or submits anything.",
      tools: [
        { name: "BscScan Token Approval Checker", url: "https://bscscan.com/tokenapprovalchecker" },
        { name: "revoke.cash", url: "https://revoke.cash" },
      ],
    },
    disclaimer: "Read-only report. Prices are best-effort (CoinGecko) and may be missing. This is not financial advice; verify any revocation in your own wallet before signing.",
  };
}

// ---------- HTTP ----------
const EXAMPLE_WALLET = "0x670799b408172cc8688EfA62C101B8634f362A16";

function htmlPage() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wallet Guard — BSC approval scanner</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#e8e8e8;background:#101418}h1{font-size:28px}a{color:#7cc4ff}input{width:100%;padding:10px;font-size:15px;border-radius:8px;border:1px solid #444;background:#1a2129;color:#fff}button{padding:10px 18px;font-size:15px;border-radius:8px;border:0;background:#2f81f7;color:#fff;cursor:pointer;margin-top:10px}pre{background:#1a2129;padding:14px;border-radius:8px;overflow:auto;font-size:13px}.card{background:#1a2129;border-radius:10px;padding:14px;margin:12px 0}.crit{color:#ff7b72}.high{color:#ffa657}.med{color:#e3b341}.ok{color:#3fb950}.muted{color:#9aa4b2;font-size:13px}</style></head>
<body>
<h1>🛡️ Wallet Guard</h1>
<p>A read-only guard for BSC wallets. It checks your token approvals — unlimited allowances, approvals to unknown contracts or plain wallets (EOAs), stale approvals — and tells you, in plain language, what is at risk and how to revoke it. It never asks for a wallet connection and never signs anything.</p>
<p class="muted">Agent Games (zkVerify) — Wildcard track. Chain: BNB Smart Chain. Method: one Multicall3 read call, no indexer, no API key.</p>
<form id="f"><input id="addr" placeholder="Wallet address, e.g. 0x..." value=""><br>
<button type="submit">Scan wallet</button>
<button type="button" id="ex">Try an example</button></form>
<div id="out"></div>
<script>
const out=document.getElementById('out');
document.getElementById('ex').onclick=()=>{document.getElementById('addr').value='${EXAMPLE_WALLET}';document.getElementById('f').requestSubmit();};
document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const a=document.getElementById('addr').value.trim();out.innerHTML='<p>Scanning…</p>';try{const r=await fetch('/scan?address='+encodeURIComponent(a));const j=await r.json();if(!r.ok){out.innerHTML='<p class="crit">'+(j.error||'scan failed')+'</p>';return;}const s=j.summary;let h='<div class="card"><h2>Score '+s.score+'/100 — Grade '+s.grade+' — '+s.verdict+'</h2><p>'+s.approvalsFound+' approval(s) found · '+s.unlimitedCount+' unlimited · '+s.eoaSpenderCount+' to plain wallets (EOAs) · '+s.unknownSpenderCount+' to unknown contracts</p><p class="muted">Scanned '+j.scannedAt+' via '+j.rpc+'</p></div>';for(const ap of j.approvals){h+='<div class="card"><b>'+ap.token+'</b> → '+ap.spenderName+' <span class="muted">'+ap.spender.slice(0,10)+'…</span><br>Allowance: <b>'+(ap.unlimited?'UNLIMITED':ap.allowance)+'</b> · Balance: '+ap.balance+(ap.exposureUsd!==null?' · Exposure: $'+ap.exposureUsd.toLocaleString():'')+'<br>'+ap.findings.map(f=>'<span class="'+(f.level==='critical'?'crit':f.level==='high'?'high':f.level==='medium'?'med':'ok')+'">• '+f.text+'</span>').join('<br>')+'</div>';}if(!j.approvals.length)h+='<div class="card"><b class="ok">No approvals found for the checked tokens × spenders.</b><br><span class="muted">This scan covers a curated list — see the JSON for exactly what was checked.</span></div>';h+='<p class="muted">Revoke: <a href="https://bscscan.com/tokenapprovalchecker" target="_blank">BscScan Token Approval Checker</a> · <a href="https://revoke.cash" target="_blank">revoke.cash</a> — revoking costs a little BNB gas and is done from your own wallet.</p><details><summary>Raw JSON</summary><pre>'+JSON.stringify(j,null,2)+'</pre></details>';out.innerHTML=h;}catch(err){out.innerHTML='<p class="crit">Scan failed: '+err.message+'</p>';}};
</script>
<p class="muted">API: <code>GET /scan?address=0x…</code> — optional <code>&amp;tokens=0x…,0x…</code> and <code>&amp;spenders=0x…,0x…</code> to extend the curated lists. <code>GET /health</code> for liveness. Source: <a href="https://github.com/zairzuab/wallet-guard">github.com/zairzuab/wallet-guard</a>.</p>
</body></html>`;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/" || url.pathname === "/index.html") {
        return new Response(htmlPage(), { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      if (url.pathname === "/health") {
        return Response.json({ ok: true, service: "wallet-guard", chain: "BSC (56)", time: new Date().toISOString() });
      }
      if (url.pathname === "/scan") {
        const address = (url.searchParams.get("address") || "").trim();
        if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
          return Response.json({ error: "Pass a valid BSC wallet address: /scan?address=0x..." }, { status: 400 });
        }
        const extraTokens = parseAddressList(url.searchParams.get("tokens") || "");
        const extraSpenders = parseAddressList(url.searchParams.get("spenders") || "");
        const report = await scanWallet(address, extraTokens, extraSpenders);
        if (url.searchParams.get("format") === "html") {
          return new Response(`<!DOCTYPE html><html><body><pre>${JSON.stringify(report, null, 2)}</pre></body></html>`, { headers: { "content-type": "text/html; charset=utf-8" } });
        }
        return Response.json(report);
      }
      return Response.json({ error: "not found. Try / (demo) or /scan?address=0x..." }, { status: 404 });
    } catch (e) {
      return Response.json({ error: `scan failed: ${e.message}` }, { status: 502 });
    }
  },
};
