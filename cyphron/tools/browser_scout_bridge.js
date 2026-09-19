#!/usr/bin/env node
"use strict";
/*
 * browser_scout_bridge — jembatan CDP untuk engine browser_scout (Python).
 *
 * Menerima: --cdp-port N --urls u1|u2|... --timeout-ms N --settle-ms N
 *           --max-pages N --target-host example.test
 * Menghasilkan: SATU objek JSON ke stdout:
 *   {"pages": [{url, final_url, status, dom, requests, cookies,
 *               third_party_blocked, errors}], "errors": [...]}
 *
 * Pagar yang ditegakkan di dalam browser (bukan hanya di Python):
 * - Fetch.requestPaused: request di luar --target-host DIBLOKIR
 *   (BlockedByClient) sebelum keluar jaringan -> scope per-destination
 *   berlaku juga untuk semua subresource SPA.
 * - GET/navigation saja dari sisi scout; halaman berjalan normal, tapi
 *   jumlah halaman dan waktu dibatasi ketat.
 * - Profil browser terisolasi dikelola sisi Python; bridge tidak menyentuh
 *   disk kecuali stdout.
 */

const http = require("http");

const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith("--")) args[a.slice(2)] = process.argv[i + 1];
}

const CDP_PORT = parseInt(args["cdp-port"], 10);
const MAX_PAGES = Math.max(1, Math.min(parseInt(args["max-pages"] || "5", 10), 8));
const TIMEOUT_MS = Math.max(2000, Math.min(parseInt(args["timeout-ms"] || "10000", 10), 30000));
const SETTLE_MS = Math.max(0, Math.min(parseInt(args["settle-ms"] || "1200", 10), 8000));
const TARGET_HOST = (args["target-host"] || "").toLowerCase();
const URLS = (args["urls"] || "").split("|").filter(Boolean).slice(0, MAX_PAGES);

function httpJson(method, path) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port: CDP_PORT, path, method, timeout: 5000 },
      (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => {
          try { resolve(JSON.parse(b)); }
          catch (e) { reject(new Error("bad-json: " + b.slice(0, 80))); }
        });
      });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("http-timeout")));
    req.end();
  });
}

async function newTab(url) {
  // Chrome 111+ mewajibkan PUT untuk /json/new; Edge lama masih GET.
  try { return await httpJson("PUT", "/json/new?" + encodeURIComponent(url)); }
  catch (e) { return await httpJson("GET", "/json/new?" + encodeURIComponent(url)); }
}

function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    let ws;
    try { ws = new WebSocket(wsUrl); }
    catch (e) { return reject(e); }
    ws.addEventListener("open", () => resolve(ws));
    ws.addEventListener("error", () => reject(new Error("ws-error")));
    setTimeout(() => reject(new Error("ws-timeout")), 8000);
  });
}

class Cdp {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = {};
    ws.addEventListener("message", (ev) => {
      let msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message || "cdp-error"));
        else resolve(msg.result);
      } else if (msg.method && this.handlers[msg.method]) {
        for (const h of this.handlers[msg.method]) {
          try { h(msg.params); } catch (e) { /* event handler tidak boleh crash */ }
        }
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try { this.ws.send(JSON.stringify({ id, method, params })); }
      catch (e) { this.pending.delete(id); reject(e); }
    });
  }
  on(method, handler) {
    (this.handlers[method] = this.handlers[method] || []).push(handler);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function sameSite(v) {
  if (v === "Strict") return "strict";
  if (v === "Lax") return "lax";
  return "unspecified";
}

async function scoutPage(url) {
  const page = {
    url, final_url: url, status: null, dom: "",
    requests: [], cookies: [], third_party_blocked: 0, errors: [],
  };
  const tab = await newTab("about:blank");
  if (!tab || !tab.webSocketDebuggerUrl) throw new Error("no-tab");
  const ws = await connect(tab.webSocketDebuggerUrl);
  const cdp = new Cdp(ws);
  await cdp.send("Page.enable");
  await cdp.send("Network.enable");
  await cdp.send("Runtime.enable");
  let fetchOn = true;
  try { await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*" }] }); }
  catch (e) { fetchOn = false; page.errors.push("fetch-gate-off"); }

  if (fetchOn) {
    cdp.on("Fetch.requestPaused", (p) => {
      let host = "";
      try { host = new URL(p.request.url).hostname.toLowerCase(); } catch (e) {}
      const inScope = host === TARGET_HOST || host.endsWith("." + TARGET_HOST);
      if (inScope) {
        cdp.send("Fetch.continueRequest", { requestId: p.requestId })
          .catch(() => {});
      } else {
        page.third_party_blocked += 1;
        cdp.send("Fetch.failRequest",
                 { requestId: p.requestId, errorReason: "BlockedByClient" })
          .catch(() => {});
      }
    });
  }

  const reqMeta = new Map(); // requestId -> {url, method, type}
  cdp.on("Network.requestWillBeSent", (p) => {
    reqMeta.set(p.requestId, {
      url: p.request.url, method: p.request.method, type: p.type || "",
    });
  });
  cdp.on("Network.responseReceived", (p) => {
    const meta = reqMeta.get(p.requestId) || { url: "", method: "GET", type: "" };
    let host = "";
    try { host = new URL(meta.url).hostname.toLowerCase(); } catch (e) {}
    const inScope = host === TARGET_HOST || host.endsWith("." + TARGET_HOST);
    const hdrs = {};
    for (const h of (p.response.headers || {}) ? Object.entries(p.response.headers) : []) {
      hdrs[h[0].toLowerCase()] = h[1];
    }
    page.requests.push({
      url: meta.url, method: meta.method, type: meta.type,
      status: p.response.status || null,
      mime: p.response.mimeType || "",
      host, in_scope: inScope,
      set_cookie: hdrs["set-cookie"] || "",
    });
    if (p.requestId === undefined) return;
    if (meta.type === "Document" && page.status === null) page.status = p.response.status;
  });
  cdp.on("Network.loadingFailed", (p) => {
    const meta = reqMeta.get(p.requestId);
    if (meta) page.requests.push({ url: meta.url, method: meta.method,
                                   type: meta.type, status: null, failed: true,
                                   in_scope: false, host: "", mime: "",
                                   set_cookie: "" });
  });

  const loaded = new Promise((resolve) => cdp.on("Page.loadEventFired", resolve));
  await cdp.send("Page.navigate", { url });
  await Promise.race([loaded, sleep(TIMEOUT_MS)]);
  await sleep(SETTLE_MS); // beri waktu XHR/fetch SPA menyelesaikan capture

  try {
    const loc = await cdp.send("Runtime.evaluate",
                               { expression: "location.href", returnByValue: true });
    if (loc && loc.result && loc.result.value) page.final_url = loc.result.value;
  } catch (e) { page.errors.push("location: " + e.message); }

  try {
    const dom = await cdp.send("Runtime.evaluate", {
      expression: "document.documentElement ? document.documentElement.outerHTML : ''",
      returnByValue: true,
    });
    page.dom = String((dom && dom.result && dom.result.value) || "").slice(0, 2000000);
  } catch (e) { page.errors.push("dom: " + e.message); }

  try {
    const ck = await cdp.send("Network.getAllCookies");
    page.cookies = (ck.cookies || []).map((c) => ({
      name: c.name, domain: c.domain, path: c.path,
      http_only: !!c.httpOnly, secure: !!c.secure,
      same_site: sameSite(c.sameSite), session: c.expires === -1 || c.expires < 0,
    }));
  } catch (e) { page.errors.push("cookies: " + e.message); }

  try { ws.close(); } catch (e) {}
  return page;
}

(async () => {
  const out = { pages: [], errors: [] };
  if (!Number.isFinite(CDP_PORT)) out.errors.push("bad-cdp-port");
  if (!TARGET_HOST) out.errors.push("bad-target-host");
  for (const url of URLS) {
    if (out.errors.length && !out.pages.length) break;
    try { out.pages.push(await scoutPage(url)); }
    catch (e) { out.errors.push(`${url}: ${e.message}`); }
  }
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
})().catch((e) => {
  process.stdout.write(JSON.stringify({ pages: [], errors: [String(e && e.message)] }));
  process.exit(0);
});
