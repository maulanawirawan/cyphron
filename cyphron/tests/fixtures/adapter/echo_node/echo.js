#!/usr/bin/env node
// fixture adapter test: kontrak stdin-args JSON -> stdout JSON
let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  let args = {};
  try { args = JSON.parse(raw || "{}"); } catch (e) {}
  const findings = [];
  if (args.emit_finding) {
    findings.push({ title: "Temuan sah dari adapter node", severity: "low",
                    description: "fixture", confidence: 0.6,
                    finding_class: "posture" });
    findings.push({ title: "Tidak sah - severity ngarang",
                    severity: "mega-critical" });
  }
  process.stdout.write("log baris dulu\n");
  process.stdout.write(JSON.stringify({
    ok: true,
    data: { echo: args.hello || null, double: (args.n || 0) * 2 },
    findings,
    requests: args.requests || 0,
  }));
});
