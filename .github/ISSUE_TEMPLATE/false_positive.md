---
name: False positive report
about: A secai tool flagged something that is not real
title: "[fp] "
labels: false-positive
assignees: ""
---

<!-- False-positive reports are first-class citizens here: every
     detector has an anti-FP floor, and reports like this tighten it
     for everyone. -->

**Which tool/skill + check id?**

<!-- e.g. `webshell_triage` / check `webshell-cmd-param` -->

**What was flagged, and why is it wrong?**

<!-- Paste the finding (REDACT credentials, tokens, hostnames).
     Explain the benign reality: e.g. "this is our backup tool's
     scheduled export". -->

**The evidence that was available**

<!-- What did the input look like (sanitized excerpt)? The tool's
     decision can only be as good as the evidence shape it was given. -->

**Would an allowlist flag have fixed your case?**

<!-- Many tools expose --allow-*/--allow-check with suppression
     counts recorded. If a general rule fix is needed instead, say
     what distinguishes benign from malicious here. -->

**Environment**

- OS:
- Commit / release:
