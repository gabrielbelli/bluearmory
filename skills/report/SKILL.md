---
name: report
---

Generate a structured incident report from the current investigation. Include:

1. **Executive Summary** — one paragraph, plain language, suitable for management.
2. **IOC Table** — all indicators with type, defanged value, verdict, and sources.
3. **Timeline** — chronological sequence of observed events.
4. **Analysis** — detailed technical findings with MITRE ATT&CK mapping where applicable.
5. **Recommendations** — containment, eradication, and recovery actions.
6. **Appendix** — raw tool outputs referenced in the analysis.

If a DFIR-IRIS case exists for this investigation, also push the timeline events and IOCs to it.
