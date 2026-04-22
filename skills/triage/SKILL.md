---
name: triage
---

Triage the provided IOC(s). For each:

1. Run Swiss `enrich` to auto-detect type and fan out across all sources.
2. Summarise findings in a table: source, verdict, score/confidence, key details.
3. Check Graylog for any internal log hits related to the IOC.
4. Give an overall assessment: malicious / suspicious / benign / inconclusive with confidence level.
5. Recommend next steps (escalate, block, monitor, or close).

Defang all IOCs in your output.
