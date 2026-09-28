# SOC AI Analyst (T-70 / ADR-014)

Grounded, model-agnostic AI analyst on top of Wazuh alerts. Pure Python stdlib.

| Level | Command | What it does | Safety |
|---|---|---|---|
| L1 | `soc_ai.py explain --rule 100404` | explain an alert (MITRE, severity, next steps) | RAG context only; citations checked; unknown rule/MITRE IDs → rejected → deterministic fallback |
| L2 | `soc_ai.py correlate [--narrate]` | group alerts into incidents by srcip/file/mac + 15 min window, ATT&CK kill chain, risk score | noise (SCA/rootcheck/pam/sudo) excluded; AR results (651/100092/100093) joined to their incident |
| L3 | `soc_ai.py suggest INC-xxxx` → `respond INC-xxxx block_ip --agent 001 --approver NAME --approve HASH` | proposes actions from a fixed allowlist; executes via Wazuh API `PUT /active-response` (`!firewall-drop`) | LLM may only rank/drop; human approval hash; protected IPs/users; parameters only from incident members; JSONL audit |
| — | `soc_ai.py report --out report.md` | incident report | — |

Knowledge: project rules (`wazuh/manager/rules`), Wazuh 4.14.7 built-in rule meanings and MITRE ATT&CK v19.2 extracts (`data/`, see `data/SOURCES.md`), runbooks (`docs/lab`). BM25 retrieval.

Environment: `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `SOC_AI_MODEL` (default `gpt-5-mini`; Ollama: `OPENAI_BASE_URL=http://127.0.0.1:11434/v1 SOC_AI_MODEL=llama3.1`), `SOC_AI_OFFLINE=1`, `SOC_AI_LANG`, `WAZUH_API_URL/USER/PASSWORD` (never in Git).

Verified live 2026-09-28 (wazuh-manager 4.14.7 + agent kali1 001 active):
- L1 with gpt-5-mini: Arabic answer, citations rule:100404/100402/100401, mitre:T1078/T1110, passed guard (≈30 s).
- L3: MikroTik brute force (UDP 514) → 100402/100404 → incident → proposal `block_ip 10.99.0.111` → approved → Wazuh API → `iptables -A INPUT -s 10.99.0.111 -j DROP` on the agent in 0.79 s; 651 alert; audit record.
- Findings fixed: bare `firewall-drop` → API error 1652 (needs `!`); `error:0` with 0 affected items is not success; parameters were taken from unrelated alerts (safety bug).

Tests: `tests/test_ai_agent.py` (22, no network).
