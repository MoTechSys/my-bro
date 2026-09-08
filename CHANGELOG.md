# Changelog

All notable changes to this repository. Format: [Keep a Changelog](https://keepachangelog.com/). Dates are ISO-8601.

## [0.1.0] — 2026-09-09 — Session 01: Repository foundation

### Added
- `AI_AGENT_START_HERE.md` — mandatory entry protocol for any AI session (reading order, zero-hallucination rules, rule-ID namespaces, git workflow).
- `docs/00_PROJECT_STATE.md` — live state + exact next action.
- `docs/01_SOURCE_ANALYSIS.md` — deep analysis of the 7 uploaded sources (2 PDF, 3 DOCX, 2 voice notes) with cross-source consistency matrix.
- `docs/02_ARCHITECTURE.md` — lab facts (IPs, versions, agents, rule-ID registry, paths, ports) each tagged with its evidence screenshot.
- `docs/03_ROADMAP.md` — phases P0–P3 with acceptance criteria.
- `docs/04_ISSUES_LOG.md` — 31 issues/inconsistencies found in the sources + 7 open questions for the team.
- `docs/DECISIONS.md` — 10 ADRs.
- `docs/lab/UC-01..UC-08` — corrected runbooks for every implemented use case.
- `docs/thesis/README.md` — thesis structure and chapter status.
- `docs/sources/` — originals (incl. **repaired** `04_thesis_ch1_ch3_latest_REPAIRED.docx`), extracted text, 90 screenshots, voice notes.
- `wazuh/` — clean deployable config: `local_rules.xml` (13 rules, unique IDs), `local_decoder.xml`, CDB lists, manager/agent `ossec.conf` snippets, Active Response scripts (Linux sh, Windows py/bat), auditd rules, Suricata patch.
- `scripts/validate/` — `check_rule_ids.py` (duplicate IDs, if_sid chain, namespaces, secrets) + `validate_all.sh`.
- `scripts/attack-emulation/malware_downloader.sh` — from Wazuh docs (lab use only).
- `extension/VISION_AND_FEASIBILITY.md` — feasibility of the team's expansion vision (network devices, phones, autonomous response).
- `.github/workflows-pending/validate.yml` — CI running the validators (move to `workflows/` to enable; token lacked `workflows` scope).

### Fixed (in repo — not yet applied to the lab)
- ISSUE-010 duplicate rule IDs 100300/100301/108000/108001.
- ISSUE-008 wrong `local_rules.xml` path in guide.
- ISSUE-009 `chmod 777` on Suricata rules → 644.
- ISSUE-020 YARA rules in `/tmp` → `/var/ossec/etc/yara/rules/`.
- ISSUE-021 duplicate `HOME_NET` in suricata.yaml.
- ISSUE-030 unquoted `$FILENAME` in `remove-threat.sh`.
- Deduplicated `suspicious-programs` CDB list.
