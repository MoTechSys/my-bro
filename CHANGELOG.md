# Changelog

> **خاتمة هذه الدفعة — 2026-09-23:** انتهت مراجعةcollector ccdc4a2c وحُكمت بنودها التسعة فيtests/README؛ لا تعاد. أضيف اتساق ساعةmanager/observer في6853581 واختباراه في414384d؛ **48 اختبارcollector و800 كليًا ناجحة على414384d**. ذكرrunning أو46/798 أدناه لقطة سابقة. محولات الدايمونات/Windows/controller وt4/t5 وISSUE-068 وبقية التدقيق ما زالت أعمالًا محلية؛ لا نشر أو قبول أصلي. رأس التسليم وCI النهائي فيPR28.

## [Unreleased] — 2026-09-23 — [AI] bounded UC-01 collector and partial thesis audit

- Added read-only fixed manager/systemd queries, unique durable intents, private raw-byte replay and binding to source-observer stores and the existing evaluator. No restart, enrollment or native execution in development.
- Added46 synthetic tests, including real private stores through evaluator;798 full tests passed on4b85b6f. Fixed strict boolean/integer handling, missing source diagnostics, timestamp canonicalization and future snapshot chronology.
- Archived five versioned source files and provenance. Stock Wazuh forking/RemainAfterExit may not satisfy the strict main-process adapter: multi-daemon, Windows/non-systemd and original controller capture remain local work.
- Updated chapters1/4 for ADR014, bounded claims, historical inventory, explicit Filebeat and existing vector references. No full source-image/reference audit or original results claimed.
- Independent automated reviewccdc4a2c targets c7acf13 and was still running at this entry; receipt in research/inbox. CI and final delivery checkpoint inPR28.

## [Unreleased] — 2026-09-23 — [AI] UC-01 offline connection evidence evaluator

- Added a standalone private-input evaluator for predeclared connection cycles; keeps missing/excluded planned cycles in the denominator and never exports MTTD or Wilson.
- Separates observed status transitions from functional evidence; requires service incarnation continuity, a new matched FIM creation canary and a subsequent active sample. Rejects shared evidence, overlapping cycles, clock jumps, invalid timing and identity changes.
- Bounded JSONL parsing before object creation; private regular single-link inputs, no-follow final paths, generic nonleaking CLI errors and input/source hashes.
- Adjudicated independent static review6f1083f8, fixed old-instance/chain validation, and exposed clock-domain and nonverification flags.72 new tests;752 total locally on614f9d3. Final-head CI checked separately inPR28.
- Native collection, byte binding and acceptance remain unimplemented; no service restart, deployment, original experiment data or vector diagram changes.

## [Unreleased] — 2026-09-23 — [AI] completion audit and declared AR evidence outcomes

- Reverified 15 passive vector SVGs and all generated derivatives; no embedded raster or new Word/PDF.
- Added opt-in UC-03/UC-07 AR policies, all-recorded-attempt denominators, conservative uncertainty/coverage classification and conditional statistics; t4/t5 producers and causal acceptance remain unimplemented.
- Adjudicated static review46bbb5ff: constrained UC-07 FIM triggers, rejected v1/attempt-misplaced policies, retained exclusion diagnostics and exposed eligible-trigger/clock scopes. No weakening of ambiguous ownership or invariant guards.
- 39 new AR tests;680 total local regressions passed ondd87465. Final-head CI verified separately inPR28.
- Archived five official NIST/Wazuh sources with hashes; documented selected SSDF applicability without compliance claims. Updated partial literature review, writer guide, completion matrix and remaining local/native/human gates.

## [Unreleased] — 2026-09-23 — [AI] Markdown writer handoff and SVG diagrams

- Honored the owner's Markdown/SVG delivery requirement rather than generating another Word/PDF.
- Added 15 deterministic passive SVGs, editable JSON catalog, Mermaid derivatives, Arabic captions/index, writer guide, evidence matrix, logical data dictionary and reproducible allowlisted ZIP with assembled Markdown chapters.
- Corrected eight chapter diagrams against guarded Linux AR and actual JSON/OpenSearch storage; qualified unsupported claims about MITRE coverage, VT quotas, licensing, Filebeat, safety and universal confirmation.
- Adjudicated independent automated review bdb07323: guarded catalog, snapshot checks, staged per-file SVG publication, completed ZIP exclusive publication and explicit flow directions. No group-atomic or authenticity guarantees.
- Added36 regression tests;641 total and ALL CHECKS PASSED on3abb755. Native acceptance, t4/t5, UC-01/AR denominator, config protection, full reference audit and human academic review remain open.


## [Unreleased] — 2026-09-23 — [AI] pending recovery and traceable thesis review build

- Added offline, private, byte-pinned pending recovery with complete derived journals, duplicate preservation, no invented execution/timing, safe continuation export and original-file retention.
- Bound new pending intents to canonical manifest and exact journal path/prefix; retained explicit inner cancellation and bounded internal-fault diagnostics after independent source review.
- Added46 recovery regressions and one Unicode source integration regression. Added13 review-build tests and an actual43-page DOCX/PDF build with private runtime and source/tool/output receipts.
- Full local validator:605 tests on68d4e1e. Original data, native acceptance, t4/t5, UC-01/AR denominator and final academic formatting remain uncompleted; no deployment or model inference.

## [Unreleased] — 2026-09-22 — [AI] M2-A, transport and review follow-up

- Read-only prospective source observer with private byte snapshots, bounded reads, stable identity checks, explicit failure/left-censoring, offline export and frozen trial/path/spec/clock binding. Never fabricates t1/t4/t5 or AR causality.
- Reproduced and fixed trial launch cancellation (d632a2c), observer conflict scope and journal directory durability (67ae769), and source deadline-return descriptor leak (959deea; old implementation fails the regression).
- 545 local tests pass on e8aef17: 499 inherited +36 source +7 measurement +3 AI runner. CI is tracked per exact SHA in PR28.
- Documented inherited HTTP framing fix8e0916a and both completed independent automated reviews. Three review assumptions disproved by tests; remaining limits recorded instead of false fixes.
- Updated operating/recovery guidance and current handoff pointers. Pending recovery automation, t4/t5, UC-01/AR denominator, thesis pipeline and native/human acceptance remain open. No live model, original C4 or cloud deployment.

## [Unreleased] — 2026-09-22 — [AI] T-70 launch safety and evidence regressions

- Reproduced cancellation inside Popen/before assignment leaving a live unowned child and open stdout; fixed in bd67699 by deferring the first SIGINT/SIGTERM until assignment, then using existing group cleanup. No added signal mask inherited by workers and no preexec_fn.
- Made main-thread/exclusive signal-handler ownership explicit. Ignored signals remain ignored; default cancellation caught during launch becomes KeyboardInterrupt for cleanup. C4 and terminal-v2 schemas unchanged; code fingerprints still require the original revision to import older archives.
- Added13 tests: six launch/handler/mask tests and seven byte/source_record/batch/failure/recovery tests. Boundary faults are injected after durable artifact writes, not physical power-loss tests. Prose refusal remains rejected with full denominator, not inferred abstention.
- 72 runner / 482 total tests and validator pass locally on Python3.13.14. Push CI35779096256 for908432575d9eae6b4ab78cad5ea2deaba8437f4f passes3.12/3.13; job logs confirm482 tests each. Final documentation SHA/CI recorded in PR28 after push.
- Updated handoff/STATE/taskboard/issues/session log and UC-14 section14. No live model, HTTP service, original C4 data, independent human review, cloud changes or published-history rewrite.

All notable changes to this repository. Format: [Keep a Changelog](https://keepachangelog.com/). Dates are ISO-8601.

## [Unreleased] — 2026-09-18 — [AI] M1 review adjudication

- Completed source-only review adjudication in tests/README. Retained strict timing/cadence and default JSONL contract; added optional status summary rather than fabricating missing t3.
- Added late SIGALRM cleanup/draining, protected terminal finalization, allowlisted failure diagnostics, principal/explicit-CA fingerprints without password hashes, and supplied clock_ref consistency with manifest.
- Six additional observer tests plus one importer binding test;31 observer/127 measurement/469 total local tests pass. Updated current handoff: review is completed, next is M2 source/start/completion causality. Native acceptance remains open.

## [Unreleased] — 2026-09-18 — [AI] M1 visibility evidence and resumable plan

- Implemented private read-only HTTPS Indexer observer for a known selected t2 identity, prior-negative requirement, left-censored/no-observation/failure outcomes, fixed cadence, total POSIX request timer and byte-verified offline observer export.
- Added25 synthetic regressions including real timer interruption, TLS/query contract, private storage, tampering/failures and integration into existing trial_runner.collect. Verified pinned Wazuh keyword field mappings, not deployed mapping or native timings.
- Reproduced and fixed related trial worker kill-after-reap hazard using WNOWAIT, bounded cleanup and signal masking;3 additional regressions.462 full-suite local tests pass.
- Recorded whole-project dependency plan in ROADMAP section8, operating contracts in tests/README, and exact cross-session handoff/review task/next steps in CONTEXT_RESUME. Separate static review d21f2fcc remains pending adjudication at this checkpoint.
- No native Indexer calls, attacks, model inference, remote writes or original measured results. M2 source/start/completion causality and native gates remain open.

## [Unreleased] — 2026-09-18 — [AI] Verified reporting, parallel review and thesis drafts

- Added private offline JSON/Arabic RTL HTML C4 reporting with explicit hash-bound review input, missing/failure denominators, orphan warnings and16 regressions. No live model/network or raw records in HTML; source-byte verification is not authenticity or approval.
- Reproduced Telegram fork/flock inheritance and closed the child descriptor without unlocking the parent. Two real-worker regressions;434 total tests pass. Adjudicated all five static-review findings against code/pinned sources; OS-stuck cleanup/native acceptance remain limits.
- Integrated corrected Arabic chapters4/5 and updated chapter3 sampling, timing, statistics and ADR-014 scope. Exported a five-chapter Word/PDF review draft (43 pages); university formatting, rendered diagrams and original evaluation are not complete.
- Discovered Mesh/devices=[] without enrollment; three text-only parallel tasks completed and reviewed. Synthetic HTML browser capture and two PDF-page visual samples checked; no private evidence or secrets uploaded.
- Operational docs, taskboard, issues and handoff updated. Full native SOC and C4 acceptance remain open; no remote writes or messaging/lab probes performed.

## [Unreleased] — 2026-09-18 — [AI] SSH, SQLi and Telegram implementations

- Added bounded offline-preview/explicit-lab SSH and fixed SQLi signature clients, literal RFC1918 destinations, pinned SSH host files with no credentials/remote commands, per-client and total deadlines, and explicit non-acceptance outcomes.
- Added management-excluded firewall-drop XML generation (native rule IDs only, no OR-broadened filters or global AR disable) and optional file-based SSH input. Existing Apache input retained; documented31103/31104/31106 distinction from pinned Wazuh4.14.1 source.
- Added private opt-in Telegram helper and credential-free integration XML: minimal HMAC-pseudonymized messages, fixed TLS API/no proxies or redirects, bounded fork worker, durable private intent, uncertain-delivery/no-retry semantics, deduplication and hourly/lifetime caps.
- Corrected native Integrator ABI against4.14.1 C source, which appends debug/options/timeout/retries beyond the simplified prose documentation. Added17 scenario and33 notification tests;416 total local tests and full validator pass.
- Updated existing operational READMEs and T-12/13/14 state from planned to implemented/pending native acceptance. No SSH/HTTP lab probes, Telegram messages, firewall/config deployment or original measurement results performed by this session. No secrets committed; independent security/native review remains required before deployment.

## [Unreleased] — 2026-09-18 — [AI] Cloud operator evidence handoff

- Recorded Genspark Claw's migration to kali1-init with init, three persistent volumes and unless-stopped; preserved attribution for its crash/restart and two indexed canary reports.
- Independently checked replacement configuration, five live daemons, zero zombies and advancing agent/collector counters across65 seconds. Current key and archived key match the existing backup in memory; no key, key digest, raw logs or credentials published.
- Indexed byte sizes/SHA256 of nine private operator logs and DECISIONS.md; hashes identify snapshots, not signed authenticity. Originals remain on cloud host. Existing checkout updates PR28; no additional clone/credentials on host.
- Host reboot, individual-daemon recovery and current-state rollback remain unverified. Init alone does not supervise daemons; the old stopped container is not proof of safe rollback after replay-state advances. Updated ISSUE-064..066/068 and added verification gate081.
- Documentation-only work in this session; cloud operations were read-only. No remote mutation, reboot, new backup/canary, AI inference or PILOT by this assistant. Code baseline remains7de4a52 with366 tests; final validation evidence is recorded in PR28.

## [Unreleased] — 2026-09-18 — [AI] Runner review adjudication

- Completed adjudication of the separate static review of09e91e2; no reviewer tests/clone or human certification. Reproduced post-reap group signaling and cleanup timeout leaving stdout open on be5160c. Known unknown/orphan artifacts were already fixed; rejected silent drops, partial response acceptance and incorrect tracked-file/timeout claims.
- Linux waitid(WNOWAIT) now observes exit without reaping before group signaling; default SIGCHLD and exclusive child reaping required. First cancellation during cleanup is deferred; bounded cleanup failure is recorded and stdout closes. Not a guarantee against SIGKILL, D-state or external reapers.
- Added terminal schema v2 with allowlisted validation_code and import-time recomputation; arbitrary exception text never enters metadata. Whole-batch validation and C4 denominator semantics unchanged; old evidence requires original code revision.
- 13 additional runner regressions; 59 runner /366 total local tests and validator pass at2e316e3. Exact final-head CI linked in PR28. No live transport, HTTP service, model, cloud operation or original C4 results.

## [Unreleased] — 2026-09-18 — [AI] Durable AI evidence runner

- Added offline prepare/export and explicit-opt-in batch execution; immutable-by-convention private snapshots, exclusive directory lock, file/directory fsync before worker launch, frozen manifest and one attempt per batch.
- Byte/hash reconstruction and response-to-C4 projection; corrupt/partial/unknown entries fail closed, intact interrupted intent remains failed/untimed, orphan output is explicitly unverified, missing batches remain in denominator.
- Bounded isolated worker environment/stdout and monotonic invocation deadline; tested real SIGINT/SIGTERM with synthetic descendants. No live Ollama, model download, HTTP service or cloud changes. Parent SIGKILL/power loss require external supervision; Ollama computation is not killed or attested.
- 46 runner tests; 353 full-suite tests and ALL CHECKS PASSED at5423a6f. Separate automated read-only review of09e91e2 and final-head CI are tracked on PR28, not implied by submission or historical CI.
- Documented exact CLI, model-descriptor (not runtime-weight) hashes, latency scope, reconstruction/version retention, private storage and original human C4 acceptance gates. T-70 remains IN-PROGRESS. Only this implementation session abovebf2fab0 is eligible for consolidation.

## [Unreleased] — 2026-09-18 — [AI] Evidence-based audit and remediation

### Fixed
- C4 rejects duplicate declared `(input_sha256, alert_ref)` observations under renamed batches; shared source exports suppress Wilson even with distinct cluster/batch labels. Reports source count. Four regressions; source declarations are still not authenticated artifacts.
- Ollama catches `http.client.HTTPException` and keeps CLI failures generic with no partial stdout. Two regressions cover open/read protocol errors and CLI privacy.

### Verified and planned
- Reproduced 301-test baseline at4f62a15 and 307 passing tests after fixes (48 analyst,19 knowledge,28 evaluation,67 lifecycle,145 previous). New regressions also detect old source in memory.
- Completed a separate read-only automated review and independently adjudicated its claims; rejected incorrect BOM/default-parser and temperature-zero determinism claims. Not a human review or final-head approval.
- Reconciled delivery roadmap with ADR-014, PILOT5/planned_n>=30/baseline12h and active CI; explicit native recovery and AI artifact/journal/deadline gates. Dated official-source references with reading limits; no compliance certification.
- Added audit coverage and accepted/rejected findings, ISSUE-074..078, current resume/state and UC-14 contract updates. XML-declaration compatibility and malformed internal Python-context contracts remain low-priority open items.
- No cloud access/mutation, live inference, original C4/PILOT, source-document modification or final project acceptance. Only this session's commits are eligible for consolidation above4f62a15; collaborator history is preserved. Final-head CI evidence belongs in PR28 comments.

## [Unreleased] — 2026-09-11 — [AI] Pinned knowledge and offline C4 evaluator

### Implemented and published
- `01f3f94`: official MITRE ATT&CK Enterprise v19.2 subset (T1059/T1204.002/T1571), pinned upstream commit, verified Git blob/source SHA256, retained descriptions and full license.
- `db1eab9`: exact retrieval, bounded explicit excerpts, source/rule digests, curated semantic caveats only for reviewed XML hash, optional hash-approved <=24h inventory contract without raw identity/source fields.19 new tests;277 total at this checkpoint.
- `120efba`: bounded offline three-file C4 evaluator; stable case/batch refs, frozen declared provenance, complete planned denominators, explicit missing/failed/rejected/abstained cases, classification/MITRE metrics, human-adjudicated unsupported claims, per-status latency and conditional Wilson.23 synthetic tests;300 total at this checkpoint.
- `5744011`: self-review fix suppresses Wilson for shared inference batches even with distinct cluster labels; regression added. **301 total local tests PASS**, validator and diff check clean. No independent review claimed.
- Updated Arabic UC-14 operating contracts, executable synthetic demonstration, source-update procedure, next-agent resume/state/task/session/issue records. PR28 remains open for review; final documentation-head CI evidence is recorded there after publication.

### Not implemented or accepted
- No real model inference, private live inventory, independent human-labelled dataset or real C4 results. Evaluator consumes normalized records, not an automatically audited analyst-artifact import; hashes/declarations are not proof of artifact contents, timing or reviewer identity. Durable importer/runner and hard wall-clock deadline are next.
- No cloud mutation, lifecycle native deployment/restore/canary/PILOT, autonomous AI execution or final academic results. T-70 and ISSUE-070/071/073 remain open. ISSUE-072 shared-batch interval handling fixed in repository only.
- Published history preserved with fast-forward checkpoints; no force-push, saved PAT or global Git credential changes. Commit attribution metadata is distinct from the verified MoTechSys push account; commits are not cryptographically signed.

## [Unreleased] — 2026-09-11 — [AI] T-70 advisory analyst core

### Added
- Offline-first `ai_agent/analyst.py`: bounded strict JSONL, level7 filtering, conflict-aware deduplication, batch-local identity/IP pseudonyms, exclusion of raw logs/free text/URLs and source-record tracing.
- Exact repository-rule structural retrieval and explicit missing-rule reporting; bounded same-manager/agent temporal candidates (not causality). Strict evidence/MITRE/output validation, complete nonduplicated alert coverage and no execution authority.
- Optional provider-neutral callable interface and explicit local Ollama adapter: literal loopback, no proxies/redirects/tool calls or model download; bounded payload/response and socket timeout. No external LLM adapter or live inference.
-46 synthetic regressions,258 total local tests passed. Validator now syntax-checks ai_agent. Added UC-14 operating contract and privacy/acceptance limits.

### Self-review fixes and limits
- Reproduced shared context mutation in7033616;5da888b copies validation evidence separately from provider input, rejects repeated findings and preserves selected source-record indices. Python provider code remains trusted, not sandboxed.
- Advisor call was unavailable for this sandbox type; no independent review claimed.
- Full pinned MITRE/inventory RAG, real-model quality/latency/privacy tests, approval UI/integration and C4 on30 independently human-labelled alerts remain open. Reference validity is not semantic grounding. No cloud mutation or whole-project completion.
- Reconciled explicit AI-future-only statements with already accepted ADR-014 without changing the approved scope. Historical source/measurement claims are not treated as new evidence.

## [Unreleased] — 2026-09-11 — [AI] Published revision and verified CI evidence

- Fast-forward push of `095cd869f08a23d88f7ed3d9d434db816c04fb37` succeeded and PR #28 was updated; remote PR head matched. Git configuration was unchanged and no credentials were persisted.
- [PR run](https://github.com/MoTechSys/my-bro/actions/runs/34598831817) and [push run](https://github.com/MoTechSys/my-bro/actions/runs/34598830852) both succeeded on Python 3.12 and 3.13. Direct PR log inspection confirmed all212 tests and the validator passed in each job.
- Closed T-40/ISSUE-038 for the verified revision, preserving the earlier permission rejection as history. Later commits need their own runs; final head checks are linked on PR #28.
- No cloud deployment, service restart, rollback, canary, PILOT, or native acceptance was performed.

## [Unreleased] — 2026-09-11 — [AI] Authorized synchronization and CI activation

- Verified the user-authorized temporary credential belongs to MoTechSys and has repository push and workflow scope; no credential written to project files or Git configuration.
- Fetched main and development refs before synchronization; no collaborator changes observed. Consolidation is limited to unpublished commits, preserving the published branch history and local recovery references.
- Moved the reviewed Python 3.12/3.13 workflow into `.github/workflows/validate.yml` after verifying repository Actions policy and upstream action pins. Least privilege, no checkout credential persistence, concurrency and timeouts retained.
- PR #28 and the session log carry the actual push/run outcome. The workflow-file change alone does not close T-40; both matrix jobs must succeed. Cloud deployment and ISSUE-068 remain unresolved.
- Earlier local checkpoint IDs (including e40990f and330c76f) in the append-only history identify pre-consolidation work, not necessarily a published commit. The PR head identifies the submitted revision.

## [Unreleased] — 2026-09-11 — [AI] Cloud handoff review (checkpoint before authentication restoration)

### Fixed and verified
- Reproduced the stale progress verdict forcing exit at simulated75s after recovery; adapted the cloud operator's fix to count each completed window once. Healthy windows reset the progress counter independently of per-poll daemon health.
- Added eight regressions including recovered/sustained stalls, counter resets, explicit thresholds, daemon failures, config-integrity enforcement and shutdown requested during a mocked start timeout. All212 local tests and the validator pass.
- Inspected the operator's actual patch in memory: one test errors because `mock` is not imported. Did not import that broken test or the proposed config-existence-only relaxation.
- Independently checked cloud backup archive indexes, full gzip stream integrity, current-versus-archived identity equality without disclosure, and backup-image existence. No restore or remote service mutation.

### Open boundaries
- Retained the protected-config trust boundary. The actual agent config and parent permissions fail it; ISSUE-068 requires a compatible, reviewed deployment layout rather than silently weakening the check.
- Public fetch confirms PR28 still at480384e. The configured gh account is not the agreed MoTechSys identity; no authenticated repository writes or published-history rewrite. Changes remain local until correct-account synchronization.
- The sandbox write boundary still excludes the cloud host. Native deployment, storage migration, recovery, rollback, canary and PILOT remain pending.

## [Unreleased] — 2026-09-11 — [AI] Tested lifecycle candidate (PR #28)

### Added
- `scripts/lab/agent_health.py`: read-only, bounded process/state health and two-snapshot collection-progress checks; explicit state timezone, no secret reads, no end-to-end approval claim.
- `scripts/lab/agent_lifecycle.py`: opt-in prepared-container supervisor with init/root/protected-install guards, fixed service commands, bounded startup/shutdown, signal handling and exit on sustained health or progress failure.
- `tests/test_agent_lifecycle.py`: 59 synthetic tests covering parsers, zombies versus live services, stale clocks/state, duplicate processes, stalled counters, startup guards, permissions, interrupted starts and reverse cleanup.

### Changed and verified
- `validate_all.sh` now requires the unittest suite to pass, with a 180-second timeout and rejection of empty discovery. All 204 local tests pass (145 existing plus 59 added).
- Executed the health script itself through stdin inside live kali1: expected exit1 with healthy=false, progress_verified=true and explicit PID1/zombie reasons. No remote file installation, service mutation or active attack.
- Prepared a pinned, read-only-permission CI matrix for Python 3.12/3.13. GitHub App explicitly denied workflow activation; the candidate remains in workflows-pending. CI execution is not claimed.
- Added official Docker/Wazuh references, deployment/rollback prerequisites and precise runtime acceptance limits. T-62 remains incomplete for native deployment, recovery and independent review; T-11/T-15/T-60 are not closed.

## [Unreleased] — 2026-09-11 — [AI] Cloud audit (PR #28)

### Verified
- Connected to the authorized cloud host using pinned SSH host keys, with credentials kept outside tracked files and entirely inside the sandbox workspace.
- Observed 19 zombie processes alongside five live Wazuh services in kali1. Two passive snapshots showed increasing agent, collector and manager counters; a complete collection outage was not established.
- Confirmed PID 1 is tail, Docker init/healthcheck are absent, restart policy is no, and mounts are empty. The endpoint image is Ubuntu 24.04.4, despite its kali1 name. Hardened AR and YARA artifacts are absent at their deployment paths.
- Re-ran 145 local unittest cases successfully and passed validate_all.sh on code baseline e51dd7d; these are not native SOC experiment results.

### Documented
- Updated CLOUD_ENV_ACCESS section 9 with dated observations, limits, reproducible evidence references and a state-preserving lifecycle recovery plan; historical pilot commands are explicitly gated.
- Updated current state, task ownership and session handoff; opened ISSUE-064 through ISSUE-066.
- No remote mutation, container recreation, canary, PILOT, attack, or write to the remote decision log. The session write boundary permits only /home/user/webapp; an appropriately scoped execution session must perform recovery before live experiments. No claim of completed T-11, T-15 or T-60.

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

## [0.2.0] — 2026-09-09
### Added
- `docs/05_PROJECT_INTENT_UNIFIED_VISION.md` — تشخيص "أربعة مشاريع في رأس واحد"، النية الموحَّدة، العنوان المعتمد، النموذج الذهني الستّي، الإضافة العلمية، مصفوفة MoSCoW، محاور التعميق، قرارات افتراضية بدل Q1–Q4/Q6/Q7، أجوبة اللجنة.
### Changed
- `AI_AGENT_START_HERE.md` — الوثيقة 05 أصبحت المرجع الأعلى (ترتيب القراءة #2).
- `docs/00_PROJECT_STATE.md` — المهمة التالية.

## [0.3.0] — 2026-09-09
### Added
- `COLLABORATION_PROTOCOL.md` — بروتوكول تعاون وكلاء متعددين (Claude + GPT-6 Astra): فروع `agent/<name>`، دورة الجلسة، خريطة الملكية، حل التعارضات.
- `docs/TASKBOARD.md` — لوحة مهام مشتركة بالحجز (T-01…T-40).
- `docs/SESSIONS_LOG.md` — سجل جلسات append-only مع رسائل بين الوكلاء.
- `docs/prompts/ASTRA_ONBOARDING_PROMPT.md` — برومبت تهيئة Astra.
### Changed
- `AI_AGENT_START_HERE.md` — إضافة 1b/1c في ترتيب القراءة، فروع `agent/<me>`.

## [0.3.1] — 2026-09-09
### Fixed
- ISSUE-033: نموذج الفروع v2 — فرع مشترك `genspark_ai_developer` + بادئة `[AGENT]` + `--force-with-lease` (البيئة تفرض اسم الفرع على كل الوكلاء).
### Added
- ISSUE-032 (حدود الإثبات) وتصحيح T-10 — من مراجعة Astra.

## [Unreleased] — 2026-09-09 — [ASTRA] T-10 (PR #6)
### Added
- `tests/TEST_PLAN.md`: بروتوكولات UC-01..08، عشر محاولات لكل سيناريو ونظام مشمول، ساعة baseline، عقد سجل المحاولات والربط بالأدلة، مقاييس الكشف والاستجابة والإنذارات الكاذبة، وضوابط السلامة والكبت.
- مقترحات ISSUE-034..037: مصادر الوقت ومقام المحاولات، تكرار معرف ISSUE-032، مراجعة سلامة الحذف وتوجيه AR، ودقة شرح ignore=900.
### Validation and handoff
- نجحت فحوص IDs وBash/Python وXML بعد تحييد placeholders وCDB وروابط الخطة؛ لا تشغيل Wazuh/Windows/YARA أو قياس أداء في المعمل.
- T-10 مكتملة توثيقياً؛ ISSUE-019 مفتوح. T-11 يحتاج سجل المحاولات وأدلة المصدر مع alerts.json، وT-15 مطلوب قبل اختبار الحذف الآلي. لا تغيير في ملفات `wazuh/` أو مهام Claude.

## [0.4.0] — 2026-09-09
### Added
- `docs/thesis/ch2_literature_review.md` — الفصل الثاني كاملاً (T-20، CLAUDE): SOC، SIEM، Wazuh، NIDS (Suricata vs Zeek)، FIM، YARA/VirusTotal، Active Response، MITRE ATT&CK، الهجمات المُحاكاة، مقارنة الحلول، الدراسات السابقة، الفجوة البحثية؛ 15 مرجعاً IEEE مُتحقَّقاً.
- `tests/TEST_PLAN.md` — خطة الاختبار المُقاس (T-10، ASTRA) — PR #6.
### Fixed
- ISSUE-035: إعادة ترقيم بند CI إلى ISSUE-038.
- ISSUE-037: تصحيح دلالة `ignore="900"` في runbook UC-08 (كبت القاعدة لا العملية).

## [0.5.0] — 2026-09-09
### Added
- `docs/thesis/ch3_methodology.md` — الفصل الثالث كاملاً (T-21، CLAUDE): منهجية البحث، المتطلبات، المعمارية، الطبقات المُصحَّحة، DFD ثلاثة مستويات، حالات الاستخدام وتسلسل الاستجابة، سجل IDs، المعمل، قابلية التوسع، منهجية التقييم.

## [0.6.0] — 2026-09-09
### Added
- `docs/AGENT_CAPABILITIES_AND_ALLOCATION.md` — مصفوفة القوة (منشور + ملاحَظ)، القيود، التوزيع النهائي (Astra: كل التنفيذ على النظام؛ Claude: العقل والسرد)، قاعدة Zero-Skip، هندسة السياق الإلزامية، تدقيق دوري.
- TASKBOARD: T-32 (front matter)، T-33 (مراجعة ch4/ch5).
### Changed
- `docs/00_PROJECT_STATE.md` — أُعيد بناؤه بالكامل (كان راكداً عند Session 01): نسب الإنجاز، المهمة التالية لكل وكيل، سجل الجلسات 01–07.
- `docs/thesis/README.md` — ch2/ch3 ✅.
- `AI_AGENT_START_HERE.md`, `COLLABORATION_PROTOCOL.md` — إحالة لملف القدرات.
### Removed
- `docs/05_PROJECT_INTENT.md` — نسخة قديمة مكررة (المرجع الوحيد: `05_PROJECT_INTENT_UNIFIED_VISION.md`).

## [0.7.0] — 2026-09-09
### Added
- `docs/thesis/ch1_introduction.md` — الفصل 1 v2 (T-24، CLAUDE): نص S4 حرفياً + 9 تصحيحات موثَّقة (§1.8): OVA بدل Ubuntu، Win10 بدل Win11، Wazuh Indexer/Dashboard بدل ELK، حذف Zeek، إضافة Suricata/auditd/YARA/VirusTotal/Apache بالإصدارات، هدف الاستجابة الآلية، نطاق أدق، Out-of-Scope للأعمال المستقبلية.
### Changed
- ISSUE-001/002/003/015/027 → FIXED-IN-REPO على مستوى الرسالة.

## [0.8.0-rc.1] — 2026-09-09 — [ASTRA] T-15 / PR #14 (pending review)
### Added
- `tests/SECURITY_REVIEW.md`: inventory of every AR/lab/validation script, deployment contract, residual race/ACL risks and native acceptance gates.
- Linux/Windows guarded response engines and 19 synthetic security regression tests in `tests/test_security.py`.
### Changed
- One local AR dispatch to an OS-native `remove-threat.exe`; Linux installs the shebang wrapper under that basename with `soc_ar.py`, Windows builds the native executable.
- Lab scripts require explicit opt-in; network targets are constrained, downloads checksum-gated, policy/rules backed up, and builds run unprivileged.
### Fixed
- Deletion outside add, missing path/hash checks, unbounded protocol waits, Windows JSON shell interpolation/shared stdin file, validator predictable temporary files, and truncated YARA paths.
### Validation / remaining work
- 19 local tests and `validate_all.sh` pass. No live Wazuh, Windows, YARA, installer or malware download tests performed.
- T-15 remains IN-PROGRESS and ISSUE-036 is not closed. Independent Claude review is required before merging PR #14; native/ACL/race gates remain documented. T-11 has not started.

## [0.8.1] — 2026-09-09 — ASTRA takeover consistency
### Changed
- Merged #17 handoff then #14 security after rebase and 19 passing tests; preserved both author histories.
- Replaced unsafe session reset advice with ancestry-aware single-development-branch workflow.
- Reconciled roadmap, source/evidence gates, demo CLI/timing/rule IDs and Linux/helper/Windows deployment notes (R1/R3).
- Added takeover coverage ledger and execution plan; retained native/lab blockers and original source archive.

## [0.9.0-rc.1] — 2026-09-09 — T-11 detection core (incomplete task)
### Added
- Offline `scripts/measure/mttd.py`: strict JSONL/run manifest, exact correlation, rotation deduplication, explicit misses/late/excluded/ambiguous trials, source/action timing, separate integration latency, bounded resources and input hashes.
- 33 synthetic measurement regressions; 52 total local tests including security. Contract in tests/README.md.
### Pending
- Source evidence adapters, multi-stage AR/visibility/UC-01 metrics, baseline adjudication/FP-hour, independent review and lab acceptance. T-11 remains IN-PROGRESS, not a final measurement product.

- Core follow-up: separate scan match_start from deadline anchor to count alerts during the scan. Latest local total: 34 measurement + 19 security = 53 tests.

## [0.9.1-study] — 2026-09-09 — T-17 / PR #22
### Added
- Primary-source intent study, proposed as-is/target/response diagrams, device/mobile coverage distinctions, source references, all 13 FR and 8 NFR mapped, decision and delivery gates.
- ADR-013 proposed, ISSUE-047..049, explicit direct-reading and machine-analysis limits.
### Corrected
- Model allocation based on official Anthropic/OpenAI announcements; Fable pricing and Astra Terminal-Bench figure corrected, incomparable benchmarks and production safeguards qualified.
- Study-first state/roadmap and source audit ledger; existing scope is not treated as the brother's own final decision.
### Limits
- No runtime changes, no scope approval, no new lab results; T-11/T-15/T-16 incomplete. T-17 study awaits owner confirmation and independent review.


## 2026-09-09 — T-11 v3 measurement candidate (PR #24)

### Added / changed
- Explicit v2 attempt contract: seven t0..t6 fields plus UC-03 t2_prime, device-minus-UTC offsets and whole-session invalidation; historical v1 retained separately.
- Eight exact timeline metrics plus D_VT; stdlib type7 summaries, Wilson 95%, exact Poisson upper limit, one-sided Mann–Whitney U and sample_size planning.
- Baseline exposure union/adjudication and H4 independent-group reporting, without unsupported non-inferiority conclusions.
- Guarded trial_runner.sh/Python backend: --lab/replay, durable pre-launch t0, bounded JSON/audit/Apache and observer imports, no shell, timeouts, append locking and failed-attempt retention.
- TEST_PLAN/README contract reconciliation and ISSUE-050..057; raw confirmation, cross-role alert ownership, fixed stage protocol and session guard regressions.

### Validation / limits
- 130 local tests (111 measurement/runner +19 security), validate_all and diff checks pass. No native Wazuh/Windows/YARA acceptance or real SOC attack/PILOT. Source archives and AR/security runtime unchanged.
- T-11 remains IN-PROGRESS: reviewed native observers/clock/causality evidence, UC-01, full AR success denominator, independent statistical/technical review and laboratory PILOT still required.


## 2026-09-09 — v3.1 corrections before PR #24 merge

- Restored repository authentication; pushed saved12c95b5 without using the exposed user token. Preserved incoming CLAUDE v3.1 ancestry through PR25; issue-ID crosswalk retained (EICAR060, timestamp061).
- Raised sample_size and every UC planned_n floor to30; baseline target/warning to12h per OS/config. Exact Poisson estimator retained; helper approximations labeled.
- Added unique validated EICAR filenames and runner --eicar-dir with deterministic session/run/trial identity and exact source/FIM/VT selectors, durable pre-launch path/argv, exclusive/no-follow creation.
- Added read-only --inspect-alert-timestamps and made native precision review the first G2 step before PILOT; serialized decimals are not native accuracy proof.
- Updated TEST_PLAN, README, runbook/demo/security interfaces, TASKBOARD and session handoff. 145 local tests (123 measurement/runner +22 security); no real EICAR creation, SOC attack, native acceptance or PILOT. T-11 stays IN-PROGRESS.
