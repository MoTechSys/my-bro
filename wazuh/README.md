# `wazuh/` — Clean, corrected, deployable configuration

This directory combines source-derived lab configurations with newly authored T-15 hardening (#14). Local tests are not native deployment acceptance. Follow tests/SECURITY_REVIEW.md for gates, backup and rollback; never copy all files blindly.

```
wazuh/
├── manager/
│   ├── rules/local_rules.xml          -> /var/ossec/etc/rules/local_rules.xml
│   ├── decoders/local_decoder.xml     -> /var/ossec/etc/decoders/local_decoder.xml
│   ├── lists/suspicious-programs      -> /var/ossec/etc/lists/suspicious-programs
│   ├── lists/audit-keys               (reference; shipped with Wazuh)
│   └── ossec.conf.d/*.xml             snippets to merge into /var/ossec/etc/ossec.conf
├── agents/
│   ├── linux/ossec.conf.d/*.xml       snippets for kali1 /var/ossec/etc/ossec.conf
│   ├── linux/active-response/*.sh     -> /var/ossec/active-response/bin/  (root:wazuh 750)
│   ├── windows/ossec.conf.d/*.xml     snippets for win1 ossec.conf
│   └── windows/active-response/       yara.bat, remove-threat.py (-> .exe via PyInstaller)
├── suricata/suricata.yaml.patch.md
└── auditd/wazuh.rules
```

## Linux and Windows deployment contract
Linux: install remove-threat.sh as /var/ossec/active-response/bin/remove-threat.exe, with soc_ar.py beside it; install yara.sh with that same helper. All root:wazuh 0750 in protected parents. Never copy the Windows binary to Linux. Windows needs verified allowlists, native PyInstaller builds and ACL testing. The manager uses one local remove-threat dispatch; current VT integration does not automatically cover Windows. See docs/lab/UC-03 and UC-07.

## Apply order (manager)
1. `lists/suspicious-programs` → then add `<list>` line (`ossec.conf.d/10-*`).
2. `decoders/local_decoder.xml`
3. `rules/local_rules.xml`
4. Merge `ossec.conf.d/20-*`, `30-*`, `40-*` into `<ossec_config>` (set the VirusTotal key).
5. `sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager`

## Validate before commit
```bash
bash scripts/validate/validate_all.sh
```

## Rule-ID namespace
See `docs/02_ARCHITECTURE.md §5`. Reserved for extensions: 100400–100499 (network/syslog), 100500–100599 (AI/reporting).


## UC-10: private Telegram notifications — implementation, native acceptance pending

Files: `manager/integrations/custom-telegram.py` and `manager/ossec.conf.d/60-integration-telegram.xml`. No autonomous response or approval. Linux Python3 stdlib only. The helper reads one bounded JSON alert (4MiB), filters level>=12, and sends only rule ID/level, UTC time and keyed event/agent references. Raw log, description, names, source IP, usernames and file paths are excluded. HMAC references are pseudonyms, not a guarantee of anonymity; timing/rule metadata may still identify incidents. Approve the external disclosure policy first.

### Private configuration (never in Git, XML or process arguments)

On the authorized manager, install the script as `/var/ossec/integrations/custom-telegram.py`, root:wazuh0750, with a verified `/usr/bin/python3`. Use a dedicated root-owned0700 `/etc/soc-telegram/` and `/var/lib/soc-telegram/`; ancestors must not be group/other writable or symlinks. Config is `/etc/soc-telegram/config.json`, root0600, regular and single-link. Store stays root0700. If Integrator runs under another UID, explicitly review ownership/isolation rather than relaxing private permissions. The code does not chmod/chown existing Wazuh trees.

Configuration contract (placeholders intentionally invalid until replaced privately):

```json
{
  "schema_version": 1,
  "enabled": false,
  "bot_token": "PRIVATE_BOT_TOKEN",
  "chat_id": "PRIVATE_NUMERIC_CHAT_ID",
  "hmac_key": "64_LOWERCASE_HEX_FROM_32_RANDOM_BYTES",
  "min_level": 12,
  "max_per_hour": 10,
  "max_total_attempts": 1000
}
```

`enabled` must be boolean; min_level12..16, hourly1..60, lifetime1..1000. Obtain the token privately from BotFather, approve the numeric private chat/group destination, and generate a random32-byte HMAC key via a trusted local secret manager (`secrets.token_hex(32)` is suitable; do not paste its output in chat/Git). Do not reuse the synthetic test values. No real token is provided or requested in this repository.

Preview, without network or store writes:

```bash
python3 -I -B wazuh/manager/integrations/custom-telegram.py \
  --alert /approved/private/one-alert.json \
  --config /approved/private/config.json
```

`--send` plus `enabled=true` are both required for manual delivery. The native Wazuh entrypoint is invoked via positional arguments, so `enabled=true` is the explicit deployment opt-in there. Merge only the60-integration-telegram.xml block after preview and native installation validation. Do not add api_key/hook_url/options: the native Integrator passes these on argv, and this helper deliberately rejects them. Rule levels5712/5763=10 and31103=7 are **below this notification threshold**; they will not notify by default. Do not raise rule severity just to force a test.

### Delivery and failure semantics

- Fixed `https://api.telegram.org/.../sendMessage` API, default TLS certificate/hostname verification, no proxies or redirects. No arbitrary endpoint. No Markdown/HTML parse_mode; link previews disabled and protect_content requested (not a screenshot-prevention guarantee).
- Worker receives token/config in memory, not subprocess argv; child environment/stdin/stdout/stderr are stripped. Socket timeout5s plus a10s parent process deadline/alarm, bounded16KiB acknowledgement. CLI signal cancellation cleans up its child where possible; OS scheduling/D-state/SIGKILL are not hard-real-time guarantees. Fork requires this trusted single-thread CLI; not a plugin sandbox.
- `sent` requires Telegram ok=true, positive message_id and matchingchat; it confirms API acceptance, not a human reading the message. Failure/timeout is `unknown` because delivery may have occurred before losing the acknowledgement. **No automatic retry.** The integration never guesses delivery from HTTP200 alone.
- Private store uses directory flock, exclusive0600 records and file+directoryfsync. HMAC event identity (manager,agent,id) is reserved durably before networking; duplicate or interrupted intents never resend. Same identity with altered content fails closed. This is at-most-one application attempt per retained identity, not distributed exactly-once delivery or signed evidence.
- Hourly and lifetime caps count attempts including unknown outcomes. At capacity the helper returnsrate_limited, not success. No silent pruning. Operator rotation/archive is explicit and must preserve duplicate policy; deleting state/changing HMAC key can enable repeat sends. Queue/failure counters are not a C4 evidence dataset. Low-level filtered/rate-limited/lock failures do not create unbounded records.
- Partial/corrupt/unexpected files, symlink/hardlink/public mode, backward time relative to recorded intent, or disk failure refuse delivery. Same-UID malicious modification, ACLs and clock forward jumps remain operator risks. First deploy with a small cap; monitor Wazuh integration errors and filesystem capacity.
- Outputs contain sanitized statuses. Exit0=preview/filtered/duplicate/sent, exit2=unknown/rate_limited, exit1=invalid input/config/storage, exit130=CLI cancellation. Never treat exit0 alone as successful delivery. `delivery_confirmed` is true only for the current acknowledged send.

### Native ABI, testing and rollback

Pinned Wazuh4.14.1 Integrator adds debug/options/timeout/retries after alert/key/hook and may leave literal redirection argv fields. The helper supports the restricted empty-key/empty-hook/empty-options form and ignores native retry advice in favour of its no-retry policy; no shell evaluation. Synthetic ABI tests are not proof of deployment on every Wazuh version.

Acceptance: validate the merged manager configuration in its native environment, preview a private high-level test alert, then send one explicitly approved notification to a private test chat. Check both Telegram receipt and the private intent/terminal record. Reinvoke the same alert and verify no duplicate. Test denied transport/timeout/rate-limit/storage permissions without affecting manager collection. No external message was sent during repository tests. Disabling: setenabled=false privately and remove only thisintegrationblock through the normal change window; retain records for duplicate/audit policy. Do not revoke/delete unrelated credentials or alter VT/YARA.

References consulted2026-09-18:
- [Wazuh external integration guide](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html).
- [Exact4.14.1 command construction](https://github.com/wazuh/wazuh/blob/v4.14.1/src/os_integrator/integrator.c), especially Integrator argv construction aroundlines431–447. Actual code adds fields beyond the simplified guide.
- [Telegram Bot API](https://core.telegram.org/bots/api#sendmessage): HTTPS requests, JSON responses/ok flag and sendMessage. No claim of reviewing the entire API document.

SSH/SQLi execution and guarded firewall-drop generation are documented in [attack-emulation README](../scripts/attack-emulation/README.md); the optionalSSHfilecollector is `agents/linux/ossec.conf.d/60-localfile-sshd.xml`. Do not blindly apply all snippets.
