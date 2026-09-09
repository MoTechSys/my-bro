#!/bin/bash
# Purpose: checksum-gated YARA lab build; owner [ASTRA]; updated 2026-09-09.
# Status: syntax reviewed; build/native validation pending. Source: UC-07 / YARA 4.5.5.
# Hashes must be independently verified by the lab operator, not taken from this download.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && $# == 3 ]] || { echo 'Usage: install_yara_kali.sh --lab SOURCE_SHA256 RULES_SHA256' >&2; exit 2; }
SOURCE_HASH=$2
RULES_HASH=$3
[[ $SOURCE_HASH =~ ^[a-fA-F0-9]{64}$ && $RULES_HASH =~ ^[a-fA-F0-9]{64}$ ]] || exit 2
[[ $EUID != 0 ]] || { echo 'Build as an unprivileged lab user, not root' >&2; exit 2; }
getent group wazuh >/dev/null || { echo 'Install Wazuh agent first' >&2; exit 2; }
umask 077
WORK=$(mktemp -d "$PWD/.yara-build.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
sudo apt update
sudo apt install -y make gcc autoconf automake libtool libssl-dev pkg-config jq curl python3
curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 120 \
  https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz -o "$WORK/yara.tar.gz"
printf '%s  %s\n' "$SOURCE_HASH" "$WORK/yara.tar.gz" | sha256sum --check --status
python3 - "$WORK" <<'PY'
import pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
with tarfile.open(root / 'yara.tar.gz') as archive:
    for m in archive.getmembers():
        p = pathlib.PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts or not (m.isdir() or m.isfile()):
            raise SystemExit('Unsafe archive member')
    archive.extractall(root)
PY
cd "$WORK/yara-4.5.5"
./bootstrap.sh
./configure
make -j2
make check
# Download rules unprivileged, before installing either artifact.
curl --fail --proto '=https' --connect-timeout 10 --max-time 120 \
  https://valhalla.nextron-systems.com/api/v1/get \
  --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
  -o "$WORK/yara_rules.yar"
printf '%s  %s\n' "$RULES_HASH" "$WORK/yara_rules.yar" | sha256sum --check --status
./yarac "$WORK/yara_rules.yar" "$WORK/compiled.rules"
sudo make install
sudo ldconfig
RULES_DIR=/var/ossec/etc/yara/rules
for p in /var/ossec /var/ossec/etc /var/ossec/etc/yara "$RULES_DIR"; do
  if sudo test -L "$p"; then echo "Refusing symlink: $p" >&2; exit 1; fi
done
sudo install -d -o root -g wazuh -m 750 "$RULES_DIR"
if sudo test -e "$RULES_DIR/yara_rules.yar"; then
  BACKUP=$(sudo mktemp "$RULES_DIR/yara.backup.XXXXXX")
  sudo cp --preserve=mode,ownership,timestamps "$RULES_DIR/yara_rules.yar" "$BACKUP"
  echo "Old rules: $BACKUP"
fi
sudo install -o root -g wazuh -m 640 "$WORK/yara_rules.yar" "$RULES_DIR/yara_rules.yar"
/usr/local/bin/yara --version
echo 'Deploy yara.sh AND soc_ar.py; verify monitored directories separately. No live detection claim.'
