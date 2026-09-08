#!/bin/bash
# UC-03: drop an EICAR test file into the VirusTotal-monitored dir (harmless AV test string).
# Source: S2 p.18.  Expected: rule 87105 (VT positive) -> AR remove-threat -> rule 100092 in dashboard.
DIR="${1:-/home/kali/SOCfile}"
mkdir -p "$DIR"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$DIR/eicar.com"
echo "EICAR written to $DIR/eicar.com — check dashboard: rule.id: is one of 553,100092,87105,100201"
