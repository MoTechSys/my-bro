#!/bin/bash
# UC-07: build YARA 4.5.5 from source on Kali/Ubuntu and place rules OUTSIDE /tmp (ISSUE-020).
# Source: S2 pp.40-42, S5 img20-22
set -e
sudo apt update
sudo apt install -y make gcc autoconf libtool libssl-dev pkg-config jq
cd /tmp && curl -LO https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz
sudo tar -xvzf v4.5.5.tar.gz -C /usr/local/bin/ && rm -f v4.5.5.tar.gz
cd /usr/local/bin/yara-4.5.5/
sudo ./bootstrap.sh && sudo ./configure && sudo make && sudo make install && sudo make check
# fix "libyara.so.9: cannot open shared object file" (S2 p.41)
echo "/usr/local/lib" | sudo tee -a /etc/ld.so.conf >/dev/null && sudo ldconfig
yara --version

RULES_DIR=/var/ossec/etc/yara/rules
sudo mkdir -p "$RULES_DIR" /tmp/yara/malware
sudo curl 'https://valhalla.nextron-systems.com/api/v1/get' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' --compressed \
  -H 'Referer: https://valhalla.nextron-systems.com/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
  --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
  -o "$RULES_DIR/yara_rules.yar"
sudo chown -R root:wazuh /var/ossec/etc/yara && sudo chmod 750 /var/ossec/etc/yara "$RULES_DIR" && sudo chmod 640 "$RULES_DIR/yara_rules.yar"
ls -lah "$RULES_DIR"
echo "Now: copy wazuh/agents/linux/active-response/yara.sh to /var/ossec/active-response/bin/ (root:wazuh 750) and restart wazuh-agent"
