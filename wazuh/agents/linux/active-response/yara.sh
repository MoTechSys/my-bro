#!/bin/bash
# Wazuh - Yara active response (UC-07)
# Copyright (C) 2015-2022, Wazuh Inc. - GPLv2
# Target: /var/ossec/active-response/bin/yara.sh   (chown root:wazuh ; chmod 750)
# Source: S2 pp.42-43 ; S5 img24
#------------------------- Gather parameters -------------------------#
read -r INPUT_JSON
YARA_PATH=$(echo "$INPUT_JSON" | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo "$INPUT_JSON" | jq -r .parameters.extra_args[3])
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

# Wait until the file is fully written
size=0
actual_size=$(stat -c %s "${FILENAME}")
while [ "${size}" -ne "${actual_size}" ]; do
  sleep 1
  size=${actual_size}
  actual_size=$(stat -c %s "${FILENAME}")
done

#----------------------- Analyze parameters -----------------------#
if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]; then
  echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> "${LOG_FILE}"
  exit 1
fi

#------------------------- Main workflow --------------------------#
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"
if [[ $yara_output != "" ]]; then
  while read -r line; do
    echo "wazuh-yara: INFO - Scan result: $line" >> "${LOG_FILE}"
  done <<< "$yara_output"
fi
exit 0
