#!/bin/bash
# Wazuh active response: YARA-scan a file flagged by FIM (rule 554).
# Install to /var/ossec/active-response/bin/ on the agent (chmod 750, root:wazuh).
# Requires yara installed and rules at /var/ossec/yara/rules/lab_rules.yar.
# Output is parsed by rules/local_decoder.xml -> alert rule 108001.
LOG=/var/ossec/logs/active-responses.log
YARA_BIN=/usr/bin/yara
YARA_RULES=/var/ossec/yara/rules/lab_rules.yar

read -r INPUT
FILE=$(echo "$INPUT" | grep -oP '"path"\s*:\s*"\K[^"]+' | head -1)

if [ -n "$FILE" ] && [ -e "$FILE" ]; then
  RESULTS=$("$YARA_BIN" -w "$YARA_RULES" "$FILE" 2>/dev/null)
  if [ -n "$RESULTS" ]; then
    while read -r line; do
      RULE=$(echo "$line" | awk '{print $1}')
      [ -n "$RULE" ] && echo "wazuh-yara: INFO - Scan result: $RULE $FILE" >> "$LOG"
    done <<< "$RESULTS"
  else
    echo "wazuh-yara: INFO - No YARA match for $FILE" >> "$LOG"
  fi
fi
exit 0
