#!/bin/bash
# Wazuh active response: quarantine a webshell flagged by FIM (rule 100030).
# Install to /var/ossec/active-response/bin/ on the agent (chmod 750, root:wazuh).
# Wired in manager ossec.conf via <command>/<active-response> on rule 100030.
LOG=/var/ossec/logs/active-responses.log
QDIR=/var/ossec/quarantine
mkdir -p "$QDIR"

read -r INPUT
FILE=$(echo "$INPUT" | grep -oP '"path"\s*:\s*"\K[^"]+' | head -1)

if [ -n "$FILE" ] && [ -f "$FILE" ]; then
  TS=$(date +%Y%m%d-%H%M%S)
  BASE=$(basename "$FILE")
  mv "$FILE" "$QDIR/${TS}_${BASE}.quarantined"
  chmod 000 "$QDIR/${TS}_${BASE}.quarantined"
  echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine-webshell: MOVED $FILE -> $QDIR/${TS}_${BASE}.quarantined" >> "$LOG"
else
  echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine-webshell: no file to quarantine (path=$FILE)" >> "$LOG"
fi
exit 0
