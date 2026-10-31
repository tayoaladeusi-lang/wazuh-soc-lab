#!/bin/bash
# Wazuh active response: YARA-scan, then quarantine a webshell flagged by FIM
# Scan runs BEFORE the move, so YARA enrichment is never lost to a race.
LOG=/var/ossec/logs/active-responses.log
QDIR=/var/ossec/quarantine
YARA_BIN=/usr/bin/yara
YARA_RULES=/var/ossec/yara/rules/lab_rules.yar
mkdir -p "$QDIR"

read -r INPUT
FILE=$(echo "$INPUT" | grep -oP '"path"\s*:\s*"\K[^"]+' | head -1)

if [ -n "$FILE" ] && [ -f "$FILE" ]; then
  # 1. YARA scan (same log format as yara-scan.sh, so the decoder and rule 108001 still match)
  if [ -x "$YARA_BIN" ] && [ -r "$YARA_RULES" ]; then
    RESULTS=$("$YARA_BIN" -w "$YARA_RULES" "$FILE" 2>/dev/null)
    if [ -n "$RESULTS" ]; then
      while read -r line; do
        RULE=$(echo "$line" | awk '{print $1}')
        [ -n "$RULE" ] && echo "wazuh-yara: INFO - Scan result: $RULE $FILE" >> "$LOG"
      done <<< "$RESULTS"
    else
      echo "wazuh-yara: INFO - No YARA match for $FILE" >> "$LOG"
    fi
  else
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine-webshell: YARA unavailable, scan skipped for $FILE" >> "$LOG"
  fi

  # 2. Record the hash, then contain
  SHA=$(sha256sum "$FILE" | awk '{print $1}')
  TS=$(date +%Y%m%d-%H%M%S)
  BASE=$(basename "$FILE")
  mv "$FILE" "$QDIR/${TS}_${BASE}.quarantined"
  chmod 000 "$QDIR/${TS}_${BASE}.quarantined"
  echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine-webshell: MOVED $FILE -> $QDIR/${TS}_${BASE}.quarantined" >> "$LOG"
  echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine-webshell: SHA256 $SHA ${TS}_${BASE}.quarantined" >> "$LOG"
else
  echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine-webshell: no file to quarantine (path=$FILE)" >> "$LOG"
fi
exit 0
