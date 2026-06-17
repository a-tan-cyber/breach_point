
Designing an Automated Attack Path Workflow for Ethical Network Security Testing

***

Student Name: Tan Amos

Student Code: s22

Class Code: CCK3\_250714

Institute: Centre for Cybersecurity

Trainer: Samson

***

### 1. Introduction

Project Breach Point is the first part of a breach simulation series under the penetration testing track. It is designed to simulate the tactics, techniques, and procedures (TTPs) of a threat actor and to guide the student through the penetration testing lifecycle: information gathering, exploitation, privilege escalation, and data exfiltration. The overall goal is to automate parts of this attack process using Bash (`.sh`) scripts so that the steps are repeatable and traceable.

This report explains how the accompanying Bash script, `Project Breach Point - Automation Script`, was designed and implemented to meet the project requirements. The explanation is written for beginners and focuses on clear, step‑by‑step descriptions of what the script does and how it aligns with the seven main scopes defined in the project brief.

***

### 2. Project Requirements Overview

The project brief defines a structured set of tasks grouped into seven scopes:

*   **Getting the user input** – Ask the user for the target network, create an output directory if needed, and let the user choose between a **Basic** or **Full** scan mode. Basic mode must scan TCP and UDP services, including service versions and weak passwords. Full mode must add Nmap Scripting Engine (NSE) checks and vulnerability analysis, and display potential vulnerabilities using NSE and Searchsploit.

*   **Presenting attack paths** – Once initial information is collected, the script must present several attack options and let the user choose what to do next. These options include weak credential checks, generating Metasploit resource (`.rc`) files, payload generation, and data exfiltration.

*   **Weak credentials** – Look for weak passwords used in login services (SSH, RDP, FTP and SMB). The script must have a built‑in `password.lst` file but also allow the user to provide their own password list.

*   **Automate with resource files** – Allow the user to generate different Metasploit resource (`.rc`) files to: (a) exploit SSH logins using `auxiliary/scanner/ssh/ssh_login` or another module, (b) create a handler, and (c) run the local exploit suggester. The user should also be able to choose whether to execute the generated `.rc` file.

*   **Generate a payload** – Ask the user where to store the payload, and collect all necessary options such as payload name, `LHOST`, `LPORT`, output format, and other details required by `msfvenom`.

*   **Data exfiltration** – Ask for the operating system (Linux or Windows) and then generate commands that will help the user find, compress, encode and transfer interesting files (for example files containing the words `password`, `.docx`, and `.xlsx`).

*   **Log results** – Show the current stage clearly in the terminal, summarise what was done at the end of the session, and allow the user to search inside the results before exiting.

In addition, the deliverables require a recorded demonstration of the script, commented code, proper credit for any reused snippets, and submission of both the script and a PDF report in a single compressed file.

***

### 3. Overall Script Design

The `Project Breach Point - Automation Script` was written in Bash and is intended to be run with `sudo` on a Linux system in a controlled, legal lab environment.

Key design features include:

*   **Safety and environment checks** – The script first checks that it is running as root (`$EUID -ne 0`) and prints a clear message if `sudo` is not used. This is important because tools like `nmap` and `masscan` often need root privileges.

*   **Help and header** – A `print_usage` function shows a detailed overview of what the script does and how to run it. This help can be accessed in three ways:

    *   By starting the script with `h` or `-help`.

    *   By pressing `h` or `H` at the initial banner prompt.

    *   By pressing `h` or `H` from the main menu.

*   **Session‑specific output structure** – The script asks the user for an output directory name and then creates a timestamped `run_YYYYMMDD_HHMMSS` folder inside it. Within this run folder, it creates subdirectories: `scans/`, `credentials/`, `metasploit/`, `payloads/`, and `logs/`. This keeps each run separate and organised.

*   **Logging and action tracking** – A `log_msg` function writes timestamped messages both to the screen and to a session log file (for example `logs/session.log`). An array called `SESSION_ACTIONS` records high‑level actions (such as "TCP scan completed"), which are summarised at the end of the session.

*   **Menu‑driven workflow** – After collecting initial input, the script presents a main menu that corresponds directly to the attack paths described in the project structure. The user can run scans, perform weak credential checks, generate `.rc` files, create payloads, build data exfiltration commands, check dependencies, or search the results.

*   **Dependency management** – The script checks for common tools such as `nmap`, `masscan`, `hydra`, `msfconsole`, `msfvenom`, `searchsploit`, `zip`, `scp`, `base64`, and `pscp`. If a tool is missing, the script can offer to install it via `apt-get` (if available) or continue with limited features.

This design makes the script modular and easier to understand: each major task is handled by a dedicated function (for example `run_scans`, `weak_credentials`, `generate_msf_rc`, `generate_payload`, and `data_exfil_helper`).

***

### 4. Implementation by Scope

### 4.1 Scope 1 – Getting the User Input

To satisfy Scope 1, the script asks the user for several important pieces of information at the beginning of the run:

*   **Target network** – The script repeatedly prompts for a target network (for example `192.168.1.0/24`) and checks for empty input or obvious mistakes like spaces.

*   **Output directory** – The user can type a name for the output directory (default: `output`). If the directory does not exist, the script creates it.

*   **Scan type (Basic or Full)** – The script asks the user to choose between `basic` and `full`. It accepts either upper or lower case input, and repeats the question until the user types a valid choice.

After these values are collected, the script sets up the run directory and logging, creates a default password wordlist if it does not already exist, and writes a simple default user list. These lists are used later for weak password checks.

### 4.2 Scope 2 – Presenting Attack Paths and Letting the User Choose

The main menu represents the different attack paths that the project requires. Each menu item maps to a function:

*   **Run network scans** – Stage 2: discovery and vulnerability scanning.

*   **Weak credential checks** – Stage 3: brute force login attempts against common services.

*   **Generate Metasploit** **`.rc`** **file** – Stage 4: resource file generation for Metasploit.

*   **Generate payload** – Stage 5: `msfvenom` payload creation.

*   **Data exfiltration helpers** – Stage 6: generating file search, compression, encoding and transfer commands.

*   **Search within results** – Stage 7: recursive search through all run output.

*   **Check/install dependencies** – On‑demand dependency status report and optional installation.

*   **Help / overview** – Displays the same usage information as the `h` / `-help` option.

This structure clearly presents the attack paths and allows the user to move between them in any order.

### 4.3 Scope 3 – Weak Credentials

The script fulfils the weak credential requirements in two complementary ways.

*   **Built‑in and custom wordlists**

    *   A function `ensure_wordlist` creates a default `password.lst` file the first time the script is run, containing typical weak passwords such as `password`, `admin123`, and simple numeric sequences.

    *   The script also writes a default user list containing usernames like `root`, `admin`, `guest`, `user`, and `test`.

    *   During weak credential checks, the user can choose to use this built‑in list or provide a custom password list. If a custom list path is invalid, the script falls back to the default.

*   **Services covered and tools used**

    *   The **quick weak‑password NSE scan** (`quick_weak_scan`) uses Nmap Scripting Engine to run scripts such as `ssh-brute`, `ftp-brute`, `smb-brute`, and `rdp-brute` against the entire target network. It uses the supplied user and password lists and saves results in both text and XML format.

    *   The **Hydra‑based weak credential checks** (`weak_credentials`) allow the user to test a specific host and service with `hydra`. The user can:

        *   Choose the service: SSH, RDP, FTP, or SMB.

        *   Provide a single username or a file containing multiple usernames.

        *   Provide or confirm the password list.

        *   Adjust the port if needed.

    *   If `hydra` is installed, the script runs it and stores the output in the `credentials/` directory. If `hydra` is missing, the script writes a suggested `hydra` command instead, so the student still understands how the test would be run.

Together, these features implement automated weak password checks for all services listed in the brief (SSH, RDP, FTP and SMB) and satisfy the requirement for both built‑in and user‑supplied wordlists.

### 4.4 Scope 4 – Automate with Resource Files

The `generate_msf_rc` function implements Scope 4 by guiding the user through the creation of Metasploit resource (`.rc`) files. The user is given three options:

*   **SSH login exploit/sweep** – Generates an `.rc` file that uses the `auxiliary/scanner/ssh/ssh_login` module by default. The script asks for:

    *   `RHOSTS` (single host, network, or host list),

    *   `USERNAME`,

    *   `PASS_FILE`,

    *   `THREADS`.

*   **Create a handler** – Generates an `.rc` file to start a multi/handler for a reverse shell payload. The script prompts for:

    *   Payload type (default: `windows/meterpreter/reverse_tcp`),

    *   `LHOST`,

    *   `LPORT` (validated to be numeric).

*   **Use the suggester** – Generates an `.rc` file that runs `post/multi/recon/local_exploit_suggester` against a given Metasploit session ID.

After generating the chosen `.rc` file in the `metasploit/` directory, the script asks if the user wants to run `msfconsole -r` with that file. If `msfconsole` is available and the user answers yes, the script launches Metasploit with the correct options. If not, the user still has a ready‑to‑use `.rc` file.

This behaviour matches the requirement to generate SSH exploit, handler, and suggester resource files, and to give the user the choice to execute them.

### 4.5 Scope 5 – Generate a Payload

Payload generation is handled by the `generate_payload` function. It follows the project requirements by collecting the necessary information from the user:

*   Directory to store the payload (default: the `payloads/` subdirectory of the current run).

*   Base name of the payload file (for example `payload`).

*   `LHOST` – the IP address or hostname where the reverse connection should return.

*   `LPORT` – the port for the reverse connection, validated to be numeric.

*   Payload type:

    *   Windows Meterpreter reverse TCP,

    *   Linux x64 Meterpreter reverse TCP, or

    *   a fully custom payload string entered by the user.

*   Output format (for example `exe`, `elf`, `asp`, `msi`, `raw`). A sensible default is provided based on the chosen payload family.

If `msfvenom` is installed, the script runs it with the provided parameters and writes the payload file to the chosen directory. Otherwise, the script prints a suggested `msfvenom` command so that the user understands exactly how to create the payload manually.

### 4.6 Scope 6 – Data Exfiltration Helpers

The `data_exfil_helper` function does not perform exfiltration directly. Instead, it safely generates example commands that a penetration tester might use to locate and prepare sensitive files for transfer. This respects the project brief, which emphasises generating commands rather than actually stealing data.

The function first asks for:

*   Target operating system: `linux` or `windows`.

*   Root directory to search (defaults to `/` on Linux and `C:\` on Windows).

*   Paths or patterns to compress (optional; may include globs like `/home/user/*.docx`).

*   An optional SCP destination, such as `user@attacker-ip:/tmp`.

Depending on the OS, the script then writes appropriate commands into `logs/data_exfil_commands.txt`:

*   **Linux commands**:

    *   `find` to search for files containing `password`, `.docx`, or `.xlsx` in their names.

    *   `zip` to compress selected files into `/tmp/exfil.zip`.

    *   `base64` to encode the ZIP file into `/tmp/exfil.zip.b64`.

    *   `scp` to copy the encoded file to the attacker machine.

*   **Windows commands**:

    *   `dir` with switches `/s /b` to recursively search for matching filenames.

    *   PowerShell `Compress-Archive` to create `C:\exfil.zip`.

    *   `certutil -encode` to convert the ZIP file into `C:\exfil.zip.b64`.

    *   `pscp` (PuTTY SCP client) to transfer the encoded file to the attacker.

If helper tools such as `zip`, `base64`, `scp` or `pscp` are missing locally, the script records this in the log so the user is aware that additional setup is required before the commands will work.

### 4.7 Scope 7 – Logging and Result Search

Scope 7 is implemented through a combination of logging, banners, and a final summary:

*   **Stage banners** – Before each major step, the script prints a banner (for example, "Stage 2 – Network Scanning") so that the current activity is clear to the user.

*   **Session log** – All important messages are written to `logs/session.log`, including tool availability, scan commands, file paths, and errors.

*   **Action summary** – The `finalize_session` function prints a "Session Summary" banner, summarises dependency status, and lists the high‑level actions stored in `SESSION_ACTIONS`.

*   **Search within results** – The `search_results` function allows the user to type a search term and runs a recursive `grep` across the entire run directory. This makes it easy to find specific IP addresses, hostnames, credentials or vulnerability names inside the stored output files.

This approach ensures that the student can replay what happened during the session and quickly locate relevant information.

***

### 5. Tools Used and Rationale

The script is designed to work with a set of widely‑used penetration testing tools.

*   **Nmap** – Performs TCP and UDP port scanning, service and version detection, and uses NSE scripts for brute‑forcing weak passwords and identifying known vulnerabilities.

*   **Masscan** – Acts as a fast UDP discovery scanner. The script uses it to quickly identify live UDP ports and then runs a more detailed `nmap -sU` scan only against those ports.

*   **Hydra** – Performs parallel login attempts against services such as SSH, RDP, FTP and SMB using username and password lists.

*   **Searchsploit** – Matches discovered services and versions to public exploits from Exploit‑DB, based on Nmap XML output.

*   **Metasploit (****`msfconsole`****)** – Executes resource files that automate exploit attempts, handlers and local exploit suggesters.

*   **Msfvenom** – Generates payload binaries (for example Windows and Linux Meterpreter reverse shells) according to user‑specified parameters.

*   **Zip, scp, base64, pscp** – Provide the building blocks for searching, compressing, encoding and transferring potentially sensitive files during the data exfiltration stage.

The script includes a dependency checker to make sure these tools are available and, where possible, to install missing packages using `apt-get`. This reduces setup friction for beginners and clearly shows which features are active or limited in each run.

***

### 6. Example Usage Workflow

A typical lab workflow with this script is as follows:

*   The student runs the script using `sudo ./breach_point.sh`.

*   The script shows a header banner and offers the option to display the full help/overview by pressing `h` or `H`.

*   The script prompts for the target network, output directory, and scan type (Basic or Full).

*   The script checks and, if requested, installs core dependencies, then displays the main menu.

*   The student chooses **Run network scans** to perform TCP/UDP scans and (in Full mode) additional NSE vulnerability checks and Searchsploit mapping.

*   The student chooses **Weak credential checks** to run either NSE‑based brute force or Hydra‑based tests against specific services.

*   If an exploitable weakness is found, the student uses **Generate Metasploit** **`.rc`** **file** and **Generate payload** to create handlers and payloads for exploitation.

*   The student uses **Data exfiltration helpers** to generate example commands for searching, compressing, encoding, and transferring files on Linux or Windows targets.

*   The student uses **Search within results** to locate particular findings in the saved output.

*   On exit, the script prints a session summary and key actions taken. All outputs and logs remain organised under the timestamped run directory for later review and reporting.

This sequence aligns well with the penetration testing lifecycle: reconnaissance, exploitation, post‑exploitation, and data exfiltration.

***

### 7. Limitations and Future Improvements

While the script covers all major project requirements, there are some limitations and areas for further improvement:

*   **Error handling and validation** – Basic checks (such as non‑empty input and numeric ports) are implemented, but more detailed validation of IP formats, network ranges, and file paths could be added.

*   **Service detection for targeted attacks** – Currently, weak credential checks and Metasploit resource files rely on manual input of hosts, users, and ports. A future version could parse Nmap results automatically and suggest pre‑filled values.

*   **Support for additional services and payloads** – The script focuses on SSH, RDP, FTP and SMB for weak credentials and two common Meterpreter families for payloads. It could be extended to cover more services and payload types as students progress.

*   **Cross‑distribution support** – The script assumes the presence of `apt-get` for package installation. Support for other package managers (such as `yum` or `dnf`) could make it more portable.

Reflecting on these limitations is part of the learning process. It helps identify how the current automation can be improved in later versions or more advanced courses.

***

### 8. Conclusion

This report has described how the `Project Breach Point - Automation Script` was designed and implemented to meet the project brief. The script guides the user from initial reconnaissance through weak credential discovery, exploitation setup, payload generation, and data exfiltration command building, while keeping outputs organised and logged.

For a beginner in penetration testing, the script serves as both a learning aid and a practical automation tool. It demonstrates how common security tools can be combined in a structured, repeatable workflow, and how Bash scripting can be used to simulate realistic attacker behaviour in a safe lab environment.
