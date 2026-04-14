# Wazuh Custom Integration Scripts — Complete Guide

> **How to format data for Wazuh, avoid sending duplicates, and build production-ready integration scripts.**

---

## Table of Contents

- [1. Data Ingestion Architecture](#1-data-ingestion-architecture)
  - [How Wazuh Receives Data](#how-does-wazuh-receive-data)
  - [Ingestion Methods](#ingestion-methods)
- [2. Data Formatting: How to Present Data to Wazuh](#2-data-formatting-how-to-present-data-to-wazuh)
  - [Recommended JSON Structure](#recommended-json-structure)
  - [Critical Formatting Rules](#critical-formatting-rules)
  - [Writing Output from Your Script](#writing-output-from-your-script)
- [3. Deduplication: How to Avoid Sending Duplicate Data](#3-deduplication-how-to-avoid-sending-duplicate-data)
  - [Strategy A: State File with Last Timestamp/ID](#strategy-a-state-file-with-last-timestampid)
  - [Strategy B: Hash Set for Exact Duplicate Detection](#strategy-b-hash-set-for-exact-duplicate-detection)
  - [Strategy C: API Cursor with Pagination](#strategy-c-api-cursor-with-pagination)
  - [Strategy Comparison](#strategy-comparison)
- [4. Wazuh Python Framework](#4-wazuh-python-framework)
  - [Location and Usage](#location-and-usage)
  - [Key Capabilities](#key-capabilities)
  - [When to Use the Framework vs. Standalone Scripts](#when-to-use-the-framework-vs-standalone-scripts)
- [5. Practical Use Cases](#5-practical-use-cases)
  - [Case 1: REST API Polling (Threat Intelligence Feed)](#case-1-rest-api-polling-threat-intelligence-feed)
  - [Case 2: File-Based Ingestion via Logcollector (Vulnerability Scanner)](#case-2-file-based-ingestion-via-logcollector-vulnerability-scanner)
  - [Case 3: Reactive Integration via Integratord (VirusTotal Enrichment)](#case-3-reactive-integration-via-integratord-virustotal-enrichment)
  - [Case 4: Database Audit Ingestion (PostgreSQL)](#case-4-database-audit-ingestion-postgresql)
- [6. Common Patterns and Best Practices](#6-common-patterns-and-best-practices)
  - [Integration Checklist](#integration-checklist)
  - [Common Mistakes to Avoid](#common-mistakes-to-avoid)
  - [Recommended Directory Structure](#recommended-directory-structure)
- [7. Official Wazuh Documentation References](#7-official-wazuh-documentation-references)

---

## 1. Data Ingestion Architecture

### How Does Wazuh Receive Data?

Wazuh processes data through its **analysis engine (analysisd)**. There are two main paths for injecting custom data:

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ External Source  │────▶│  Custom Script    │────▶│  Wazuh Input        │
│ (API, DB, file)  │     │  (Python/Bash)    │     │                     │
└─────────────────┘     └────────��─────────┘     │  Option A:          │
                                                  │   Wodle Command     │
                                                  │   (stdout capture)  │
                                                  │                     │
                                                  │  Option B:          │
                                                  │   Logcollector      │
                                                  │   (file monitoring) │
                                                  │                     │
                                                  │  Option C:          │
                                                  │   Integratord       │
                                                  │   (alert-reactive)  │
                                                  │                     │
                                                  │  Option D:          │
                                                  │   Syslog forwarding │
                                                  └────────┬────────────┘
                                                           │
                                                  ┌────────▼────────────┐
                                                  │  analysisd          │
                                                  │  (decoding + rules) │
                                                  └────────┬────────────┘
                                                           │
                                                  ┌────────▼─────────��──┐
                                                  │  Alerts / Indexer   │
                                                  └─────────────────────┘
```

### Ingestion Methods

| Method | Mechanism | Best For |
|---|---|---|
| **Wodle Command** | `ossec.conf` runs your script on a schedule | Polling APIs, DB queries |
| **Logcollector** | Wazuh reads a log file your script writes to | Continuous stream-like data |
| **Integratord** | Wazuh's native integration framework | Reactive enrichment (post-alert) |
| **Syslog Output** | Script sends syslog to the agent/manager | Legacy systems |

---

## 2. Data Formatting: How to Present Data to Wazuh

### Core Principle

Wazuh expects **one line of text = one event**. The most effective and recommended format is **single-line JSON**, because:

- Wazuh automatically decodes it with the built-in `json` decoder
- Fields become available as `data.field_name` in rules
- It's extensible without writing custom decoders

### Recommended JSON Structure

```json
{
  "integration": "custom-my_integration_name",
  "source": "source_name",
  "event_type": "event_type",
  "severity": "low|medium|high|critical",
  "timestamp": "2026-04-14T10:30:00Z",
  "description": "Human-readable event description",
  "data": {
    "field1": "value1",
    "field2": "value2"
  }
}
```

### Critical Formatting Rules

| # | Rule | Why |
|---|---|---|
| 1 | **One line per event** — no newlines inside JSON | Wazuh treats each line as a separate event. A multi-line JSON will be parsed as multiple broken events. |
| 2 | **Always include `timestamp`** — ISO 8601 format | Ensures accurate event chronology in the indexer. |
| 3 | **Include a unique identifier field** | Required for effective deduplication (see Section 3). |
| 4 | **Include an `integration` field** | Allows filtering in rules with `<field name="integration">`. |
| 5 | **Do not exceed 65,535 bytes per event** | This is the hard-coded maximum single event size in `analysisd`. Events exceeding this will be truncated silently. |

### Writing Output from Your Script

```python
import json
import sys

def send_event(event: dict):
    """Send an event to stdout in Wazuh-compatible format."""
    # separators=(',', ':') removes whitespace, keeps it single-line
    line = json.dumps(event, separators=(',', ':'))
    print(line)
    sys.stdout.flush()
```

---

## 3. Deduplication: How to Avoid Sending Duplicate Data

This is the **most critical** and most frequently misimplemented aspect of custom integrations.

### Strategy A: State File with Last Timestamp/ID

Persist the last processed timestamp or event ID between runs. On next execution, only query/process events newer than the saved marker.

```python
import json
import os

STATE_FILE = "/var/ossec/var/run/custom_integration_state.json"

def load_state() -> dict:
    """Load previous execution state."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {"last_timestamp": None, "last_event_id": None}

def save_state(state: dict):
    """Persist current state for the next execution."""
    tmp_file = STATE_FILE + ".tmp"
    with open(tmp_file, 'w') as f:
        json.dump(state, f)
    os.replace(tmp_file, STATE_FILE)  # Atomic on POSIX

def get_new_events(all_events: list, state: dict) -> list:
    """Filter only new events based on saved state."""
    last_ts = state.get("last_timestamp")
    if last_ts is None:
        return all_events
    return [e for e in all_events if e["timestamp"] > last_ts]
```

### Strategy B: Hash Set for Exact Duplicate Detection

Compute a hash of the identifying fields for each event. Maintain a set of seen hashes and skip any event whose hash already exists.

```python
import hashlib
import json
import os

SEEN_FILE = "/var/ossec/var/run/custom_integration_seen.json"
MAX_SEEN = 10000  # Limit memory usage

def compute_event_hash(event: dict) -> str:
    """Generate a unique hash based on fields that identify the event."""
    unique_payload = {
        "source": event.get("source"),
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
    }
    raw = json.dumps(unique_payload, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def load_seen_hashes() -> set:
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, 'r') as f:
            return set(json.load(f))
    return set()

def save_seen_hashes(seen: set):
    seen_list = list(seen)
    if len(seen_list) > MAX_SEEN:
        seen_list = seen_list[-MAX_SEEN:]
    with open(SEEN_FILE, 'w') as f:
        json.dump(seen_list, f)

def is_duplicate(event: dict, seen: set) -> bool:
    h = compute_event_hash(event)
    if h in seen:
        return True
    seen.add(h)
    return False
```

### Strategy C: API Cursor with Pagination

Many modern APIs support cursors or temporal pagination. This is the most reliable method when the source API supports it.

```python
import requests

def fetch_with_cursor(api_url: str, headers: dict, state: dict) -> tuple:
    """
    Fetch events using API-native cursor pagination.
    Always prefer this method when the API supports it.
    """
    params = {"limit": 100, "order": "asc"}

    if state.get("next_cursor"):
        params["cursor"] = state["next_cursor"]
    elif state.get("last_timestamp"):
        params["since"] = state["last_timestamp"]

    response = requests.get(api_url, headers=headers, params=params)
    response.raise_for_status()
    data = response.json()

    events = data.get("results", [])
    new_cursor = data.get("next_cursor")

    return events, new_cursor
```

### Strategy Comparison

| Strategy | Pros | Cons | Use When |
|---|---|---|---|
| **State file (timestamp/ID)** | Simple, low disk usage | May miss events if they arrive out of order | API guarantees chronological order |
| **Hash set** | Detects exact duplicates regardless of order | Higher memory/disk usage | Sources without ordering or cursors |
| **API cursor** | Most reliable, API-native | Depends on API support | Well-designed APIs (most modern ones) |

---

## 4. Wazuh Python Framework

Wazuh ships with its own Python interpreter and SDK located at `/var/ossec/framework/python/`.

### Location and Usage

```bash
# Wazuh's bundled Python interpreter (includes the SDK)
/var/ossec/framework/python/bin/python3

# Framework modules
/var/ossec/framework/python/lib/python3.x/site-packages/wazuh/
```

### Key Capabilities

```python
#!/var/ossec/framework/python/bin/python3
"""
This script uses Wazuh's Python framework.
It MUST be executed with Wazuh's bundled interpreter.
"""

# ── Core: manager information ──
from wazuh.core.common import WAZUH_PATH       # /var/ossec

# ── Agents ──
from wazuh import agent
result = agent.get_agents(q="status=active")
print(result.affected_items)

# ── Rules ──
from wazuh import rule
result = rule.get_rules(search={"value": "sshd", "negation": False})
```

### When to Use the Framework vs. Standalone Scripts

| Aspect | Wazuh Framework (`/var/ossec/framework/python/`) | Standalone Script (system Python) |
|---|---|---|
| **Access to Wazuh config** | ✅ Direct via internal API | ❌ Must parse XML manually |
| **Agent information** | ✅ Native SDK | ⚠️ Via REST API |
| **Portability** | ❌ Manager only | ✅ Any machine |
| **External dependencies** | ⚠️ Limited to Wazuh's environment | ✅ `pip install` anything |
| **Recommended for** | Integrations that need Wazuh's internal data | Polling external APIs, data transformation |

---

## 5. Practical Use Cases

---

### Case 1: REST API Polling (Threat Intelligence Feed)

**Scenario:** Query a threat intelligence API every 5 minutes and inject new IOCs.

**Method:** Wodle Command

#### ossec.conf Configuration

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>threat-intel</tag>
  <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-threat-intel.py</command>
  <interval>5m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>120</timeout>
</wodle>
```

#### Full Script

```python
#!/var/ossec/framework/python/bin/python3
"""
Custom integration: Threat Intelligence Feed -> Wazuh
Location: /var/ossec/integrations/custom-threat-intel.py
Method: Wodle Command (polling every 5 min)
"""

import json
import os
import sys
import hashlib
import requests
from datetime import datetime, timezone

# ── Configuration ──
API_URL = "https://api.threatfeed.example.com/v1/indicators"
API_KEY = os.environ.get("THREAT_INTEL_API_KEY", "")
STATE_FILE = "/var/ossec/var/run/threat_intel_state.json"
SEEN_FILE = "/var/ossec/var/run/threat_intel_seen.json"
MAX_SEEN_HASHES = 50000
LOG_FILE = "/var/ossec/logs/threat_intel_integration.log"
INTEGRATION_NAME = "custom-threat-intel"


# ── Logging (never pollute stdout) ──
def log(level: str, message: str):
    ts = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, 'a') as f:
        f.write(f"{ts} [{level.upper()}] {message}\n")


# ── State Management ──
def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            log("warn", "State file corrupted, starting fresh")
    return {"last_timestamp": None, "next_cursor": None}


def save_state(state: dict):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


# ── Deduplication ──
def load_seen() -> set:
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, 'r') as f:
                return set(json.load(f))
        except (json.JSONDecodeError, IOError):
            pass
    return set()


def save_seen(seen: set):
    seen_list = list(seen)
    if len(seen_list) > MAX_SEEN_HASHES:
        seen_list = seen_list[-MAX_SEEN_HASHES:]
    tmp = SEEN_FILE + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(seen_list, f)
    os.replace(tmp, SEEN_FILE)


def event_hash(indicator: dict) -> str:
    unique = f"{indicator.get('id','')}{indicator.get('value','')}"
    return hashlib.sha256(unique.encode()).hexdigest()[:16]


# ── Data Fetch ──
def fetch_indicators(state: dict) -> tuple:
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Accept": "application/json"
    }
    params = {"limit": 200, "order": "asc"}

    if state.get("next_cursor"):
        params["cursor"] = state["next_cursor"]
    elif state.get("last_timestamp"):
        params["since"] = state["last_timestamp"]

    try:
        resp = requests.get(API_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("indicators", []), data.get("next_cursor")
    except requests.RequestException as e:
        log("error", f"API request failed: {e}")
        return [], None


# ── Transformation: Wazuh format ──
def transform_indicator(indicator: dict) -> dict:
    """Transform an IOC from API format to Wazuh format."""
    severity_map = {"low": 3, "medium": 7, "high": 10, "critical": 13}

    return {
        "integration": INTEGRATION_NAME,
        "source": "threat-intel-feed",
        "event_type": "ioc",
        "timestamp": indicator.get("created_at",
                                   datetime.now(timezone.utc).isoformat()),
        "alert": {
            "severity": severity_map.get(
                indicator.get("severity", "low"), 3
            ),
            "description": (
                f"Threat indicator: {indicator.get('type', 'unknown')}"
                f" - {indicator.get('value', 'N/A')}"
            ),
        },
        "data": {
            "ioc_type": indicator.get("type"),
            "ioc_value": indicator.get("value"),
            "threat_type": indicator.get("threat_type"),
            "confidence": indicator.get("confidence", 0),
            "source_feed": indicator.get("feed_name"),
            "tags": indicator.get("tags", []),
            "first_seen": indicator.get("first_seen"),
            "last_seen": indicator.get("last_seen"),
            "reference_url": indicator.get("reference"),
        }
    }


# ── Send to Wazuh (stdout for wodle command) ──
def send_event(event: dict):
    line = json.dumps(event, separators=(',', ':'))
    print(line)
    sys.stdout.flush()


# ── Main ──
def main():
    log("info", "Starting threat intel collection")

    state = load_state()
    seen = load_seen()
    total_new = 0
    total_dup = 0

    while True:
        indicators, next_cursor = fetch_indicators(state)

        if not indicators:
            break

        for indicator in indicators:
            h = event_hash(indicator)
            if h in seen:
                total_dup += 1
                continue

            seen.add(h)
            event = transform_indicator(indicator)
            send_event(event)
            total_new += 1

        last = indicators[-1]
        state["last_timestamp"] = last.get("created_at")
        state["next_cursor"] = next_cursor

        if not next_cursor:
            break

    save_state(state)
    save_seen(seen)
    log("info",
        f"Finished: {total_new} new events, {total_dup} duplicates skipped")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("critical", f"Unhandled exception: {e}")
        sys.exit(1)
```

#### Custom Rules

```xml
<!-- /var/ossec/etc/rules/custom-threat-intel-rules.xml -->
<group name="custom,threat-intel,">

  <!-- Base rule: any event from this integration -->
  <rule id="100100" level="0">
    <decoded_as>json</decoded_as>
    <field name="integration">custom-threat-intel</field>
    <description>Threat intelligence integration event.</description>
  </rule>

  <!-- Low confidence IOC -->
  <rule id="100101" level="3">
    <if_sid>100100</if_sid>
    <field name="data.confidence">^[0-4]\d$|^[0-9]$</field>
    <description>Low confidence threat indicator: $(data.ioc_type) - $(data.ioc_value)</description>
    <group>threat_intel,ioc,low,</group>
  </rule>

  <!-- High confidence IOC -->
  <rule id="100102" level="10">
    <if_sid>100100</if_sid>
    <field name="data.confidence">^(8\d|9\d|100)$</field>
    <description>High confidence threat indicator: $(data.ioc_type) - $(data.ioc_value)</description>
    <group>threat_intel,ioc,high,</group>
  </rule>

  <!-- Critical IOC -->
  <rule id="100103" level="13">
    <if_sid>100100</if_sid>
    <field name="alert.severity">13</field>
    <description>CRITICAL threat indicator detected: $(data.ioc_type) - $(data.ioc_value)</description>
    <group>threat_intel,ioc,critical,</group>
    <options>alert_by_email</options>
  </rule>

</group>
```

> **📖 Official Docs:**
> - [Wodle Command configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
> - [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
> - [Custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)

---

### Case 2: File-Based Ingestion via Logcollector (Vulnerability Scanner)

**Scenario:** A vulnerability scanner writes results to a file; Wazuh monitors the file.

**Method:** Script writes to a file → Logcollector reads it

#### Full Script

```python
#!/usr/bin/env python3
"""
Vulnerability scan results -> JSON lines file -> Wazuh logcollector
Location: /var/ossec/integrations/custom-vuln-scanner.py
Runs via cron: 0 */6 * * * (every 6 hours)
"""

import json
import os
import fcntl
import subprocess
import hashlib
from datetime import datetime, timezone

OUTPUT_FILE = "/var/ossec/logs/custom/vuln-scanner.log"
STATE_FILE = "/var/ossec/var/run/vuln_scanner_state.json"
INTEGRATION_NAME = "custom-vuln-scanner"


def ensure_output_dir():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {"last_scan_hashes": []}


def save_state(state: dict):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def run_scan() -> list:
    """
    Execute the scan and return a list of findings.
    Replace this with your actual scanning logic.
    """
    result = subprocess.run(
        ["dpkg-query", "-W", "-f",
         '{"package":"${Package}","version":"${Version}",'
         '"status":"${Status}"}\n'],
        capture_output=True, text=True
    )
    findings = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try:
                pkg = json.loads(line)
                findings.append(pkg)
            except json.JSONDecodeError:
                continue
    return findings


def transform_finding(finding: dict, scan_id: str) -> dict:
    return {
        "integration": INTEGRATION_NAME,
        "source": "vulnerability-scanner",
        "event_type": "vulnerability",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "data": {
            "package": finding.get("package"),
            "installed_version": finding.get("version"),
            "cve_id": finding.get("cve_id", "N/A"),
            "cvss_score": finding.get("cvss_score", 0),
            "fix_version": finding.get("fix_version", "N/A"),
            "severity": finding.get("severity", "unknown"),
            "hostname": os.uname().nodename,
        }
    }


def write_events(events: list):
    """
    Write to the log file with file locking.
    CRITICAL: locking prevents partial writes that
    logcollector could read as corrupt events.
    """
    ensure_output_dir()
    with open(OUTPUT_FILE, 'a') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            for event in events:
                line = json.dumps(event, separators=(',', ':'))
                f.write(line + '\n')
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def main():
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    state = load_state()

    findings = run_scan()

    current_hashes = []
    new_events = []

    for finding in findings:
        h = hashlib.sha256(
            json.dumps(finding, sort_keys=True).encode()
        ).hexdigest()[:16]
        current_hashes.append(h)

        if h not in state.get("last_scan_hashes", []):
            event = transform_finding(finding, scan_id)
            new_events.append(event)

    if new_events:
        write_events(new_events)

    state["last_scan_hashes"] = current_hashes
    save_state(state)


if __name__ == "__main__":
    main()
```

#### ossec.conf — Logcollector Configuration

```xml
<!-- On the agent's ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/custom/vuln-scanner.log</location>
  <label key="integration">custom-vuln-scanner</label>
</localfile>
```

> **Note:** When using `<log_format>json</log_format>`, Wazuh automatically parses each line as JSON. No custom decoder is needed.

#### Log Rotation

```
# /etc/logrotate.d/wazuh-vuln-scanner
/var/ossec/logs/custom/vuln-scanner.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
```

> **📖 Official Docs:**
> - [localfile configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
> - [Log data collection — monitoring log files](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html)

---

### Case 3: Reactive Integration via Integratord (VirusTotal Enrichment)

**Scenario:** When Wazuh detects a suspicious file hash, automatically query VirusTotal for enrichment.

**Method:** Integratord (triggered as a reaction to alerts)

#### ossec.conf Configuration

```xml
<integration>
  <name>custom-virustotal-enrichment</name>
  <hook_url>https://www.virustotal.com</hook_url>
  <api_key>YOUR_VT_API_KEY</api_key>
  <level>7</level>
  <rule_id>550,554</rule_id>  <!-- File integrity monitoring rules -->
  <alert_format>json</alert_format>
</integration>
```

#### Full Script

```python
#!/var/ossec/framework/python/bin/python3
"""
Reactive integration: VirusTotal Enrichment
Location: /var/ossec/integrations/custom-virustotal-enrichment
(no .py extension, must be executable)

Integratord invokes this script with:
  argv[1] = temp file containing the alert (JSON)
  argv[2] = api_key
  argv[3] = hook_url (not used here)
"""

import json
import sys
import os
import requests
from datetime import datetime, timezone

LOG_FILE = "/var/ossec/logs/integrations.log"
INTEGRATION_NAME = "custom-virustotal-enrichment"


def read_alert(alert_file: str) -> dict:
    """Read the alert that triggered this integration."""
    with open(alert_file, 'r') as f:
        return json.load(f)


def extract_hash(alert: dict) -> str:
    """Extract file hash from a syscheck alert."""
    syscheck = alert.get("syscheck", {})
    for algo in ["sha256_after", "sha256", "sha1_after", "md5_after"]:
        h = syscheck.get(algo)
        if h:
            return h
    return None


def query_virustotal(file_hash: str, api_key: str) -> dict:
    """Query VT and return the result."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return {"data": {"attributes": {"last_analysis_stats": None}}}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def build_enriched_event(alert: dict, vt_result: dict) -> dict:
    """Build the enriched event in Wazuh format."""
    stats = (vt_result.get("data", {})
             .get("attributes", {})
             .get("last_analysis_stats"))

    malicious = 0
    total = 0
    if stats:
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

    if stats is None:
        threat_level = "unknown"
        severity = 3
    elif malicious == 0:
        threat_level = "clean"
        severity = 0
    elif malicious < 5:
        threat_level = "suspicious"
        severity = 7
    else:
        threat_level = "malicious"
        severity = 13

    file_hash = extract_hash(alert)

    return {
        "integration": INTEGRATION_NAME,
        "source": "virustotal",
        "event_type": "file_enrichment",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "original_rule_id": alert.get("rule", {}).get("id"),
            "original_level": alert.get("rule", {}).get("level"),
            "severity": severity,
            "description": (
                f"VirusTotal: {malicious}/{total} engines detected "
                f"'{alert.get('syscheck', {}).get('path', 'unknown')}' "
                f"as {threat_level}"
            ),
        },
        "data": {
            "file_path": alert.get("syscheck", {}).get("path"),
            "file_hash": file_hash,
            "vt_malicious": malicious,
            "vt_total_engines": total,
            "vt_threat_level": threat_level,
            "vt_permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            "agent_id": alert.get("agent", {}).get("id"),
            "agent_name": alert.get("agent", {}).get("name"),
        }
    }


def send_event(event: dict):
    """Integratord captures stdout as an event."""
    msg = json.dumps(event, separators=(',', ':'))
    print(msg)
    sys.stdout.flush()


def main():
    if len(sys.argv) < 3:
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]

    alert = read_alert(alert_file)
    file_hash = extract_hash(alert)

    if not file_hash:
        return

    vt_result = query_virustotal(file_hash, api_key)
    event = build_enriched_event(alert, vt_result)
    send_event(event)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        with open(LOG_FILE, 'a') as f:
            ts = datetime.now(timezone.utc).isoformat()
            f.write(f"{ts} ERROR: {INTEGRATION_NAME}: {e}\n")
        sys.exit(1)
```

#### Required Permissions

```bash
chmod 750 /var/ossec/integrations/custom-virustotal-enrichment
chown root:wazuh /var/ossec/integrations/custom-virustotal-enrichment
```

> **📖 Official Docs:**
> - [Integration configuration reference (ossec.conf)](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
> - [wazuh-integratord daemon](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html)
> - [External API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
> - [VirusTotal integration PoC](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html)

---

### Case 4: Database Audit Ingestion (PostgreSQL)

**Scenario:** Query a PostgreSQL audit table every 10 minutes and inject change events.

**Method:** Wodle Command

#### Full Script

```python
#!/usr/bin/env python3
"""
PostgreSQL audit log ingestion -> Wazuh
Location: /var/ossec/integrations/custom-db-audit.py
Method: Wodle Command every 10 minutes

Expected audit table:
  audit_log(id SERIAL, action TEXT, table_name TEXT,
            user_name TEXT, old_data JSONB, new_data JSONB,
            executed_at TIMESTAMP WITH TIME ZONE)
"""

import json
import sys
import os
from datetime import datetime, timezone

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print(json.dumps({
        "integration": "custom-db-audit",
        "event_type": "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"error": "psycopg2 not installed"}
    }))
    sys.exit(1)

# ── Config ──
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "dbname": os.environ.get("DB_NAME", "app_production"),
    "user": os.environ.get("DB_USER", "wazuh_reader"),
    "password": os.environ.get("DB_PASSWORD", ""),
}
STATE_FILE = "/var/ossec/var/run/db_audit_state.json"
INTEGRATION_NAME = "custom-db-audit"
BATCH_SIZE = 500


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {"last_id": 0}


def save_state(state: dict):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def fetch_audit_records(last_id: int) -> list:
    """
    Deduplication by auto-increment ID:
    Only queries records with ID greater than the last processed one.
    This is the most efficient pattern for tables with sequential PKs.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, action, table_name, user_name,
                       old_data, new_data, executed_at
                FROM audit_log
                WHERE id > %s
                ORDER BY id ASC
                LIMIT %s
            """, (last_id, BATCH_SIZE))
            return cur.fetchall()
    finally:
        conn.close()


def transform_record(record: dict) -> dict:
    severity_map = {
        "INSERT": 3,
        "UPDATE": 5,
        "DELETE": 8,
        "TRUNCATE": 13,
        "ALTER": 13,
        "DROP": 15,
    }

    action = record.get("action", "UNKNOWN").upper()

    changed_fields = []
    if action == "UPDATE" and record.get("old_data") and record.get("new_data"):
        old = record["old_data"] if isinstance(record["old_data"], dict) else {}
        new = record["new_data"] if isinstance(record["new_data"], dict) else {}
        changed_fields = [k for k in new if old.get(k) != new.get(k)]

    return {
        "integration": INTEGRATION_NAME,
        "source": "postgresql-audit",
        "event_type": "db_change",
        "timestamp": (record.get("executed_at", datetime.now(timezone.utc))
                      .isoformat() if hasattr(record.get("executed_at"), 'isoformat')
                      else str(record.get("executed_at"))),
        "alert": {
            "severity": severity_map.get(action, 5),
            "description": (
                f"Database {action} on {record.get('table_name')} "
                f"by {record.get('user_name')}"
            ),
        },
        "data": {
            "record_id": record.get("id"),
            "action": action,
            "table_name": record.get("table_name"),
            "db_user": record.get("user_name"),
            "changed_fields": changed_fields,
            "old_data": (json.dumps(record["old_data"])
                         if record.get("old_data") else None),
            "new_data": (json.dumps(record["new_data"])
                         if record.get("new_data") else None),
        }
    }


def send_event(event: dict):
    print(json.dumps(event, separators=(',', ':')))
    sys.stdout.flush()


def main():
    state = load_state()
    last_id = state.get("last_id", 0)

    records = fetch_audit_records(last_id)

    for record in records:
        event = transform_record(record)
        send_event(event)
        last_id = max(last_id, record.get("id", last_id))

    state["last_id"] = last_id
    save_state(state)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        err = {
            "integration": INTEGRATION_NAME,
            "event_type": "integration_error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"error": str(e)}
        }
        print(json.dumps(err, separators=(',', ':')))
        sys.exit(1)
```

> **📖 Official Docs:**
> - [Wodle Command configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)

---

## 6. Common Patterns and Best Practices

### Integration Checklist

- [ ] **Format:** Single-line JSON per event
- [ ] **`integration` field** included for rule filtering
- [ ] **ISO 8601 timestamp** in every event
- [ ] **Deduplication mechanism** (state file, hash set, or cursor)
- [ ] **Atomic state file writes** (write to `.tmp` + `os.replace`)
- [ ] **Error handling** that does NOT pollute stdout
- [ ] **Timeouts** on all network connections
- [ ] **Log rotation** on the output file (if using logcollector)
- [ ] **Permissions:** `750` for scripts, owner `root:wazuh`
- [ ] **Sensitive variables** in env vars, NEVER hardcoded
- [ ] **Matching rules XML** in `/var/ossec/etc/rules/`

### Common Mistakes to Avoid

| Mistake | Consequence | Solution |
|---|---|---|
| Multi-line JSON | Wazuh interprets it as multiple broken events | `json.dumps(event, separators=(',',':'))` |
| Printing errors to stdout | Error messages are ingested as corrupt events | Log errors to a separate log file |
| No deduplication | Alert flooding, disk fills up | Implement a state file from day one |
| Non-atomic state file writes | Corruption if the process dies mid-write | Write to `.tmp` then `os.replace()` |
| No timeout on HTTP requests | Script hangs, wodle kills it via global timeout | `timeout=30` on every HTTP call |
| Events > 65,535 bytes | Silently truncated by `analysisd` | Split large events or reduce payload |

### Recommended Directory Structure

```
/var/ossec/
├── integrations/
│   ├── custom-threat-intel.py              # Integration scripts
│   ├── custom-vuln-scanner.py
│   ├── custom-db-audit.py
│   └── custom-virustotal-enrichment        # No extension for integratord
├── var/run/
│   ├── threat_intel_state.json             # State files
│   ├── threat_intel_seen.json              # Hash sets
│   ��── vuln_scanner_state.json
│   └── db_audit_state.json
├── logs/
│   ├── custom/
│   │   └── vuln-scanner.log                # Output for logcollector
│   ├── threat_intel_integration.log        # Debug logs
│   └── integrations.log                    # Used by integratord
└── etc/rules/
    ├── custom-threat-intel-rules.xml       # Rules per integration
    ├── custom-vuln-scanner-rules.xml
    └── custom-db-audit-rules.xml
```

---

## 7. Official Wazuh Documentation References

All technical claims in this guide have been verified against the official Wazuh documentation. Below are the canonical references for each integration method:

### Wodle Command (Cases 1 & 4)

| Resource | URL |
|---|---|
| Wodle command configuration reference | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html |

### Logcollector / localfile (Case 2)

| Resource | URL |
|---|---|
| `localfile` configuration reference | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html |
| Log data collection — monitoring log files | https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html |

### Integratord (Case 3)

| Resource | URL |
|---|---|
| `integration` configuration reference | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html |
| `wazuh-integratord` daemon reference | https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html |
| External API integration guide | https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html |
| VirusTotal integration PoC | https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html |

### Syslog Output

| Resource | URL |
|---|---|
| `syslog_output` configuration reference | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syslog-output.html |

### Rules and Decoders

| Resource | URL |
|---|---|
| Custom rules | https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html |
| Custom decoders | https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html |
| Decoders syntax reference | https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html |

### Analysis Engine

| Resource | URL |
|---|---|
| `wazuh-analysisd` daemon reference | https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html |
| Event size limit (65,535 bytes) discussion | https://github.com/wazuh/wazuh/issues/17689 |

### General

| Resource | URL |
|---|---|
| `ossec.conf` full reference index | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html |

---

## License

This documentation is provided as-is for educational and operational purposes.
