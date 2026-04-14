# Wazuh Custom Integration Scripts — Complete Guide (v2)

> **How to format data for Wazuh, avoid sending duplicates, and build production-ready integration scripts — with real-world patterns extracted from Wazuh's own source code.**

---

## Table of Contents

- [1. Data Ingestion Architecture](#1-data-ingestion-architecture)
- [2. Data Formatting: How to Present Data to Wazuh](#2-data-formatting-how-to-present-data-to-wazuh)
- [3. Deduplication: How to Avoid Sending Duplicate Data](#3-deduplication-how-to-avoid-sending-duplicate-data)
- [4. Wazuh Python Framework](#4-wazuh-python-framework)
- [5. Practical Use Cases](#5-practical-use-cases)
  - [Case 1: Wodle aws-s3 — AWS CloudTrail (Production Reference)](#case-1-wodle-aws-s3--aws-cloudtrail-production-reference)
  - [Case 2: Log Data Collection via Logcollector](#case-2-log-data-collection-via-logcollector)
  - [Case 3: Reactive Integration via Integratord](#case-3-reactive-integration-via-integratord)
    - [3A: VirusTotal (Enrich + Re-inject via UNIX Socket)](#3a-virustotal-enrich--re-inject-via-unix-socket)
    - [3B: Slack (Notify Externally via HTTP POST)](#3b-slack-notify-externally-via-http-post)
  - [Case 4: Database Audit Ingestion (PostgreSQL)](#case-4-database-audit-ingestion-postgresql)
- [6. Common Patterns and Best Practices](#6-common-patterns-and-best-practices)
- [7. Official Wazuh Documentation References](#7-official-wazuh-documentation-references)

---

## 1. Data Ingestion Architecture

### How Does Wazuh Receive Data?

Wazuh processes data through its **analysis engine (analysisd)**. There are several paths for injecting custom data:

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────────────┐
│ External Source  │────▶│  Custom Script    │────▶│  Wazuh Input             │
│ (API, DB, file)  │     │  (Python/Bash)    │     │                          │
└─────────────────┘     └──────────────────┘     │  Option A: Wodle          │
                                                  │  (stdout or UNIX socket)  │
                                                  │                          │
                                                  │  Option B: Logcollector   │
                                                  │  (file monitoring)        │
                                                  │                          │
                                                  │  Option C: Integratord    │
                                                  │  (alert-reactive)         │
                                                  │                          │
                                                  │  Option D: Syslog         │
                                                  │  (forwarding)             │
                                                  └────────┬─────────────────┘
                                                           │
                                                  ┌────────▼─────────────────┐
                                                  │  analysisd               │
                                                  │  (decoding + rules)      │
                                                  └────────┬─────────────────┘
                                                           │
                                                  ┌────────▼─────────────────┐
                                                  │  Alerts / Indexer        │
                                                  └──────────────────────────┘
```

### Ingestion Methods

| Method | Mechanism | Best For |
|---|---|---|
| **Wodle Command / aws-s3** | `ossec.conf` runs your script on a schedule; output via stdout or UNIX socket | Polling APIs, cloud services, DB queries |
| **Logcollector** | Wazuh reads a log file your script or application writes to | Monitoring application logs, third-party tool output |
| **Integratord** | Wazuh's native integration framework triggered by alerts | Reactive enrichment, notifications |
| **Syslog Output** | Script sends syslog to the agent/manager | Legacy systems |

---

## 2. Data Formatting: How to Present Data to Wazuh

### Core Principle

Wazuh expects **one line of text = one event**. The most effective format is **single-line JSON**, because:

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
| 1 | **One line per event** — no newlines inside JSON | Wazuh treats each line as a separate event. Multi-line JSON will be parsed as multiple broken events. |
| 2 | **Always include `timestamp`** — ISO 8601 format | Ensures accurate event chronology in the indexer. |
| 3 | **Include a unique identifier field** | Required for effective deduplication (see Section 3). |
| 4 | **Include an `integration` field** | Allows filtering in rules with `<field name="integration">`. |
| 5 | **Do not exceed 65,535 bytes per event** | Hard-coded max in `analysisd` ([`MAX_EVENT_SIZE = 65535`](https://github.com/wazuh/wazuh/blob/master/wodles/utils.py#L142)). Events exceeding this are truncated silently. |

### Writing Output: Two Methods

#### Method 1: stdout (Simple — Wodle captures output)

```python
import json, sys

def send_event_stdout(event: dict):
    """Send event to stdout — captured by wodle command."""
    line = json.dumps(event, separators=(',', ':'))
    print(line)
    sys.stdout.flush()
```

#### Method 2: UNIX Socket (Production — Direct to analysisd)

This is how Wazuh's own AWS integration sends events. It writes directly to the `analysisd` UNIX socket, bypassing stdout. Faster, more reliable.

From [`wodles/aws/wazuh_integration.py`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py#L293-L324):

```python
import json, socket

WAZUH_QUEUE = "/var/ossec/queue/sockets/queue"
MAX_EVENT_SIZE = 65535
MESSAGE_HEADER = "1:Wazuh-Custom:"  # Format: "1:<location>:"

def send_event_socket(event: dict):
    """Send event directly to the analysisd UNIX socket."""
    try:
        json_msg = json.dumps(event, default=str)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(WAZUH_QUEUE)
        encoded_msg = f"{MESSAGE_HEADER}{json_msg}".encode()
        if len(encoded_msg) > MAX_EVENT_SIZE:
            pass  # Handle oversized events
        s.send(encoded_msg)
        s.close()
    except socket.error as e:
        if e.errno == 111:
            raise ConnectionError("Wazuh must be running.")
        elif e.errno == 90:
            pass  # Message too long
        else:
            raise
```

> **Message header format:** `"1:<location>:<json_message>"`
> - `1` = event type indicator
> - `<location>` = identifies your integration (e.g., `Wazuh-AWS`, `virustotal`)

---

## 3. Deduplication: How to Avoid Sending Duplicate Data

This is the **most critical** and most frequently misimplemented aspect.

### Strategy A: State File with Last Timestamp/ID

```python
import json, os

STATE_FILE = "/var/ossec/var/run/custom_integration_state.json"

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {"last_timestamp": None, "last_event_id": None}

def save_state(state: dict):
    tmp_file = STATE_FILE + ".tmp"
    with open(tmp_file, 'w') as f:
        json.dump(state, f)
    os.replace(tmp_file, STATE_FILE)  # Atomic on POSIX
```

### Strategy B: Hash Set for Exact Duplicate Detection

```python
import hashlib, json, os

SEEN_FILE = "/var/ossec/var/run/custom_integration_seen.json"
MAX_SEEN = 10000

def compute_event_hash(event: dict) -> str:
    unique_payload = {
        "source": event.get("source"),
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
    }
    raw = json.dumps(unique_payload, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def is_duplicate(event: dict, seen: set) -> bool:
    h = compute_event_hash(event)
    if h in seen:
        return True
    seen.add(h)
    return False
```

### Strategy C: API Cursor with Pagination

```python
import requests

def fetch_with_cursor(api_url: str, headers: dict, state: dict) -> tuple:
    params = {"limit": 100, "order": "asc"}
    if state.get("next_cursor"):
        params["cursor"] = state["next_cursor"]
    elif state.get("last_timestamp"):
        params["since"] = state["last_timestamp"]

    response = requests.get(api_url, headers=headers, params=params)
    response.raise_for_status()
    data = response.json()
    return data.get("results", []), data.get("next_cursor")
```

### Strategy D: SQLite Database (Production-Grade)

This is **how Wazuh itself solves deduplication**. The `WazuhAWSDatabase` class in [`wodles/aws/wazuh_integration.py`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py#L394-L542) uses SQLite to track processed log files. The `AWSBucket` class in [`wodles/aws/buckets_s3/aws_bucket.py`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/buckets_s3/aws_bucket.py) queries the DB before processing each file:

```python
# Simplified from aws_bucket.py — the actual dedup query:
sql_already_processed = """
    SELECT count(*) FROM {table_name}
    WHERE bucket_path=:bucket_path
      AND aws_account_id=:aws_account_id
      AND aws_region=:aws_region
      AND log_key=:log_name;
"""
# If count > 0, skip the file. Otherwise, process and INSERT.
```

Reusable pattern for your own integrations:

```python
import sqlite3, os
from datetime import datetime, timezone, timedelta

class IntegrationDatabase:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL
            );""")
        self.conn.commit()

    def is_duplicate(self, event_id: str) -> bool:
        result = self.cursor.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return result is not None

    def mark_processed(self, event_id: str):
        self.cursor.execute(
            "INSERT OR IGNORE INTO processed_events (event_id, processed_at) VALUES (?, ?)",
            (event_id, datetime.now(timezone.utc).isoformat())
        )

    def cleanup(self, days: int = 90):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        self.cursor.execute("DELETE FROM processed_events WHERE processed_at < ?", (cutoff,))

    def close(self):
        self.conn.commit()
        self.cursor.execute("PRAGMA optimize;")
        self.conn.close()
```

### Strategy Comparison

| Strategy | Pros | Cons | Use When |
|---|---|---|---|
| **State file (timestamp/ID)** | Simple, low disk usage | May miss out-of-order events | API guarantees chronological order |
| **Hash set (JSON file)** | Detects exact duplicates | Doesn't scale past ~50K | Small-scale sources |
| **API cursor** | Most reliable, API-native | Depends on API support | Well-designed APIs |
| **SQLite database** | Scales to millions, ACID, queryable | Slightly more complex | Production integrations (how Wazuh does it) |

---

## 4. Wazuh Python Framework

Wazuh ships with its own Python interpreter and SDK at `/var/ossec/framework/python/`.

```bash
# Wazuh's bundled Python interpreter
/var/ossec/framework/python/bin/python3

# Framework modules
/var/ossec/framework/python/lib/python3.x/site-packages/wazuh/
```

### Key Capabilities

```python
#!/var/ossec/framework/python/bin/python3

from wazuh.core.common import WAZUH_PATH       # /var/ossec
from wazuh import agent
result = agent.get_agents(q="status=active")

from wazuh import rule
result = rule.get_rules(search={"value": "sshd", "negation": False})
```

### When to Use Framework vs. Standalone

| Aspect | Wazuh Framework | Standalone (system Python) |
|---|---|---|
| **Access to Wazuh config** | ✅ Direct via internal API | ❌ Must parse XML manually |
| **Agent information** | ✅ Native SDK | ⚠️ Via REST API |
| **Portability** | ❌ Manager only | ✅ Any machine |
| **External dependencies** | ⚠️ Limited | ✅ `pip install` anything |
| **Best for** | Integrations needing Wazuh internals | Polling external APIs |

---

## 5. Practical Use Cases

---

### Case 1: Wodle aws-s3 — AWS CloudTrail (Production Reference)

**Scenario:** Ingest AWS CloudTrail logs from an S3 bucket — the most common cloud integration.

**Method:** Wazuh's built-in `wodle name="aws-s3"` — a production-grade integration that demonstrates how Wazuh itself solves data ingestion at scale.

#### Why Study This Integration

Before building your own custom integration, it's worth understanding how Wazuh's AWS wodle works. It's the gold standard for how Wazuh ingests external data, and every pattern you need is here:

| Pattern | How Wazuh AWS Does It | Source File |
|---|---|---|
| **Event delivery** | UNIX socket direct to `analysisd` queue | [`wazuh_integration.py` → `send_msg()`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py#L293-L324) |
| **Deduplication** | SQLite DB — checks `already_processed()` before ingesting each log file | [`aws_bucket.py` → `already_processed()`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/buckets_s3/aws_bucket.py#L233-L239) |
| **State persistence** | SQLite `mark_complete()` with `DATETIME('now')` timestamps | [`aws_bucket.py` → `mark_complete()`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/buckets_s3/aws_bucket.py#L244-L254) |
| **DB maintenance** | Retains only last 500 records per region, deletes older entries | [`aws_bucket.py` → `db_maintenance()`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/buckets_s3/aws_bucket.py#L271-L281) |
| **Modular architecture** | Base class `WazuhIntegration` → `WazuhAWSDatabase` → per-service subclasses | [`wazuh_integration.py`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py) |
| **Oversized events** | Logs warning if event exceeds `MAX_EVENT_SIZE` (65,535 bytes) | [`utils.py` line 142](https://github.com/wazuh/wazuh/blob/master/wodles/utils.py#L142) |

#### Architecture

```
wodles/aws/
├── wazuh_integration.py      # Base: UNIX socket + SQLite
│   ├── WazuhIntegration      #   send_msg() → socket AF_UNIX
│   └── WazuhAWSDatabase      #   SQLite init/close/metadata
├── buckets_s3/
│   ├── aws_bucket.py          # AWSBucket: iter_files → dedup → send
│   ├── cloudtrail.py          # AWSCloudTrailBucket
│   ├── guardduty.py           # AWSGuardDutyBucket
│   ├── vpcflow.py             # AWSVPCFlowBucket
│   └── ...
├── services/
│   ├── inspector.py
│   └── cloudwatchlogs.py
└── aws_s3.py                  # Entry point (arg parsing + dispatch)
```

#### Configuration (ossec.conf)

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>30m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>no</skip_on_error>
  <bucket type="cloudtrail">
    <name>my-cloudtrail-bucket</name>
    <aws_profile>default</aws_profile>
    <!-- Optional filters -->
    <!-- <regions>us-east-1,eu-west-1</regions> -->
    <!-- <only_logs_after>2026-JAN-01</only_logs_after> -->
    <!-- <aws_account_id>123456789012</aws_account_id> -->
  </bucket>
</wodle>
```

Other supported bucket types: `guardduty`, `vpcflow`, `config`, `waf`, `alb`, `clb`, `nlb`, `server_access`, `cisco_umbrella`, `custom`.

#### Event Flow (What Happens Internally)

```
1. aws_s3.py parses args, selects AWSCloudTrailBucket class
2. iter_bucket() → init_db() creates SQLite table if not exists
3. iter_files_in_bucket() → list_objects_v2() on S3
4. For each log file:
   a. already_processed()? → SELECT count(*) FROM table WHERE log_key=:name
      - If yes → skip
   b. get_log_file() → download + decompress (gzip/zip)
   c. iter_events() → for each JSON event in "Records":
      - event_should_be_skipped()? → apply discard_regex
      - get_alert_msg() → wrap in {"integration":"aws", "aws":{...}}
      - send_msg() → UNIX socket to /var/ossec/queue/sockets/queue
   d. mark_complete() → INSERT INTO table (log_key, processed_date, ...)
5. db_maintenance() → DELETE old records beyond retention limit (500)
6. close_db() → COMMIT + PRAGMA optimize
```

#### What a CloudTrail Event Looks Like in Wazuh

```json
{
  "integration": "aws",
  "aws": {
    "log_info": {
      "aws_account_alias": "",
      "log_file": "AWSLogs/123456789012/CloudTrail/us-east-1/2026/04/14/..._CloudTrail_us-east-1_20260414T0000Z_abc.json.gz",
      "s3bucket": "my-cloudtrail-bucket"
    },
    "eventVersion": "1.08",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateUser",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.50",
    "userAgent": "console.amazonaws.com",
    "source": "cloudtrail",
    "aws_account_id": "123456789012"
  }
}
```

#### Applying This to Your Own Custom Integrations

If you're building a custom wodle that polls an external API, follow the same architecture:

1. **Use UNIX socket** instead of stdout (set `<ignore_output>yes</ignore_output>` in your wodle config)
2. **Use SQLite** for dedup state instead of JSON flat files (see Strategy D in Section 3)
3. **Build a message header** matching the protocol: `"1:My-Integration:<json>"`
4. **Implement DB maintenance** — don't let the state DB grow forever

> **📖 Official Docs & Source Code:**
> - [wodle `aws-s3` configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-s3.html)
> - [AWS CloudTrail integration guide](https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudtrail.html)
> - [AWS module considerations](https://documentation.wazuh.com/current/cloud-security/amazon/services/prerequisites/considerations.html)
> - **Source code:** [github.com/wazuh/wazuh/tree/master/wodles/aws](https://github.com/wazuh/wazuh/tree/master/wodles/aws)

---

### Case 2: Log Data Collection via Logcollector

**Scenario:** You have an application, tool, or script that writes log files to disk. You want Wazuh to monitor those files and ingest the events.

**Method:** Wazuh's **Log Data Collection** capability via the `<localfile>` configuration block. This is the simplest integration method — no custom script needed on the Wazuh side.

#### How It Works

```
┌─────────────────────┐     ┌───────────────────────────────┐     ┌──────────────┐
│ Your Application     │     │ Log file on disk               │     │ Wazuh Agent  │
│ or Script writes     │────▶│ /var/log/myapp/events.log      │────▶│ logcollector │
│ JSON lines to file   │     │ (one JSON object per line)     │     │ reads file   │
└─────────────────────┘     └───────────────────────────────┘     └──────┬───────┘
                                                                         │
                                                                ┌────────▼───────┐
                                                                │  analysisd     │
                                                                │  (auto-decode  │
                                                                │   JSON fields) │
                                                                └────────────────┘
```

#### Configuration

The only thing required is a `<localfile>` block in `ossec.conf` on the agent (or server):

```xml
<localfile>
  <location>/var/log/myapp/events.log</location>
  <log_format>json</log_format>
</localfile>
```

That's it. When `<log_format>` is set to `json`, Wazuh automatically:
1. Reads each new line from the file
2. Parses it as JSON
3. Makes all fields available for rule matching (e.g., `data.user`, `data.action`)

#### Supported Log Formats

| `log_format` value | Use for |
|---|---|
| `json` | JSON-formatted logs (one object per line) — **recommended for custom integrations** |
| `syslog` | Standard syslog format |
| `multi-line:N` | Logs where each event spans N lines |
| `eventchannel` | Windows Event Channel (Windows agents only) |
| `journald` | systemd journal (Linux) |
| `command` | Output of a command executed periodically |
| `full_command` | Full output of a command (entire output as one event) |

#### Common Configurations

**Monitor with wildcards:**
```xml
<localfile>
  <location>/var/log/myapp/*.log</location>
  <log_format>json</log_format>
</localfile>
```

**Date-based file names:**
```xml
<localfile>
  <location>/var/log/myapp/events-%Y-%m-%d.log</location>
  <log_format>json</log_format>
</localfile>
```

**Add labels for rule filtering:**
```xml
<localfile>
  <location>/var/log/myapp/events.log</location>
  <log_format>json</log_format>
  <label key="app_name">my-custom-app</label>
  <label key="environment">production</label>
</localfile>
```

#### If Your Script Writes the Log File

```python
import json, fcntl

OUTPUT_FILE = "/var/log/myapp/events.log"

def write_event(event: dict):
    """Write a single event to the log file with file locking."""
    line = json.dumps(event, separators=(',', ':'))
    with open(OUTPUT_FILE, 'a') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(line + '\n')
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
```

#### Log Rotation

```
# /etc/logrotate.d/myapp
/var/log/myapp/events.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate   # Required: truncate in place so logcollector keeps tracking
}
```

> **📖 Official Docs:**
> - [Log data collection overview](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html)
> - [`localfile` configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
> - [Monitoring log files](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html)

---

### Case 3: Reactive Integration via Integratord

**Scenario:** When Wazuh generates an alert, automatically react — enrich it, or send a notification.

**Method:** Integratord (`wazuh-integratord`) — a daemon that watches for alerts and executes your script.

#### How Integratord Works

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────────────┐
│  Alert       │────▶│  wazuh-integratord│────▶│  Your script             │
│  matches     │     │  writes alert to  │     │                          │
│  criteria    │     │  temp JSON file   │     │  argv[1] = alert file    │
│              │     │                   │     │  argv[2] = api_key       │
└─────────────┘     └──────────────────┘     │  argv[3] = hook_url      │
                                              └──────────────────────────┘
```

Wazuh ships with **two official integration scripts** that demonstrate two fundamentally different patterns. Both live in [`integrations/`](https://github.com/wazuh/wazuh/tree/master/integrations):

| Script | Pattern | Response Method |
|---|---|---|
| [`virustotal.py`](https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py) | **Enrich + re-inject** | UNIX socket back to `analysisd` |
| [`slack.py`](https://github.com/wazuh/wazuh/blob/master/integrations/slack.py) | **Notify externally** | HTTP POST to webhook |

---

#### 3A: VirusTotal (Enrich + Re-inject via UNIX Socket)

When Wazuh detects a file integrity change, query VirusTotal to check if the file is malicious, then **send the enriched alert back into Wazuh** for further rule processing.

**ossec.conf:**

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VT_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

**How it works** (from the [actual source code](https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py)):

1. `wazuh-integratord` detects an alert matching the `syscheck` group
2. Writes the alert JSON to a temp file
3. Calls: `virustotal.py <alert_file> <api_key> <hook_url> ...`
4. The script reads the alert, extracts the `md5_after` hash
5. Queries the VirusTotal API (`/vtapi/v2/file/report`)
6. Builds an enriched message:

```python
# From virustotal.py — the enriched output structure:
alert_output = {
    'integration': 'virustotal',
    'virustotal': {
        'found': 1,              # Was the hash in VT's database?
        'malicious': 1,          # Was it flagged as malicious?
        'positives': 15,         # How many engines detected it
        'total': 70,             # Total engines
        'sha1': '...',
        'permalink': 'https://www.virustotal.com/...',
        'source': {
            'alert_id': '...',
            'file': '/path/to/suspicious/file',
            'md5': '...',
            'sha1': '...',
        }
    }
}
```

7. **Sends it back to Wazuh via UNIX socket** (the key pattern):

```python
# From virustotal.py lines 317-333 — actual Wazuh code:

SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

def send_msg(msg, agent=None):
    # Build message with agent routing
    if not agent or agent['id'] == '000':
        string = '1:virustotal:{0}'.format(json.dumps(msg))
    else:
        # Include agent info so the enriched alert is associated
        # with the original agent
        location = '[{0}] ({1}) {2}'.format(
            agent['id'], agent['name'],
            agent['ip'] if 'ip' in agent else 'any'
        )
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->virustotal:{1}'.format(location, json.dumps(msg))

    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(string.encode())
    sock.close()
```

> **Key takeaway:** The enriched data goes back INTO Wazuh's analysis pipeline. You can then write rules that match on `virustotal.malicious`, `virustotal.positives`, etc.

> **📖 Official Docs & Source:**
> - [VirusTotal integration PoC](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html)
> - [Source: `integrations/virustotal.py`](https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py)

---

#### 3B: Slack (Notify Externally via HTTP POST)

When Wazuh generates a high-severity alert, send a formatted notification to a Slack channel. Data goes **out** of Wazuh — nothing comes back in.

**ossec.conf:**

```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/XXXXXX/XXXXXX/XXXXXXX</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

**How it works** (from the [actual source code](https://github.com/wazuh/wazuh/blob/master/integrations/slack.py)):

1. `wazuh-integratord` detects an alert with level ≥ 7
2. Calls: `slack.py <alert_file> <api_key> <hook_url> ...`
3. The script reads the alert and formats a Slack attachment:

```python
# From slack.py — message construction:
level = alert['rule']['level']

if level <= 4:
    color = 'good'       # green
elif level <= 7:
    color = 'warning'    # yellow
else:
    color = 'danger'     # red

msg = {
    'color': color,
    'pretext': 'WAZUH Alert',
    'title': alert['rule']['description'],
    'text': alert.get('full_log'),
    'fields': [
        {'title': 'Agent',    'value': f"({agent['id']}) - {agent['name']}"},
        {'title': 'Location', 'value': alert['location']},
        {'title': 'Rule ID',  'value': f"{alert['rule']['id']} _(Level {level})_"},
    ]
}

payload = {'attachments': [msg]}
```

4. **Sends it to Slack via HTTP POST** (simple and direct):

```python
# From slack.py lines 195-207 — actual Wazuh code:

def send_msg(msg, url):
    headers = {
        'content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    res = requests.post(url, data=msg, headers=headers, timeout=10)
```

> **Key takeaway:** Unlike VirusTotal, Slack is a one-way notification — no UNIX socket, no data re-injection. The script just POSTs and exits. Use this pattern for any outbound notification (PagerDuty, Teams, email APIs, ticketing systems, etc.).

> **📖 Official Docs & Source:**
> - [Integration configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
> - [wazuh-integratord daemon](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html)
> - [External API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
> - [Source: `integrations/slack.py`](https://github.com/wazuh/wazuh/blob/master/integrations/slack.py)

---

#### Building Your Own Custom Integration

Custom integratord scripts must:

1. **Be named with the `custom-` prefix** (e.g., `custom-myintegration`)
2. **Have no `.py` extension** and be **executable** (`chmod 750`)
3. **Be placed in** `/var/ossec/integrations/`
4. **Accept the standard argv contract:** `argv[1]=alert_file`, `argv[2]=api_key`, `argv[3]=hook_url`
5. Choose a response pattern:
   - **Enrich + re-inject** → send to UNIX socket (VirusTotal pattern)
   - **Notify externally** → HTTP POST (Slack pattern)
   - **Both** → combine both patterns in your script

```bash
chmod 750 /var/ossec/integrations/custom-myintegration
chown root:wazuh /var/ossec/integrations/custom-myintegration
```

> **📖 Source Code Reference:**
> - **Wazuh integrations directory:** [github.com/wazuh/wazuh/tree/master/integrations](https://github.com/wazuh/wazuh/tree/master/integrations)

---

### Case 4: Database Audit Ingestion (PostgreSQL)

**Scenario:** Query a PostgreSQL audit table every 10 minutes and inject change events.

**Method:** Wodle Command

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

import json, sys, os
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
    """Deduplication by auto-increment ID:
    Only queries records with ID > last processed."""
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, action, table_name, user_name,
                       old_data, new_data, executed_at
                FROM audit_log
                WHERE id > %s ORDER BY id ASC LIMIT %s
            """, (last_id, BATCH_SIZE))
            return cur.fetchall()
    finally:
        conn.close()


def transform_record(record: dict) -> dict:
    severity_map = {
        "INSERT": 3, "UPDATE": 5, "DELETE": 8,
        "TRUNCATE": 13, "ALTER": 13, "DROP": 15,
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
            "description": f"Database {action} on {record.get('table_name')} by {record.get('user_name')}",
        },
        "data": {
            "record_id": record.get("id"),
            "action": action,
            "table_name": record.get("table_name"),
            "db_user": record.get("user_name"),
            "changed_fields": changed_fields,
            "old_data": json.dumps(record["old_data"]) if record.get("old_data") else None,
            "new_data": json.dumps(record["new_data"]) if record.get("new_data") else None,
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
        print(json.dumps({
            "integration": INTEGRATION_NAME,
            "event_type": "integration_error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"error": str(e)}
        }, separators=(',', ':')))
        sys.exit(1)
```

> **📖 Official Docs:**
> - [Wodle Command configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)

---

## 6. Common Patterns and Best Practices

### Integration Checklist

- [ ] **Format:** Single-line JSON per event
- [ ] **`integration` field** for rule filtering
- [ ] **ISO 8601 timestamp** in every event
- [ ] **Deduplication** (state file, hash set, cursor, or SQLite)
- [ ] **Atomic state writes** (`.tmp` + `os.replace`)
- [ ] **Error handling** that does NOT pollute stdout
- [ ] **Timeouts** on all network connections
- [ ] **Log rotation** (if using logcollector)
- [ ] **Permissions:** `750`, owner `root:wazuh`
- [ ] **Secrets** in env vars, NEVER hardcoded
- [ ] **Matching rules XML** in `/var/ossec/etc/rules/`

### Common Mistakes to Avoid

| Mistake | Consequence | Solution |
|---|---|---|
| Multi-line JSON | Multiple broken events | `json.dumps(event, separators=(',',':'))` |
| Errors to stdout | Corrupt events ingested | Log to separate file, or use UNIX socket |
| No deduplication | Alert flooding | Implement state tracking from day one |
| Non-atomic state writes | Corruption on crash | `.tmp` + `os.replace()` |
| No HTTP timeout | Script hangs | `timeout=30` on every call |
| Events > 65,535 bytes | Silent truncation | Split or reduce payload |
| stdout for high-volume | Slower, less reliable | UNIX socket for production |

### Recommended Directory Structure

```
/var/ossec/
├── wodles/
│   └── aws/                               # Built-in AWS wodle (reference)
│       ├── wazuh_integration.py
│       ├── buckets_s3/
│       └── ...
├── integrations/
│   ├── virustotal.py                      # Built-in VT (reference)
│   ├── slack.py                           # Built-in Slack (reference)
│   ├── custom-myenrichment                # Your integratord scripts
│   └── custom-db-audit.py                 # Your wodle scripts
├── var/run/
│   └── db_audit_state.json                # State files
├── logs/
│   └── integrations.log                   # Integratord logs
└── etc/rules/
    └── custom-db-audit-rules.xml          # Your rules
```

---

## 7. Official Wazuh Documentation References

### Wodle aws-s3 (Case 1)

| Resource | URL |
|---|---|
| `wodle aws-s3` configuration reference | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-s3.html |
| AWS CloudTrail integration guide | https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudtrail.html |
| AWS module considerations | https://documentation.wazuh.com/current/cloud-security/amazon/services/prerequisites/considerations.html |

### Wodle Command (Case 4)

| Resource | URL |
|---|---|
| Wodle command configuration reference | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html |

### Logcollector / localfile (Case 2)

| Resource | URL |
|---|---|
| `localfile` configuration reference | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html |
| Log data collection overview | https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html |
| Monitoring log files | https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html |

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
| Event size limit (65,535 bytes) | https://github.com/wazuh/wazuh/issues/17689 |
| `MAX_EVENT_SIZE` in source | https://github.com/wazuh/wazuh/blob/master/wodles/utils.py#L142 |

### General

| Resource | URL |
|---|---|
| `ossec.conf` full reference index | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html |

### Wazuh Source Code References

| Component | URL | What to Learn |
|---|---|---|
| **AWS wodle** | https://github.com/wazuh/wazuh/tree/master/wodles/aws | UNIX socket, SQLite dedup, modular architecture |
| `wazuh_integration.py` | https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py | `send_msg()`, `WazuhAWSDatabase` |
| `aws_bucket.py` | https://github.com/wazuh/wazuh/blob/master/wodles/aws/buckets_s3/aws_bucket.py | `already_processed()`, `mark_complete()`, `db_maintenance()` |
| `utils.py` | https://github.com/wazuh/wazuh/blob/master/wodles/utils.py | `MAX_EVENT_SIZE`, `find_wazuh_path()` |
| **Integrations** | https://github.com/wazuh/wazuh/tree/master/integrations | Official integratord scripts |
| `virustotal.py` | https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py | Enrich + re-inject via socket |
| `slack.py` | https://github.com/wazuh/wazuh/blob/master/integrations/slack.py | Notify via HTTP POST |

---

## License

This documentation is provided as-is for educational and operational purposes.
