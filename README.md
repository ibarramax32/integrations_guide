# Wazuh Custom Integration Scripts — Complete Guide (v2)

> **How to format data for Wazuh, avoid sending duplicates, and build production-ready integration scripts — with real-world patterns extracted from Wazuh's own source code.**

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
  - [Strategy D: SQLite Database (Production-Grade)](#strategy-d-sqlite-database-production-grade)
  - [Strategy Comparison](#strategy-comparison)
- [4. Wazuh Python Framework](#4-wazuh-python-framework)
  - [Location and Usage](#location-and-usage)
  - [Key Capabilities](#key-capabilities)
  - [When to Use the Framework vs. Standalone Scripts](#when-to-use-the-framework-vs-standalone-scripts)
- [5. Practical Use Cases](#5-practical-use-cases)
  - [Case 1: Wodle Command + UNIX Socket + SQLite (AWS-Style Integration)](#case-1-wodle-command--unix-socket--sqlite-aws-style-integration)
  - [Case 2: Log Data Collection via Logcollector](#case-2-log-data-collection-via-logcollector)
  - [Case 3: Reactive Integration via Integratord (VirusTotal + Slack)](#case-3-reactive-integration-via-integratord-virustotal--slack)
  - [Case 4: Database Audit Ingestion (PostgreSQL)](#case-4-database-audit-ingestion-postgresql)
- [6. Common Patterns and Best Practices](#6-common-patterns-and-best-practices)
  - [Integration Checklist](#integration-checklist)
  - [Common Mistakes to Avoid](#common-mistakes-to-avoid)
  - [Recommended Directory Structure](#recommended-directory-structure)
- [7. Official Wazuh Documentation References](#7-official-wazuh-documentation-references)

---

## 1. Data Ingestion Architecture

### How Does Wazuh Receive Data?

Wazuh processes data through its **analysis engine (analysisd)**. There are several paths for injecting custom data:

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────────────┐
│ External Source  │────▶│  Custom Script    │────▶│  Wazuh Input             │
│ (API, DB, file)  │     │  (Python/Bash)    │     │                          │
└─────────────────┘     └──────────────────┘     │  Option A: Wodle Command  │
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
| **Wodle Command** | `ossec.conf` runs your script on a schedule; output via stdout or UNIX socket | Polling APIs, DB queries, heavy integrations |
| **Logcollector** | Wazuh reads a log file your script or application writes to | Monitoring application logs, third-party tools output |
| **Integratord** | Wazuh's native integration framework triggered by alerts | Reactive enrichment (post-alert), notifications |
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
| 5 | **Do not exceed 65,535 bytes per event** | Hard-coded max in `analysisd` ([`MAX_EVENT_SIZE = 65535`](https://github.com/wazuh/wazuh/blob/master/wodles/utils.py#L142)). Events exceeding this are truncated silently. |

### Writing Output from Your Script

There are **two methods** for sending events to Wazuh from a custom script:

#### Method 1: stdout (Simple — Wodle captures output)

```python
import json
import sys

def send_event_stdout(event: dict):
    """Send an event to stdout — captured by Wazuh wodle command."""
    line = json.dumps(event, separators=(',', ':'))
    print(line)
    sys.stdout.flush()
```

#### Method 2: UNIX Socket (Production — Direct to analysisd queue)

This is how Wazuh's own AWS integration sends events. It writes directly to the `analysisd` UNIX socket at `/var/ossec/queue/sockets/queue`, bypassing stdout entirely. This is faster, more reliable, and what Wazuh uses in production.

Extracted from [`wodles/aws/wazuh_integration.py`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py#L293-L324):

```python
import json
import socket

WAZUH_PATH = "/var/ossec"
WAZUH_QUEUE = f"{WAZUH_PATH}/queue/sockets/queue"
MAX_EVENT_SIZE = 65535
MESSAGE_HEADER = "1:Wazuh-Custom:"  # Format: "1:<location>:"

def send_event_socket(event: dict):
    """Send an event directly to the analysisd UNIX socket.

    This is the production method used by Wazuh's own integrations
    (AWS, Azure, Docker, etc.). It bypasses stdout and writes
    directly to the analysis queue.
    """
    try:
        json_msg = json.dumps(event, default=str)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(WAZUH_QUEUE)
        encoded_msg = f"{MESSAGE_HEADER}{json_msg}".encode()

        if len(encoded_msg) > MAX_EVENT_SIZE:
            # Log warning — event will be truncated by analysisd
            pass  # Handle oversized events (split or reduce payload)

        s.send(encoded_msg)
        s.close()
    except socket.error as e:
        if e.errno == 111:
            raise ConnectionError("Wazuh must be running.")
        elif e.errno == 90:
            pass  # Message too long — consider increasing rmem_max
        else:
            raise
```

> **Message header format:** `"1:<location>:<json_message>"`
> - The `1` is the event type indicator
> - `<location>` identifies your integration (e.g., `Wazuh-AWS`, `virustotal`, or your custom name)
> - This is how `analysisd` knows where the event originated

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

### Strategy D: SQLite Database (Production-Grade)

This is **how Wazuh itself solves deduplication** in its AWS integration. Instead of JSON flat files, it uses a SQLite database to track which log files and markers have already been processed. This approach scales to hundreds of thousands of records without memory issues.

Extracted from [`wodles/aws/wazuh_integration.py`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py#L394-L542) — the `WazuhAWSDatabase` class:

```python
import sqlite3
import os

WAZUH_WODLE_PATH = "/var/ossec/wodles/my_integration"

class IntegrationDatabase:
    """
    SQLite-based deduplication following the same pattern as
    Wazuh's AWS integration (WazuhAWSDatabase class).

    The DB file lives alongside your wodle, and tracks:
    - Which items have been processed
    - A metadata table with the integration version
    """

    SQL_CREATE_TABLE = """
        CREATE TABLE IF NOT EXISTS processed_events (
            event_id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            processed_at TEXT NOT NULL
        );
    """
    SQL_CREATE_METADATA = """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (key, value)
        );
    """
    SQL_CHECK_EVENT = "SELECT 1 FROM processed_events WHERE event_id = :event_id;"
    SQL_INSERT_EVENT = """
        INSERT OR IGNORE INTO processed_events (event_id, source, processed_at)
        VALUES (:event_id, :source, :processed_at);
    """
    SQL_CLEANUP_OLD = """
        DELETE FROM processed_events
        WHERE processed_at < :cutoff_date;
    """
    SQL_OPTIMIZE = "PRAGMA optimize;"

    def __init__(self, db_name: str):
        self.db_path = os.path.join(WAZUH_WODLE_PATH, f"{db_name}.db")
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        self.cursor.execute(self.SQL_CREATE_TABLE)
        self.cursor.execute(self.SQL_CREATE_METADATA)
        self.conn.commit()

    def is_duplicate(self, event_id: str) -> bool:
        """Check if an event has already been processed."""
        result = self.cursor.execute(
            self.SQL_CHECK_EVENT, {"event_id": event_id}
        ).fetchone()
        return result is not None

    def mark_processed(self, event_id: str, source: str):
        """Mark an event as processed."""
        from datetime import datetime, timezone
        self.cursor.execute(self.SQL_INSERT_EVENT, {
            "event_id": event_id,
            "source": source,
            "processed_at": datetime.now(timezone.utc).isoformat()
        })

    def cleanup(self, days_to_keep: int = 30):
        """Remove records older than N days to prevent unbounded growth."""
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days_to_keep)).isoformat()
        self.cursor.execute(self.SQL_CLEANUP_OLD, {"cutoff_date": cutoff})

    def close(self):
        """Commit, optimize, and close — same pattern as WazuhAWSDatabase."""
        self.conn.commit()
        self.cursor.execute(self.SQL_OPTIMIZE)
        self.conn.close()
```

### Strategy Comparison

| Strategy | Pros | Cons | Use When |
|---|---|---|---|
| **State file (timestamp/ID)** | Simple, low disk usage | May miss events arriving out of order | API guarantees chronological order |
| **Hash set (JSON file)** | Detects exact duplicates regardless of order | Higher memory/disk, doesn't scale past ~50K | Small-scale sources without ordering |
| **API cursor** | Most reliable, API-native | Depends on API support | Well-designed APIs (most modern ones) |
| **SQLite database** | Scales to millions of records, ACID guarantees, queryable | Slightly more complex setup | Production integrations (how Wazuh does it) |

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

### Case 1: Wodle Command + UNIX Socket + SQLite (AWS-Style Integration)

**Scenario:** Build a production-grade integration that polls an external API, deduplicates via SQLite, and sends events directly to the analysisd UNIX socket — following the exact same architecture as Wazuh's own `wodles/aws/` integration.

**Method:** Wodle Command

**Why this pattern?** This is how Wazuh itself ingests AWS CloudTrail, GuardDuty, VPC Flow Logs, and more. By studying [`wodles/aws/wazuh_integration.py`](https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py), we can see the three production-grade patterns:

1. **UNIX socket** (`socket.AF_UNIX, socket.SOCK_DGRAM`) instead of stdout — direct write to the analysis queue
2. **SQLite** for deduplication state — instead of JSON flat files
3. **Modular architecture** — base class + per-source subclasses

#### Architecture Overview (from Wazuh's AWS wodle)

```
wodles/aws/
├── wazuh_integration.py    # Base class: WazuhIntegration (socket + SQLite)
│   ├── send_msg()          # UNIX socket write to /var/ossec/queue/sockets/queue
│   ├── WazuhAWSDatabase    # SQLite dedup (inherits WazuhIntegration)
│   │   ├── init_db()
│   │   ├── close_db()      # commit + PRAGMA optimize
│   │   └── check_metadata_version()
├── buckets_s3/
│   ├── aws_bucket.py       # AWSBucket → per-source implementations
│   ├── cloudtrail.py       # AWSCloudTrailBucket
│   ├── guardduty.py        # AWSGuardDutyBucket
│   ├── vpcflow.py          # AWSVPCFlowBucket
│   └── ...
├── services/
│   ├── inspector.py
│   └── cloudwatchlogs.py
└── aws_s3.py               # Entry point (argument parsing + dispatch)
```

#### ossec.conf Configuration

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>custom-threat-intel</tag>
  <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/custom-threat-intel/main.py</command>
  <interval>5m</interval>
  <ignore_output>yes</ignore_output>  <!-- stdout not needed: we use the socket -->
  <run_on_start>yes</run_on_start>
  <timeout>120</timeout>
</wodle>
```

> **Key difference from Case 2-4:** `<ignore_output>yes</ignore_output>` — since events go through the UNIX socket, we don't need wodle to capture stdout.

#### Full Script

```python
#!/var/ossec/framework/python/bin/python3
"""
Custom integration: Threat Intelligence Feed -> Wazuh
Location: /var/ossec/wodles/custom-threat-intel/main.py
Method: Wodle Command + UNIX Socket + SQLite

Architecture modeled after Wazuh's own wodles/aws/ integration:
- UNIX socket for event delivery (not stdout)
- SQLite for deduplication state (not JSON files)
- Message header format matching analysisd expectations

Source reference:
  https://github.com/wazuh/wazuh/tree/master/wodles/aws
"""

import json
import os
import sys
import socket
import sqlite3
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: requests module is required.")
    sys.exit(1)

# ── Configuration ──
API_URL = "https://api.threatfeed.example.com/v1/indicators"
API_KEY = os.environ.get("THREAT_INTEL_API_KEY", "")

# Paths — following Wazuh conventions
WAZUH_PATH = "/var/ossec"
WAZUH_QUEUE = os.path.join(WAZUH_PATH, "queue", "sockets", "queue")
WODLE_PATH = os.path.join(WAZUH_PATH, "wodles", "custom-threat-intel")
DB_PATH = os.path.join(WODLE_PATH, "threat_intel.db")
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "custom-threat-intel.log")

# Message header: "1:<location>:<json>"
# This matches the protocol analysisd expects on the UNIX socket.
# See: wazuh_integration.py line 38 → MESSAGE_HEADER = "1:Wazuh-AWS:"
MESSAGE_HEADER = "1:custom-threat-intel:"

# Max event size: 65535 bytes (from wodles/utils.py line 142)
MAX_EVENT_SIZE = 65535

INTEGRATION_NAME = "custom-threat-intel"


# ══════════════════════════════════════════════════════
# Logging — never pollute stdout
# ══════════════════════════════════════════════════════
def log(level: str, message: str):
    ts = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, 'a') as f:
        f.write(f"{ts} [{level.upper()}] {message}\n")


# ══════════════════════════════════════════════════════
# UNIX Socket delivery (from WazuhIntegration.send_msg)
# ══════════════════════════════════════════════════════
def send_event(event: dict):
    """Send event directly to analysisd via UNIX socket.

    This replicates the pattern from wazuh_integration.py send_msg():
    - AF_UNIX + SOCK_DGRAM
    - Message format: "1:<location>:<json>"
    - Error handling for errno 111 (Wazuh not running) and 90 (message too long)
    """
    try:
        json_msg = json.dumps(event, default=str)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(WAZUH_QUEUE)
        encoded_msg = f"{MESSAGE_HEADER}{json_msg}".encode()

        if len(encoded_msg) > MAX_EVENT_SIZE:
            log("warn", f"Event size {len(encoded_msg)} exceeds max {MAX_EVENT_SIZE}")

        s.send(encoded_msg)
        s.close()
    except socket.error as e:
        if e.errno == 111:
            log("error", "Wazuh must be running (errno 111)")
            sys.exit(11)
        elif e.errno == 90:
            log("error", "Message too long for socket buffer. Skipping.")
        else:
            log("error", f"Socket error: {e}")
            sys.exit(13)


# ══════════════════════════════════════════════════════
# SQLite deduplication (from WazuhAWSDatabase pattern)
# ══════════════════════════════════════════════════════
class ThreatIntelDB:
    """SQLite-based state tracking, modeled after WazuhAWSDatabase.

    Key patterns from the source:
    - metadata table for version tracking
    - PRAGMA optimize on close
    - Table existence checks before creation
    """

    SQL_CREATE_PROCESSED = """
        CREATE TABLE IF NOT EXISTS processed_indicators (
            indicator_id TEXT PRIMARY KEY,
            indicator_value TEXT NOT NULL,
            processed_at TEXT NOT NULL
        );
    """
    SQL_CREATE_METADATA = """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (key, value)
        );
    """
    SQL_CREATE_CURSOR = """
        CREATE TABLE IF NOT EXISTS api_cursor (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_timestamp TEXT,
            next_cursor TEXT
        );
    """

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        self.cursor.execute(self.SQL_CREATE_PROCESSED)
        self.cursor.execute(self.SQL_CREATE_METADATA)
        self.cursor.execute(self.SQL_CREATE_CURSOR)
        # Initialize cursor row if not exists
        self.cursor.execute(
            "INSERT OR IGNORE INTO api_cursor (id, last_timestamp, next_cursor) VALUES (1, NULL, NULL)"
        )
        self.conn.commit()

    def is_duplicate(self, indicator_id: str) -> bool:
        result = self.cursor.execute(
            "SELECT 1 FROM processed_indicators WHERE indicator_id = ?",
            (indicator_id,)
        ).fetchone()
        return result is not None

    def mark_processed(self, indicator_id: str, indicator_value: str):
        self.cursor.execute(
            "INSERT OR IGNORE INTO processed_indicators (indicator_id, indicator_value, processed_at) "
            "VALUES (?, ?, ?)",
            (indicator_id, indicator_value, datetime.now(timezone.utc).isoformat())
        )

    def get_cursor_state(self) -> dict:
        row = self.cursor.execute(
            "SELECT last_timestamp, next_cursor FROM api_cursor WHERE id = 1"
        ).fetchone()
        return {"last_timestamp": row[0], "next_cursor": row[1]} if row else {}

    def save_cursor_state(self, last_timestamp: str = None, next_cursor: str = None):
        self.cursor.execute(
            "UPDATE api_cursor SET last_timestamp = ?, next_cursor = ? WHERE id = 1",
            (last_timestamp, next_cursor)
        )

    def cleanup(self, days: int = 90):
        """Prevent unbounded DB growth."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        self.cursor.execute(
            "DELETE FROM processed_indicators WHERE processed_at < ?", (cutoff,)
        )

    def close(self):
        """Commit, optimize, close — same as WazuhAWSDatabase.close_db()."""
        self.conn.commit()
        self.cursor.execute("PRAGMA optimize;")
        self.conn.close()


# ══════════════════════════════════════════════════════
# API Fetch
# ══════════════════════════════════════════════════════
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


# ══════════════════════════════════════════════════════
# Transformation
# ══════════════════════════════════════════════════════
def transform_indicator(indicator: dict) -> dict:
    severity_map = {"low": 3, "medium": 7, "high": 10, "critical": 13}

    return {
        "integration": INTEGRATION_NAME,
        "source": "threat-intel-feed",
        "event_type": "ioc",
        "timestamp": indicator.get("created_at",
                                   datetime.now(timezone.utc).isoformat()),
        "alert": {
            "severity": severity_map.get(indicator.get("severity", "low"), 3),
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


# ══════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════
def main():
    log("info", "Starting threat intel collection")

    db = ThreatIntelDB()
    state = db.get_cursor_state()
    total_new = 0
    total_dup = 0

    try:
        while True:
            indicators, next_cursor = fetch_indicators(state)

            if not indicators:
                break

            for indicator in indicators:
                ioc_id = str(indicator.get("id", ""))
                if db.is_duplicate(ioc_id):
                    total_dup += 1
                    continue

                event = transform_indicator(indicator)
                send_event(event)
                db.mark_processed(ioc_id, indicator.get("value", ""))
                total_new += 1

            # Update cursor for next page/execution
            last = indicators[-1]
            state["last_timestamp"] = last.get("created_at")
            state["next_cursor"] = next_cursor
            db.save_cursor_state(state["last_timestamp"], state["next_cursor"])

            if not next_cursor:
                break

        # Periodic cleanup
        db.cleanup(days=90)

    finally:
        db.close()

    log("info", f"Finished: {total_new} new events, {total_dup} duplicates skipped")


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
    <description>CRITICAL threat indicator: $(data.ioc_type) - $(data.ioc_value)</description>
    <group>threat_intel,ioc,critical,</group>
    <options>alert_by_email</options>
  </rule>

</group>
```

> **📖 Official Docs & Source Code:**
> - [Wodle Command configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
> - [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
> - [Custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
> - **Wazuh AWS wodle source code:** [github.com/wazuh/wazuh/tree/master/wodles/aws](https://github.com/wazuh/wazuh/tree/master/wodles/aws)

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
<!-- Monitor a JSON log file -->
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
<!-- Monitor all .log files in a directory -->
<localfile>
  <location>/var/log/myapp/*.log</location>
  <log_format>json</log_format>
</localfile>
```

**Monitor with date-based file names:**
```xml
<!-- File name changes daily -->
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

**Monitor a non-JSON log with syslog format:**
```xml
<localfile>
  <location>/var/log/legacy-app/output.log</location>
  <log_format>syslog</log_format>
</localfile>
```

#### If Your Script Writes the Log File

When your custom script generates the log data, follow these rules:

```python
import json
import fcntl

OUTPUT_FILE = "/var/log/myapp/events.log"

def write_event(event: dict):
    """Write a single event to the log file.

    Rules:
    - One JSON object per line (no newlines inside JSON)
    - Use file locking to prevent partial writes
    - Wazuh's logcollector handles reading — you just write
    """
    line = json.dumps(event, separators=(',', ':'))
    with open(OUTPUT_FILE, 'a') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(line + '\n')
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
```

#### Log Rotation

Since the file grows continuously, configure log rotation:

```
# /etc/logrotate.d/myapp
/var/log/myapp/events.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate   # Required: don't move the file, truncate in place
}
```

> **Important:** Use `copytruncate` instead of the default rotate behavior. This ensures Wazuh's logcollector doesn't lose track of the file descriptor.

> **📖 Official Docs:**
> - [Log data collection overview](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html)
> - [`localfile` configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
> - [Monitoring log files](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html)

---

### Case 3: Reactive Integration via Integratord (VirusTotal + Slack)

**Scenario:** When Wazuh generates an alert, automatically react — enrich it with VirusTotal data, or send a notification to Slack.

**Method:** Integratord (Wazuh's built-in integration daemon)

#### How Integratord Works

Integratord is a daemon (`wazuh-integratord`) that watches for alerts matching your criteria and executes your integration script. The contract is:

```
┌─────────────┐     ┌──────────────────┐     ┌────────────────────────┐
│  Alert       │────▶│  wazuh-integratord│────▶│  Your script           │
│  matches     │     │  writes alert to  │     │                        │
│  criteria    │     │  temp JSON file   │     │  argv[1] = alert file  │
│              │     │                   │     │  argv[2] = api_key     │
│              │     │                   │     │  argv[3] = hook_url    │
│              │     │                   │     │  argv[4] = alert_format│
└─────────────┘     └──────────────────┘     └───────────┬────────────┘
                                                          │
                                              ┌───────────▼────────────┐
                                              │  Script response:      │
                                              │                        │
                                              │  Option A: Send to     │
                                              │  UNIX socket (VT-style)│
                                              │                        │
                                              │  Option B: POST to     │
                                              │  webhook (Slack-style) │
                                              └────────────────────────┘
```

#### The Two Patterns in Wazuh's Official Integrations

Wazuh ships with two integration scripts that demonstrate two fundamentally different response patterns. Both live in [`integrations/`](https://github.com/wazuh/wazuh/tree/master/integrations):

| Script | Pattern | What It Does | Response Method |
|---|---|---|---|
| [`virustotal.py`](https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py) | **Enrich + re-inject** | Queries VT API, builds enriched alert, sends back to Wazuh | **UNIX socket** to analysisd |
| [`slack.py`](https://github.com/wazuh/wazuh/blob/master/integrations/slack.py) | **Notify externally** | Formats alert as Slack attachment, POSTs to webhook | **HTTP POST** to Slack API |

#### Pattern A: Enrich + Re-inject (VirusTotal Style)

From [`integrations/virustotal.py`](https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py):

**ossec.conf:**
```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VT_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

**Key code — how `virustotal.py` sends enriched data back via UNIX socket:**

```python
# From integrations/virustotal.py lines 317-333
# This is the actual Wazuh production code:

SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

def send_msg(msg, agent=None):
    # Build the message with location routing
    if not agent or agent['id'] == '000':
        string = '1:virustotal:{0}'.format(json.dumps(msg))
    else:
        # Include agent info for proper alert routing
        location = '[{0}] ({1}) {2}'.format(
            agent['id'], agent['name'],
            agent['ip'] if 'ip' in agent else 'any'
        )
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->virustotal:{1}'.format(location, json.dumps(msg))

    # Send via UNIX socket
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(string.encode())
    sock.close()
```

> **Important detail:** Notice the message header includes agent routing information (`[agent_id] (agent_name) agent_ip->virustotal`). This ensures the enriched alert is correctly associated with the original agent.

#### Pattern B: External Notification (Slack Style)

From [`integrations/slack.py`](https://github.com/wazuh/wazuh/blob/master/integrations/slack.py):

**ossec.conf:**
```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/XXXXXX/XXXXXX/XXXXXXX</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

**Key code — how `slack.py` sends notifications via HTTP:**

```python
# From integrations/slack.py lines 195-207
# Slack doesn't send data back to Wazuh — it sends OUT to Slack

def send_msg(msg, url):
    headers = {
        'content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    res = requests.post(url, data=msg, headers=headers, timeout=10)
```

#### Custom Integration Example (Combining Both Patterns)

Here's a custom integration that enriches with VirusTotal AND notifies Slack:

**ossec.conf:**
```xml
<integration>
  <name>custom-vt-slack</name>
  <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
  <api_key>YOUR_VT_API_KEY</api_key>
  <level>7</level>
  <rule_id>550,554</rule_id>
  <alert_format>json</alert_format>
</integration>
```

**Script:**

```python
#!/var/ossec/framework/python/bin/python3
"""
Custom integration: VirusTotal enrichment + Slack notification
Location: /var/ossec/integrations/custom-vt-slack
(no .py extension, must be executable)

Combines both official integration patterns:
- virustotal.py: query API + send enriched data back via UNIX socket
- slack.py: format alert + POST to webhook

Source references:
  https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py
  https://github.com/wazuh/wazuh/blob/master/integrations/slack.py
"""

import json
import os
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket

try:
    import requests
except ImportError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

debug_enabled = False


def debug(msg: str):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def read_alert(alert_file: str) -> dict:
    with open(alert_file, 'r') as f:
        return json.load(f)


def extract_hash(alert: dict) -> str:
    syscheck = alert.get("syscheck", {})
    for field in ["sha256_after", "sha1_after", "md5_after"]:
        h = syscheck.get(field)
        if h:
            return h
    return None


def query_virustotal(file_hash: str, api_key: str) -> dict:
    params = {'apikey': api_key, 'resource': file_hash}
    headers = {'Accept-Encoding': 'gzip, deflate'}
    try:
        resp = requests.get(
            'https://www.virustotal.com/vtapi/v2/file/report',
            params=params, headers=headers, timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
        return {"response_code": -1, "error": f"HTTP {resp.status_code}"}
    except requests.RequestException as e:
        return {"response_code": -1, "error": str(e)}


def send_to_wazuh(msg: dict, agent: dict = None):
    """Send enriched alert back to Wazuh via UNIX socket.
    Follows the same pattern as integrations/virustotal.py send_msg().
    """
    if not agent or agent.get('id') == '000':
        string = '1:custom-vt-slack:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(
            agent['id'], agent['name'],
            agent.get('ip', 'any')
        )
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->custom-vt-slack:{1}'.format(location, json.dumps(msg))

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        debug(f'# Error sending to socket: {e}')


def send_to_slack(alert: dict, vt_data: dict, webhook_url: str):
    """Send notification to Slack.
    Follows the same pattern as integrations/slack.py send_msg().
    """
    positives = vt_data.get('positives', 0)
    total = vt_data.get('total', 0)
    file_path = alert.get('syscheck', {}).get('path', 'N/A')

    color = 'danger' if positives > 5 else ('warning' if positives > 0 else 'good')

    payload = {
        "attachments": [{
            "color": color,
            "pretext": "WAZUH - VirusTotal File Analysis",
            "title": f"File: {file_path}",
            "text": f"VirusTotal: {positives}/{total} engines detected this file",
            "fields": [
                {"title": "Agent", "value": alert.get('agent', {}).get('name', 'N/A'), "short": True},
                {"title": "Rule", "value": alert.get('rule', {}).get('description', 'N/A'), "short": True},
                {"title": "VT Link", "value": vt_data.get('permalink', 'N/A')},
            ]
        }]
    }

    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    try:
        requests.post(webhook_url, data=json.dumps(payload), headers=headers, timeout=10)
    except requests.RequestException as e:
        debug(f'# Error sending to Slack: {e}')


def main():
    global debug_enabled

    if len(sys.argv) < 4:
        debug('# Error: bad arguments')
        sys.exit(2)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    webhook_url = sys.argv[3]
    debug_enabled = len(sys.argv) > 4 and sys.argv[4] == 'debug'

    alert = read_alert(alert_file)
    file_hash = extract_hash(alert)

    if not file_hash:
        debug('# No hash found in alert')
        return

    # 1. Query VirusTotal
    vt_data = query_virustotal(file_hash, api_key)

    # 2. Build enriched alert and send back to Wazuh (Pattern A)
    enriched = {
        'integration': 'custom-vt-slack',
        'virustotal': {
            'found': 1 if vt_data.get('response_code', 0) == 1 else 0,
            'positives': vt_data.get('positives', 0),
            'total': vt_data.get('total', 0),
            'permalink': vt_data.get('permalink', ''),
            'source': {
                'file': alert.get('syscheck', {}).get('path'),
                'md5': alert.get('syscheck', {}).get('md5_after'),
                'alert_id': alert.get('id'),
            }
        }
    }
    send_to_wazuh(enriched, alert.get('agent'))

    # 3. Notify Slack (Pattern B)
    if vt_data.get('positives', 0) > 0:
        send_to_slack(alert, vt_data, webhook_url)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        debug(str(e))
        raise
```

#### Required Permissions

```bash
chmod 750 /var/ossec/integrations/custom-vt-slack
chown root:wazuh /var/ossec/integrations/custom-vt-slack
```

> **📖 Official Docs & Source Code:**
> - [Integration configuration reference (ossec.conf)](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
> - [wazuh-integratord daemon](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html)
> - [External API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
> - [VirusTotal integration PoC](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html)
> - **Wazuh integrations source code:** [github.com/wazuh/wazuh/tree/master/integrations](https://github.com/wazuh/wazuh/tree/master/integrations)
>   - [`virustotal.py`](https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py) — Enrich + UNIX socket pattern
>   - [`slack.py`](https://github.com/wazuh/wazuh/blob/master/integrations/slack.py) — Notify + HTTP POST pattern

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
- [ ] **`data.integration` field** included for rule filtering
- [ ] **ISO 8601 timestamp** in every event
- [ ] **Deduplication mechanism** (state file, hash set, cursor, or SQLite)
- [ ] **Error handling** that does NOT pollute stdout (or use UNIX socket)
- [ ] **Timeouts** on all network connections
- [ ] **Log rotation** on the output file (if using logcollector)
- [ ] **Permissions:** `750` for scripts, owner `root:wazuh`
- [ ] **Sensitive variables** in env vars, NEVER hardcoded
- [ ] **Matching rules XML** in `/var/ossec/etc/rules/`

### Common Mistakes to Avoid

| Mistake | Consequence | Solution |
|---|---|---|
| Multi-line JSON | Wazuh interprets it as multiple broken events | `json.dumps(event, separators=(',',':'))` |
| Printing errors to stdout | Error messages are ingested as corrupt events | Log errors to a separate file, or use UNIX socket delivery |
| No deduplication | Alert flooding, disk fills up | Implement state tracking from day one |
| No timeout on HTTP requests | Script hangs, wodle kills it via global timeout | `timeout=30` on every HTTP call |
| Events > 65,535 bytes | Silently truncated by `analysisd` | Split large events or reduce payload |
| Using stdout when socket is better | Slower, depends on wodle capturing output | Use UNIX socket for high-volume integrations |

### Recommended Directory Structure

```
/var/ossec/
├── wodles/
│   └── custom-threat-intel/            # Wodle-based integrations
│       ├── main.py                     #   (like wodles/aws/)
│       └── threat_intel.db             #   SQLite state
├── integrations/
│   ├── custom-vt-slack                 # Integratord scripts (no extension)
│   └── custom-db-audit.py
└── etc/rules/
    ├── custom-threat-intel-rules.xml   # Rules per integration
    └── custom-db-audit-rules.xml
```

---

## 7. Official Wazuh Documentation References

All technical claims in this guide have been verified against official Wazuh documentation and source code.

### Wodle Command (Cases 1 & 4)

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
| `MAX_EVENT_SIZE` constant in source | https://github.com/wazuh/wazuh/blob/master/wodles/utils.py#L142 |

### General

| Resource | URL |
|---|---|
| `ossec.conf` full reference index | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html |

### Wazuh Source Code References

| Component | URL | What to Learn |
|---|---|---|
| **AWS wodle** | https://github.com/wazuh/wazuh/tree/master/wodles/aws | UNIX socket delivery, SQLite dedup, modular architecture |
| `wazuh_integration.py` | https://github.com/wazuh/wazuh/blob/master/wodles/aws/wazuh_integration.py | `send_msg()` socket pattern, `WazuhAWSDatabase` class |
| `utils.py` | https://github.com/wazuh/wazuh/blob/master/wodles/utils.py | `MAX_EVENT_SIZE`, `find_wazuh_path()` |
| **Integrations** | https://github.com/wazuh/wazuh/tree/master/integrations | Official integratord scripts |
| `virustotal.py` | https://github.com/wazuh/wazuh/blob/master/integrations/virustotal.py | Enrich + re-inject via socket pattern |
| `slack.py` | https://github.com/wazuh/wazuh/blob/master/integrations/slack.py | Notify via HTTP POST pattern |

---

## License

This documentation is provided as-is for educational and operational purposes.
