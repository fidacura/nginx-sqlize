# nginx-sqlize

A tool for importing Nginx logs into SQLite for flexible querying and analysis.

## 📥 Installation

```bash
# clone the repo
git clone https://github.com/fidacura/nginx-sqlize.git
cd nginx-sqlize

# create a venv
python -m venv venv
source venv/bin/activate

# install packages
pip install -e .
```

## 🔎 Quick Reference

| Category      | Command          | Description                   | Example                                                                |
| ------------- | ---------------- | ----------------------------- | ---------------------------------------------------------------------- |
| **Ingestion** | `ingest`         | Import logs into SQLite       | `nginx-sqlize ingest --logs=/var/log/nginx/access.log*`                |
| **Info**      | `info`           | Show database information     | `nginx-sqlize info --db=nginx_logs.db --status`                        |
| **Traffic**   | `top-paths`      | Show most requested URLs      | `nginx-sqlize top-paths --db=nginx_logs.db`                            |
| **Traffic**   | `top-ips`        | Show most active IPs          | `nginx-sqlize top-ips --db=nginx_logs.db`                              |
| **Traffic**   | `status-codes`   | Show HTTP status distribution | `nginx-sqlize status-codes --db=nginx_logs.db`                         |
| **Traffic**   | `methods`        | Show HTTP method usage        | `nginx-sqlize methods --db=nginx_logs.db`                              |
| **Traffic**   | `traffic`        | Show traffic over time        | `nginx-sqlize traffic --db=nginx_logs.db --period=hour`                |
| **Traffic**   | `response-sizes` | Show response sizes           | `nginx-sqlize response-sizes --db=nginx_logs.db`                       |
| **Traffic**   | `errors`         | Show error rates              | `nginx-sqlize errors --db=nginx_logs.db`                               |
| **Security**  | `attacks`        | Detect attack patterns        | `nginx-sqlize attacks --db=nginx_logs.db`                              |
| **Security**  | `bots`           | Identify bot activity         | `nginx-sqlize bots --db=nginx_logs.db`                                 |
| **Security**  | `referrers`      | Analyze referrer sources      | `nginx-sqlize referrers --db=nginx_logs.db`                            |
| **Export**    | `export`         | Export data to CSV            | `nginx-sqlize export --db=nginx_logs.db --output=data.csv --query=ips` |

## 📊 Log Ingestion

Import Nginx logs into a SQLite database:

```bash
nginx-sqlize ingest --logs=<LOG_FILES> [OPTIONS]
```

Options:

- `--logs`: Path to log file(s). Supports glob patterns (e.g., /var/log/nginx/\*.log)
- `--db`: Path to SQLite database file (default: nginx_logs.db)
- `--batch-size`: Number of log entries to insert in a batch (default: 1000)
- `--force`: Reprocess files even if they have been processed before
- `--verbose, -v`: Enable verbose output with additional processing details

Examples:

```bash
# process all access logs
nginx-sqlize ingest --logs=/var/log/nginx/access.log*

# process compressed logs
nginx-sqlize ingest --logs=/var/log/nginx/archived/*.gz

# force reprocessing of all logs
nginx-sqlize ingest --logs=/var/log/nginx/*.log --force

# use a specific database file
nginx-sqlize ingest --logs=/var/log/nginx/*.log --db=/path/to/logs.db
```

## 📂 Database Information

View information about the database:

```bash
nginx-sqlize info --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--status`: Show overall database statistics

Example:

```bash
nginx-sqlize info --db=nginx_logs.db --status
```

## 📈 Traffic Analysis

### 📊 Top Requested Paths

```bash
nginx-sqlize top-paths --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--limit`: Number of results to display (default: 10)

Example:

```bash
nginx-sqlize top-paths --db=nginx_logs.db --limit=20
```

---

### 👥 Top IP Addresses

```bash
nginx-sqlize top-ips --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--limit`: Number of results to display (default: 10)

Example:

```bash
nginx-sqlize top-ips --db=nginx_logs.db --limit=20
```

---

### 🔢 HTTP Status Codes

```bash
nginx-sqlize status-codes --db=<DATABASE_FILE>
```

Example:

```bash
nginx-sqlize status-codes --db=nginx_logs.db
```

---

### 📝 HTTP Method Distribution

```bash
nginx-sqlize methods --db=<DATABASE_FILE>
```

Options:

- `--db`: Path to SQLite database file

Example:

```bash
nginx-sqlize methods --db=nginx_logs.db
```

---

### 📅 Traffic by Time Period

```bash
nginx-sqlize traffic --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--period`: Time grouping period (day or hour, default: day)

Example:

```bash
nginx-sqlize traffic --db=nginx_logs.db --period=hour
```

---

### 📦 Response Sizes

```bash
nginx-sqlize response-sizes --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--period`: Time grouping period (day or hour, default: day)

Example:

```bash
nginx-sqlize response-sizes --db=nginx_logs.db
```

---

### ❌ Error Rates

```bash
nginx-sqlize errors --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--period`: Time grouping period (day or hour, default: day)

Example:

```bash
nginx-sqlize errors --db=nginx_logs.db
```

---

## 🔒 Security Analysis

### 🤖 Bot Activity

```bash
nginx-sqlize bots --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--limit`: Number of results to display (default: 10)

Example:

```bash
nginx-sqlize bots --db=nginx_logs.db --limit=15
```

---

### 🛡️ Attack Pattern Detection

```bash
nginx-sqlize attacks --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--limit`: Number of results to display (default: 10)

Example:

```bash
nginx-sqlize attacks --db=nginx_logs.db
```

---

### 🌐 Referrer Analysis

```bash
nginx-sqlize referrers --db=<DATABASE_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--limit`: Number of results to display (default: 10)

Example:

```bash
nginx-sqlize referrers --db=nginx_logs.db
```

## 📤 Exporting Data

For deeper analysis with external tools, we can export data to CSV format:

```bash
nginx-sqlize export --db=<DATABASE_FILE> --output=<CSV_FILE> [OPTIONS]
```

Options:

- `--db`: Path to SQLite database file
- `--output`: Path to output CSV file
- `--query`: Type of data to export (ips, paths, attacks, bots, status)
- `--limit`: Number of results to display (default: 10)

Examples:

```bash
# export IP addresses for geolocation analysis
nginx-sqlize export --db=nginx_logs.db --output=ips.csv --query=ips

# export attack patterns for security review
nginx-sqlize export --db=nginx_logs.db --output=attacks.csv --query=attacks

# export bot activity for further investigation
nginx-sqlize export --db=nginx_logs.db --output=bots.csv --query=bots
```

## 💻 Manual SQLite Queries

Since nginx-sqlize creates a standard SQLite database, you can also query it directly using the SQLite command-line tool or any SQLite client:

```bash
# open the database with the SQLite CLI
sqlite3 nginx_logs.db

# view available tables
.tables

# show database schema
.schema logs

# run custom queries
SELECT request_path, COUNT(*) as count
FROM logs
WHERE status = 404
GROUP BY request_path
ORDER BY count DESC
LIMIT 10;
```

## 🗄️ Database Schema

The database contains two main tables:

### Logs Table

```sql
CREATE TABLE logs (
    id INTEGER PRIMARY KEY,      -- Auto-incrementing unique identifier
    timestamp TEXT,              -- Log timestamp (format: 16/May/2025:00:06:10 +0000)
    remote_addr TEXT,            -- Client IP address (e.g., 78.153.140.148)
    remote_user TEXT,            -- Username if authenticated (often '-')
    request_method TEXT,         -- HTTP method (GET, POST, etc.)
    request_path TEXT,           -- Request URI path (e.g., /.env)
    http_version TEXT,           -- HTTP protocol version (e.g., HTTP/1.1)
    status INTEGER,              -- HTTP status code (200, 404, 500, etc.)
    bytes_sent INTEGER,          -- Response size in bytes
    referer TEXT,                -- Referrer URL (often '-')
    user_agent TEXT,             -- Client browser/bot info
    processed_at TEXT            -- When this log entry was imported
);
```

The following indexes are created for optimized queries:

- `idx_timestamp`: Index on timestamp for time-based queries
- `idx_remote_addr`: Index on remote_addr for IP-based queries
- `idx_request_path`: Index on request_path for URL-based queries
- `idx_status`: Index on status for HTTP status code queries
- `idx_user_agent`: Index on user_agent for bot detection

### Processed Files Table

Tracks which log files have been processed:

```sql
CREATE TABLE processed_files (
    filename TEXT PRIMARY KEY,   -- Full path to the log file
    last_position INTEGER,       -- Last byte position read in the file
    last_processed TEXT,         -- Timestamp when processing occurred
    lines_processed INTEGER,     -- Number of lines processed from this file
    file_hash TEXT               -- File hash to detect changes
);
```

## Common Use Cases

### 🔒 Finding Security Issues

```bash
# check for common exploit attempts
sqlite3 nginx_logs.db "SELECT request_path, COUNT(*) FROM logs WHERE request_path LIKE '%.php%' OR request_path LIKE '%wp-%' OR request_path LIKE '%admin%' GROUP BY request_path ORDER BY COUNT(*) DESC LIMIT 20;"

# identify suspicious IP addresses
nginx-sqlize top-ips --db=nginx_logs.db --limit=10

# analyze bot activity
nginx-sqlize bots --db=nginx_logs.db
```

### ⚠️ Monitoring Site Health

```bash
# View error rates over time
nginx-sqlize errors --db=nginx_logs.db

# Find frequently failing URLs
sqlite3 nginx_logs.db "SELECT request_path, COUNT(*) FROM logs WHERE status >= 400 GROUP BY request_path ORDER BY COUNT(*) DESC LIMIT 10;"

# Analyze traffic patterns
nginx-sqlize traffic --db=nginx_logs.db --period=hour
```

### 📊 Content Analysis

```bash
# Find most popular content
nginx-sqlize top-paths --db=nginx_logs.db

# Analyze referrers to see where traffic is coming from
nginx-sqlize referrers --db=nginx_logs.db

# Check which pages are generating 404 errors
sqlite3 nginx_logs.db "SELECT request_path, COUNT(*) FROM logs WHERE status = 404 GROUP BY request_path ORDER BY COUNT(*) DESC LIMIT 10;"
```

## 🧰 License

MIT License
