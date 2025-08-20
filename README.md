# nginx-sqlize

A tool for importing Nginx logs into SQLite for easy querying and analysis.

## ⚡ Quick Start

### Installation from PyPI

```bash
pip install nginx-sqlize
```

### Installation from Source

```bash
git clone https://github.com/fidacura/nginx-sqlize.git
cd nginx-sqlize

# create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# install in development mode
pip install -e .
```

### Basic Usage

```bash
# process nginx logs into sqlite
nginx-sqlize ingest /var/log/nginx/access.log

# analyze the data
nginx-sqlize query --top-paths 20
nginx-sqlize query --top-ips 15
nginx-sqlize query --status-codes

# check database status
nginx-sqlize status

# clean and optimize
nginx-sqlize clean --duplicates --vacuum
```

## 📋 Command Reference

### **📥 Ingestion**

| Command                   | Description                             | Example                                       |
| ------------------------- | --------------------------------------- | --------------------------------------------- |
| `ingest <logs>`           | Process nginx logs into SQLite database | `nginx-sqlize ingest /var/log/nginx/*.log`    |
| `ingest --output <name>`  | Specify custom database name            | `nginx-sqlize ingest logs/ --output mysite`   |
| `ingest --force`          | Reprocess all files (ignore tracking)   | `nginx-sqlize ingest logs/ --force`           |
| `ingest --verbose`        | Show detailed processing information    | `nginx-sqlize ingest logs/ --verbose`         |
| `ingest --batch-size <n>` | Set processing batch size               | `nginx-sqlize ingest logs/ --batch-size 5000` |

### **🔍 Analytics**

| Command                      | Description                 | Example                                  |
| ---------------------------- | --------------------------- | ---------------------------------------- |
| `query --top-paths <n>`      | Most requested paths        | `nginx-sqlize query --top-paths 20`      |
| `query --top-ips <n>`        | Most active IP addresses    | `nginx-sqlize query --top-ips 15`        |
| `query --status-codes`       | HTTP status distribution    | `nginx-sqlize query --status-codes`      |
| `query --methods`            | HTTP method distribution    | `nginx-sqlize query --methods`           |
| `query --referrers <n>`      | Top referrer sources        | `nginx-sqlize query --referrers 10`      |
| `query --response-sizes <n>` | Paths by response size      | `nginx-sqlize query --response-sizes 15` |
| `query --traffic <period>`   | Traffic patterns (hour/day) | `nginx-sqlize query --traffic hour`      |
| `query --errors`             | Error analysis and patterns | `nginx-sqlize query --errors`            |
| `query --bots <n>`           | Bot activity detection      | `nginx-sqlize query --bots 10`           |
| `query --attacks <n>`        | Potential attack patterns   | `nginx-sqlize query --attacks 20`        |

### **💾 Database**

| Command                 | Description                       | Example                                                       |
| ----------------------- | --------------------------------- | ------------------------------------------------------------- |
| `query --sql <query>`   | Execute custom SQL query          | `nginx-sqlize query --sql "SELECT * FROM logs LIMIT 10"`      |
| `query --export <file>` | Export results to JSON            | `nginx-sqlize query --top-paths 50 --export report.json`      |
| `query --combine`       | Combine multiple database results | `nginx-sqlize query --db "*.sqlite" --combine --status-codes` |
| `query --limit <n>`     | Limit number of results           | `nginx-sqlize query --top-paths 5 --limit 5`                  |

### **📊 Management**

| Command                       | Description                  | Example                                  |
| ----------------------------- | ---------------------------- | ---------------------------------------- |
| `status`                      | Show database statistics     | `nginx-sqlize status`                    |
| `status --db <path>`          | Status for specific database | `nginx-sqlize status --db mysite.sqlite` |
| `clean --duplicates`          | Remove duplicate entries     | `nginx-sqlize clean --duplicates`        |
| `clean --vacuum`              | Optimize database storage    | `nginx-sqlize clean --vacuum`            |
| `clean --older-than <period>` | Remove old logs              | `nginx-sqlize clean --older-than 30d`    |
| `clean --yes`                 | Skip confirmation prompts    | `nginx-sqlize clean --duplicates --yes`  |

### 🎯 Common Workflows

```bash
# complete analysis workflow
nginx-sqlize ingest /var/log/nginx/*.log --output website
nginx-sqlize status --db website.sqlite
nginx-sqlize query --db website.sqlite --top-paths 20
nginx-sqlize query --db website.sqlite --attacks 10 --export security-report.json

# maintenance workflow
nginx-sqlize clean --duplicates --older-than 90d --vacuum --yes

# multi-site analysis
nginx-sqlize query --db "site1.sqlite,site2.sqlite" --combine --traffic day
```

## 🚀 Detailed Command Usage

### 📥 Ingest Logs

Process nginx log files into a SQLite database with automatic optimization:

```bash
# single file
nginx-sqlize ingest /var/log/nginx/access.log

# multiple files with pattern
nginx-sqlize ingest "/var/log/nginx/*.log"

# gzipped files supported
nginx-sqlize ingest "/var/log/nginx/access.log*.gz"

# custom database name
nginx-sqlize ingest /path/to/logs --output mysite

# force reprocess all files
nginx-sqlize ingest /path/to/logs --force

# verbose output with detailed progress
nginx-sqlize ingest /path/to/logs --verbose
```

### 🔍 Query and Analytics

Powerful querying with pre-built analytics:

```bash
# top requested paths
nginx-sqlize query --top-paths 20

# most active ip addresses
nginx-sqlize query --top-ips 15

# http status distribution
nginx-sqlize query --status-codes

# traffic patterns by hour
nginx-sqlize query --traffic hour

# error analysis
nginx-sqlize query --errors

# bot activity detection
nginx-sqlize query --bots 10

# potential attack patterns
nginx-sqlize query --attacks 20

# export results to json
nginx-sqlize query --top-paths 50 --export results.json
```

### 📊 Database Status

Get comprehensive database information:

```bash
# overview with statistics
nginx-sqlize status

# specific database
nginx-sqlize status --db mysite.sqlite
```

### 🧹 Database Maintenance

Keep your database optimized and clean:

```bash
# remove duplicates and optimize
nginx-sqlize clean --duplicates --vacuum

# remove old logs
nginx-sqlize clean --older-than 30d

# remove logs older than 1 year
nginx-sqlize clean --older-than 1y

# skip confirmation
nginx-sqlize clean --duplicates --yes
```

## 🏗️ Architecture

### Database Schema

```sql
-- main logs table with optimized indexes
CREATE TABLE logs (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    remote_addr TEXT NOT NULL,
    request_method TEXT,
    request_path TEXT,
    status INTEGER,
    bytes_sent INTEGER,
    -- ... additional fields
);

-- composite index for time-series queries
CREATE INDEX idx_logs_composite ON logs(timestamp, remote_addr, status);

-- path-specific queries
CREATE INDEX idx_logs_path ON logs(request_path) WHERE request_path != '';

-- file processing tracking
CREATE TABLE processed_files (
    filename TEXT PRIMARY KEY,
    last_position INTEGER,
    lines_processed INTEGER,
    file_hash TEXT,
    processed_at TEXT
);
```

## 🔧 Configuration

### Environment Variables

```bash
# default database path
export NGINX_SQLIZE_DB="nginx_logs.sqlite"

# batch size for processing
export NGINX_SQLIZE_BATCH_SIZE=10000

# memory limit in mb
export NGINX_SQLIZE_MAX_MEMORY=512
```

### Custom Log Formats

Currently supports the standard nginx combined log format:

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

## 📈 Use Cases

### System Administration

- **Traffic Monitoring**: Real-time insights into web server performance
- **Error Tracking**: Identify and resolve 4xx/5xx error patterns
- **Capacity Planning**: Analyze traffic trends for resource allocation

### Security Analysis

- **Attack Detection**: Monitor for suspicious access patterns
- **Bot Management**: Identify and analyze automated traffic
- **Threat Intelligence**: Track attack sources and methods

### Business Intelligence

- **Content Performance**: Most popular pages and resources
- **User Behavior**: Traffic sources and navigation patterns
- **Marketing Analytics**: Referrer analysis and campaign tracking

### DevOps Integration

- **Log Aggregation**: Centralized log storage and analysis
- **Alerting**: Query-based monitoring and notifications
- **Reporting**: Automated analytics and dashboard data

## 🛠️ Development

### Setup Development Environment

```bash
git clone https://github.com/fidacura/nginx-sqlize.git
cd nginx-sqlize

# create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on windows

# install with development dependencies
pip install -e ".[dev]"
```

### Project Structure

```
nginx-sqlize/
├── nginx_sqlize/
│   ├── __init__.py      # version and package info
│   ├── main.py          # cli interface with typer
│   ├── core.py          # log processing engine
│   └── queries.py       # analytics and query engine
├── tests/               # comprehensive test suite
├── pyproject.toml       # modern python packaging
└── README.md
```

## 📄 License

This project is licensed under the GNU General Public License v2.0 ~ see the [LICENSE](LICENSE) file for details.

Copyright (C) 2025 fidacura. This is free software distributed under GPL v2.0 terms.
