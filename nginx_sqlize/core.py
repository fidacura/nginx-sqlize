"""
nginx-sqlize core module; combines parsing, db operations, and file processing.
"""

import hashlib
import re
import sqlite3
import gzip
import sys
import gc
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from typing import Iterator, Optional, Dict, Any, List, Tuple
from dataclasses import dataclass

from loguru import logger
from pydantic import BaseModel, Field


# ========================= error management =========================

def translate_error_message(error: Exception, context: str = "") -> str:
    """
    Translate technical error messages into actionable user guidance;
    with specific suggestions for resolution.
    """
    error_msg = str(error).lower()

    if "database is locked" in error_msg:
        return f"Database is busy. Another nginx-sqlize process running? try: lsof *.sqlite"

    if "disk" in error_msg and "full" in error_msg:
        return f"Insufficient disk space. Free up space and try again"

    if "permission denied" in error_msg:
        return f"Permission denied. Check file permissions: ls -la {context}"

    if "no such file" in error_msg:
        return f"File not found: {context}. verify the path is correct"

    if "corrupt" in error_msg or "malformed" in error_msg:
        return f"Database corrupted. Delete {context} and re-run to recreate"

    if "gzip" in error_msg:
        return f"Compression error. File {context} might be corrupted"

    if "encoding" in error_msg or "decode" in error_msg:
        return f"Text encoding issue in {context}. File might not be utf-8"

    if "no such table" in error_msg:
        return f"Database schema missing. Delete database file and re-run ingest"

    if "connection refused" in error_msg:
        return f"Connection refused. Check if service is running"

    if "timeout" in error_msg:
        return f"Operation timed out. Try again or check system load"

    return f"Operation failed: {str(error)}"


# ========================= input validation =========================

def validate_positive_int(value: int, name: str, max_value: int = 100000) -> int:
    """
    Validate integer is positive and reasonable;
    prevents crashes from negative numbers or absurdly large values.
    """
    if not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")

    if value <= 0:
        raise ValueError(f"{name} must be positive, got: {value}")

    if value > max_value:
        raise ValueError(f"{name} too large (max {max_value}), got: {value}")

    return value

def validate_log_line_basic(line: str) -> bool:
    """Basic log line validation to prevent crashes."""
    if not line or not line.strip():
        return False

    if len(line) > 32768:
        return False

    if '\x00' in line:
        return False

    return True


# ========================= configuration and data models =========================

class Config(BaseModel):
    """Configurations for nginx log processing with validation."""

    db_path: Path = Field(default=Path("nginx_logs.db"))
    batch_size: int = Field(default=10000, ge=100, le=100000)
    max_memory_mb: int = Field(default=512, ge=64)
    log_format: str = Field(default="combined")

    class Config:
        arbitrary_types_allowed = True

@dataclass
class LogEntry:
    """Represents a parsed nginx log entry."""

    timestamp: str
    timestamp_iso: str          # ISO 8601 for sortable date comparisons
    remote_addr: str
    remote_user: str
    request_method: str
    request_path: str
    http_version: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    processed_at: str


# ========================= main processor =========================

class NginxProcessor:
    """
    Unified processor for nginx logs with input validation;
    combines parsing, database operations, and file processing.
    """

    # ========================= class constants and schema =========================

    LOG_PATTERN = re.compile(
        r'(?P<remote_addr>[\d\.]+) - (?P<remote_user>[^ ]*) '
        r'\[(?P<timestamp>.*?)\] "(?P<request>.*?)" '
        r'(?P<status>\d+) (?P<bytes_sent>\d+) '
        r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
    )

    SCHEMA = """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            timestamp_iso TEXT,
            remote_addr TEXT NOT NULL,
            remote_user TEXT,
            request_method TEXT,
            request_path TEXT,
            http_version TEXT,
            status INTEGER,
            bytes_sent INTEGER,
            referer TEXT,
            user_agent TEXT,
            processed_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_logs_composite
        ON logs(timestamp_iso, remote_addr, status);

        CREATE INDEX IF NOT EXISTS idx_logs_path
        ON logs(request_path) WHERE request_path != '';

        CREATE TABLE IF NOT EXISTS processed_files (
            filename TEXT PRIMARY KEY,
            lines_processed INTEGER DEFAULT 0,
            file_hash TEXT,
            processed_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_processed_files_hash
        ON processed_files(file_hash);
    """

    # ========================= initialization and setup =========================

    def __init__(self, config: Config):
        """Initialise processor with validated configuration."""
        validate_positive_int(config.batch_size, "batch_size", 100000)
        validate_positive_int(config.max_memory_mb, "max_memory_mb", 8192)

        self.config = config
        self.db_path = config.db_path
        self._setup_database()

    def setup_logging(self, verbose: bool = False) -> None:
        """Setup logging based on verbosity level."""
        logger.remove()

        if verbose:
            logger.add(
                sys.stderr,
                level="DEBUG",
                format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
            )
            logger.add(
                "nginx_sqlize.log",
                rotation="10 MB",
                retention="7 days",
                level="DEBUG"
            )
        else:
            logger.add(
                "nginx_sqlize.log",
                rotation="10 MB",
                retention="7 days",
                level="INFO"
            )

    def _setup_database(self) -> None:
        """Setup database schema and run any pending migrations."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        try:
            conn.executescript(self.SCHEMA)
            self._ensure_timestamp_iso_migration(conn)
            logger.info(f"Database initialised: {self.db_path}")
        finally:
            conn.close()

    # ========================= schema migration =========================

    def _ensure_timestamp_iso_migration(self, conn: sqlite3.Connection) -> None:
        """Add timestamp_iso column and backfill existing rows if needed."""
        cursor = conn.execute("PRAGMA table_info(logs)")
        columns = {row[1] for row in cursor.fetchall()}

        if "timestamp_iso" not in columns:
            conn.execute("ALTER TABLE logs ADD COLUMN timestamp_iso TEXT")
            logger.info("Migration: added timestamp_iso column to logs table")

        count = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE timestamp_iso IS NULL"
        ).fetchone()[0]

        if count > 0:
            logger.info(f"Migration: backfilling ISO timestamps for {count:,} existing rows...")
            self._backfill_timestamp_iso(conn)
            logger.info("Migration: timestamp_iso backfill complete")

    def _backfill_timestamp_iso(self, conn: sqlite3.Connection) -> None:
        """Populate timestamp_iso for all NULL rows, processed in batches."""
        while True:
            rows = conn.execute(
                "SELECT id, timestamp FROM logs WHERE timestamp_iso IS NULL LIMIT 10000"
            ).fetchall()
            if not rows:
                break

            updates = [
                (self._parse_nginx_timestamp(row[1]), row[0])
                for row in rows
            ]
            conn.execute("BEGIN")
            conn.executemany(
                "UPDATE logs SET timestamp_iso = ? WHERE id = ?", updates
            )
            conn.execute("COMMIT")

    @staticmethod
    def _parse_nginx_timestamp(timestamp: str) -> str:
        """Convert nginx timestamp to ISO 8601 string for sortable comparisons."""
        try:
            dt = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except ValueError:
            return ""

    # ========================= database connection management =========================

    @contextmanager
    def _db_connection(self) -> Iterator[sqlite3.Connection]:
        """
        Context manager for database connections.
        Uses isolation_level=None (autocommit) so that explicit BEGIN/COMMIT/ROLLBACK
        SQL statements work without conflicting with Python's implicit transaction mgmt.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ========================= log parsing and validation =========================

    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse single log line with input validation."""
        if not validate_log_line_basic(line):
            return None

        if not line.strip():
            return None

        match = self.LOG_PATTERN.match(line.strip())
        if not match:
            return None

        data = match.groupdict()

        request_parts = data['request'].split(None, 2)
        method = request_parts[0] if request_parts else ''
        path = request_parts[1] if len(request_parts) > 1 else ''
        version = request_parts[2] if len(request_parts) > 2 else ''

        try:
            status = int(data['status']) if data['status'].isdigit() else 0
            bytes_sent = int(data['bytes_sent']) if data['bytes_sent'].isdigit() else 0
        except (ValueError, TypeError):
            status, bytes_sent = 0, 0

        return LogEntry(
            timestamp=data['timestamp'],
            timestamp_iso=self._parse_nginx_timestamp(data['timestamp']),
            remote_addr=data['remote_addr'],
            remote_user=data['remote_user'],
            request_method=method,
            request_path=path,
            http_version=version,
            status=status,
            bytes_sent=bytes_sent,
            referer=data['referer'],
            user_agent=data['user_agent'],
            processed_at=datetime.now().isoformat()
        )

    def _open_log_file(self, filepath: Path):
        """Open log file handling both plain and gzipped formats."""
        if filepath.suffix == '.gz':
            return gzip.open(filepath, 'rt', encoding='utf-8')
        return open(filepath, 'r', encoding='utf-8')

    # ========================= file processing and tracking =========================

    def _compute_file_hash(self, filepath: Path, sample_size: int = 8192) -> str:
        """
        Compute SHA-256 hash of file size + last sample_size bytes.
        Hashing the tail (not the head) reliably detects appended content,
        which is the normal growth pattern for nginx log files.
        """
        try:
            file_size = filepath.stat().st_size
            with open(filepath, 'rb') as f:
                if file_size > sample_size:
                    f.seek(-sample_size, 2)   # seek to last sample_size bytes
                sample = f.read(sample_size)

            content = f"{file_size}:".encode() + sample
            return hashlib.sha256(content).hexdigest()

        except Exception as e:
            error_msg = translate_error_message(e, str(filepath))
            logger.error(f"Error computing hash for {filepath}: {error_msg}")
            raise Exception(error_msg)

    def _get_file_status(self, filepath: Path) -> Dict[str, Any]:
        """Get processing status for a file."""
        with self._db_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM processed_files WHERE filename = ?",
                (str(filepath),)
            )
            result = cursor.fetchone()
            return dict(result) if result else {}

    def _should_process_file(
        self, filepath: Path, force: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if file should be processed.
        Returns (should_process, cached_hash) so the caller can reuse the hash
        without recomputing it (avoids a TOCTOU window and redundant I/O).
        """
        if force:
            logger.debug(f"Force mode enabled ~ will reprocess {filepath}")
            return True, None

        current_hash = self._compute_file_hash(filepath)
        file_status = self._get_file_status(filepath)

        if not file_status:
            logger.debug(f"No previous processing record found for {filepath}")
            return True, current_hash

        if file_status.get('file_hash') != current_hash:
            logger.info(f"File changed since last processing: {filepath}")
            return True, current_hash

        logger.info(
            f"Skipping {filepath.name} - "
            f"{file_status.get('lines_processed', 0)} lines already in database"
        )
        return False, current_hash

    # ========================= main processing pipeline =========================

    def process_file(self, filepath: Path, force: bool = False) -> Dict[str, int]:
        """
        Process a single log file within one atomic transaction.

        All batch inserts and the processed_files record update are committed
        together, so a mid-run crash leaves no partial data: either the whole
        file is recorded or nothing is, and re-running is always safe.
        """
        filepath = filepath.resolve()

        should_process, cached_hash = self._should_process_file(filepath, force)
        if not should_process:
            return {"processed": 0, "inserted": 0}

        logger.info(f"Processing file: {filepath}")

        entries: List[LogEntry] = []
        lines_processed = 0
        parse_errors = 0
        total_inserted = 0

        try:
            with self._open_log_file(filepath) as f, self._db_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for line in f:
                        entry = self._parse_line(line)
                        if entry:
                            entries.append(entry)
                        else:
                            if line.strip():
                                parse_errors += 1

                        lines_processed += 1

                        if len(entries) >= self.config.batch_size:
                            self._insert_batch_with_conn(entries, conn)
                            total_inserted += len(entries)
                            entries = []

                            if lines_processed % (self.config.batch_size * 10) == 0:
                                gc.collect()

                    # insert any remaining entries
                    if entries:
                        self._insert_batch_with_conn(entries, conn)
                        total_inserted += len(entries)

                    # reuse cached hash; compute fresh only in force mode
                    file_hash = cached_hash or self._compute_file_hash(filepath)

                    conn.execute(
                        """
                        INSERT OR REPLACE INTO processed_files
                        (filename, lines_processed, file_hash, processed_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (str(filepath), lines_processed, file_hash, datetime.now().isoformat())
                    )

                    conn.execute("COMMIT")
                    logger.success(f"Processed {lines_processed} lines from {filepath}")

                except Exception as e:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    error_msg = translate_error_message(e, str(filepath))
                    logger.error(f"Transaction failed: {error_msg}")
                    raise Exception(error_msg)

            if parse_errors > 0:
                logger.warning(f"⚠️ {parse_errors} lines could not be parsed")

            return {"processed": lines_processed, "inserted": total_inserted}

        except Exception as e:
            error_msg = translate_error_message(e, str(filepath))
            logger.error(f"Error processing {filepath}: {error_msg}")
            raise Exception(error_msg)

    # ========================= database operations =========================

    def _insert_batch_with_conn(
        self, entries: List[LogEntry], conn: sqlite3.Connection
    ) -> None:
        """Insert a batch of entries using the provided connection."""
        if not entries:
            return

        data_tuples = [
            (
                entry.timestamp,
                entry.timestamp_iso,
                entry.remote_addr,
                entry.remote_user,
                entry.request_method,
                entry.request_path,
                entry.http_version,
                entry.status,
                entry.bytes_sent,
                entry.referer,
                entry.user_agent,
                entry.processed_at,
            )
            for entry in entries
        ]

        conn.executemany(
            """
            INSERT INTO logs (
                timestamp, timestamp_iso, remote_addr, remote_user,
                request_method, request_path, http_version, status,
                bytes_sent, referer, user_agent, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data_tuples,
        )
        logger.debug(f"Inserted batch of {len(entries)} entries")

    # ========================= statistics and reporting =========================

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics and summary information."""
        try:
            with self._db_connection() as conn:
                total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
                total_files = conn.execute(
                    "SELECT COUNT(*) FROM processed_files"
                ).fetchone()[0]

                date_range = conn.execute(
                    """
                    SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest
                    FROM logs
                    """
                ).fetchone()
                date_range_dict = (
                    dict(date_range) if date_range and date_range[0] else {}
                )

                status_dist = conn.execute(
                    """
                    SELECT status, COUNT(*) as count
                    FROM logs
                    GROUP BY status
                    ORDER BY count DESC
                    LIMIT 5
                    """
                ).fetchall()
                status_codes = [dict(row) for row in status_dist]

                db_size_mb = self.db_path.stat().st_size / (1024 * 1024)

                return {
                    "total_logs": total_logs,
                    "processed_files": total_files,
                    "date_range": date_range_dict,
                    "top_status_codes": status_codes,
                    "database_size_mb": db_size_mb,
                }

        except Exception as e:
            error_msg = translate_error_message(e, str(self.db_path))
            logger.error(f"Failed to get database stats: {error_msg}")
            return {
                "total_logs": 0,
                "processed_files": 0,
                "date_range": {},
                "top_status_codes": [],
                "database_size_mb": 0.0,
            }

    def find_log_files(self, pattern: str) -> List[Path]:
        """Find log files matching pattern with smart globbing."""
        pattern_path = Path(pattern)

        if pattern_path.is_absolute():
            base_dir = pattern_path.parent
            glob_pattern = pattern_path.name
        else:
            base_dir = Path.cwd()
            glob_pattern = pattern

        log_files = list(base_dir.glob(glob_pattern))

        return sorted(
            [f for f in log_files if f.is_file()],
            key=lambda x: x.stat().st_mtime,
        )


# ========================= factory functions =========================

def create_processor(db_path: str = "nginx_logs.db", **kwargs) -> NginxProcessor:
    """Create processor instance with validated configuration and sensible defaults."""
    if 'batch_size' in kwargs:
        validate_positive_int(kwargs['batch_size'], "batch_size", 100000)

    config = Config(db_path=Path(db_path), **kwargs)
    return NginxProcessor(config)
