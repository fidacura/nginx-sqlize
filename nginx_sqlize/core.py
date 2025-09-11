"""
nginx-sqlize core module; combines parsing, db operations, and file processing.
"""

import re
import sqlite3
import gzip
import sys
import gc
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from typing import Iterator, Optional, Dict, Any, List
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
    
    # database operation errors
    if "database is locked" in error_msg:
        return f"Fatabase is busy. Another nginx-sqlize process running? try: lsof *.sqlite"
    
    if "disk" in error_msg and "full" in error_msg:
        return f"Insufficient disk space. Free up space and try again"
    
    if "permission denied" in error_msg:
        return f"Permission denied. Check file permissions: ls -la {context}"
    
    if "no such file" in error_msg:
        return f"File not found: {context}. verify the path is correct"
    
    if "corrupt" in error_msg or "malformed" in error_msg:
        return f"Database corrupted. Delete {context} and re-run to recreate"
    
    # file processing errors
    if "gzip" in error_msg:
        return f"compression error. File {context} might be corrupted"
    
    if "encoding" in error_msg or "decode" in error_msg:
        return f"Text encoding issue in {context}. File might not be utf-8"
    
    if "no such table" in error_msg:
        return f"Database schema missing. Delete database file and re-run ingest"
    
    # network/io errors
    if "connection refused" in error_msg:
        return f"Connection refused. Check if service is running"
    
    if "timeout" in error_msg:
        return f"Operation timed out. Try again or check system load"
    
    # fallback ~ clean up the raw error message
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
    """
    Basic log line validation to prevent crashes.
    """
    # skip empty lines
    if not line or not line.strip():
        return False
    
    # prevent extremely long lines that could cause memory issues
    if len(line) > 32768:  # 32kb limit
        return False
    
    # check for null bytes that can cause issues
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
        # allow path objects
        arbitrary_types_allowed = True

@dataclass
class LogEntry:
    """Represents a parsed nginx log entry."""
    
    timestamp: str
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
    combines parsing, database operations, and file processing using polars
    for high-performance data processing.
    """
    
    # ========================= class constants and schema =========================
    
    # compiled regex for combined log format
    LOG_PATTERN = re.compile(
        r'(?P<remote_addr>[\d\.]+) - (?P<remote_user>[^ ]*) '
        r'\[(?P<timestamp>.*?)\] "(?P<request>.*?)" '
        r'(?P<status>\d+) (?P<bytes_sent>\d+) '
        r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
    )
    
    # database schema
    SCHEMA = """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
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
        
        -- optimised indexes for common queries
        CREATE INDEX IF NOT EXISTS idx_logs_composite 
        ON logs(timestamp, remote_addr, status);
        
        CREATE INDEX IF NOT EXISTS idx_logs_path 
        ON logs(request_path) WHERE request_path != '';
        
        -- file tracking with hash-based change detection
        CREATE TABLE IF NOT EXISTS processed_files (
            filename TEXT PRIMARY KEY,
            lines_processed INTEGER DEFAULT 0,
            file_hash TEXT,
            processed_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        -- index for faster file lookups
        CREATE INDEX IF NOT EXISTS idx_processed_files_hash 
        ON processed_files(file_hash);
    """
    
    # ========================= initialization and setup =========================
    
    def __init__(self, config: Config):
        """Initialise processor with validated configuration."""
        # validate configuration parameters
        validate_positive_int(config.batch_size, "batch_size", 100000)
        validate_positive_int(config.max_memory_mb, "max_memory_mb", 8192)
        
        self.config = config
        self.db_path = config.db_path
        self._setup_database()
    
    def setup_logging(self, verbose: bool = False) -> None:
        """Setup logging based on verbosity level."""
        # remove any existing handlers
        logger.remove()
        
        if verbose:
            # verbose mode: show everything to console and file
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
            # non-verbose mode: only log to file, nothing to console
            logger.add(
                "nginx_sqlize.log",
                rotation="10 MB", 
                retention="7 days",
                level="INFO"
            )
    
    def _setup_database(self) -> None:
        """Setup database schema and optimizations."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(self.SCHEMA)
            logger.info(f"Database initialised: {self.db_path}")
    
    # ========================= database connection management =========================
    
    @contextmanager
    def _db_connection(self) -> Iterator[sqlite3.Connection]:
        """Context manager for database connections with proper cleanup."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    # ========================= log parsing and validation =========================
    
    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse single log line with input validation."""
        # validate line before processing to prevent crashes
        if not validate_log_line_basic(line):
            return None
        
        if not line.strip():
            return None
            
        match = self.LOG_PATTERN.match(line.strip())
        if not match:
            return None
        
        data = match.groupdict()
        
        # parse request components safely
        request_parts = data['request'].split(None, 2)
        method = request_parts[0] if request_parts else ''
        path = request_parts[1] if len(request_parts) > 1 else ''
        version = request_parts[2] if len(request_parts) > 2 else ''
        
        # safe integer conversion with validation
        try:
            status = int(data['status']) if data['status'].isdigit() else 0
            bytes_sent = int(data['bytes_sent']) if data['bytes_sent'].isdigit() else 0
        except (ValueError, TypeError):
            status, bytes_sent = 0, 0
        
        return LogEntry(
            timestamp=data['timestamp'],
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
        """Compute hash of file beginning for change detection."""
        import hashlib
        
        try:
            with open(filepath, 'rb') as f:
                sample = f.read(sample_size)
                return hashlib.md5(sample).hexdigest()
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
    
    def _should_process_file(self, filepath: Path, force: bool = False) -> bool:
        """Determine if file should be processed."""
        if force:
            logger.debug(f"Force mode enabled ~ will reprocess {filepath}")
            return True
        
        current_hash = self._compute_file_hash(filepath)
        file_status = self._get_file_status(filepath)
        
        if not file_status:
            logger.debug(f"No previous processing record found for {filepath}")
            return True
        
        # file changed since last processing
        if file_status.get('file_hash') != current_hash:
            logger.info(f"File changed since last processing: {filepath}")
            return True
        
        # file already processed
        logger.info(f"Skipping {filepath.name} - {file_status.get('lines_processed', 0)} lines already in database")
        return False
    
    # ========================= main processing pipeline =========================
    
    def process_file(self, filepath: Path, force: bool = False) -> Dict[str, int]:
        """
        Process a single log file with efficient batch processing;
        uses atomic transactions to ensure data consistency and validates
        all inputs to prevent crashes from malformed data.
        """
        filepath = filepath.resolve()
        
        if not self._should_process_file(filepath, force):
            return {"processed": 0, "inserted": 0}
        
        logger.info(f"Processing file: {filepath}")
        
        entries = []
        lines_processed = 0
        parse_errors = 0
        total_inserted = 0
        
        try:
            with self._open_log_file(filepath) as f:
                # process lines in batches with validation
                for line in f:
                    entry = self._parse_line(line)
                    if entry:
                        entries.append(entry)
                    else:
                        if line.strip():  # only count non-empty lines as errors
                            parse_errors += 1
                    
                    lines_processed += 1
                    
                    # process batch when full
                    if len(entries) >= self.config.batch_size:
                        self._insert_batch(entries)
                        total_inserted += len(entries)
                        entries = []
                        
                        # force garbage collection every 10 batches to manage memory
                        if lines_processed % (self.config.batch_size * 10) == 0:
                            gc.collect()
                
                # insert remaining entries and update file status atomically
                if entries or lines_processed > 0:
                    with self._db_connection() as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        try:
                            # insert remaining batch
                            if entries:
                                self._insert_batch_with_conn(entries, conn)
                                total_inserted += len(entries)
                            
                            # update file status in same transaction
                            file_hash = self._compute_file_hash(filepath)
                            conn.execute("""
                                INSERT OR REPLACE INTO processed_files 
                                (filename, lines_processed, file_hash, processed_at)
                                VALUES (?, ?, ?, ?)
                            """, (str(filepath), lines_processed, file_hash, datetime.now().isoformat()))
                            
                            conn.commit()
                            logger.success(f"Processed {lines_processed} lines from {filepath}")
                            
                        except Exception as e:
                            conn.rollback()
                            error_msg = translate_error_message(e, str(filepath))
                            logger.error(f"Transaction failed: {error_msg}")
                            raise Exception(error_msg)
                
                # report parse errors if any
                if parse_errors > 0:
                    logger.warning(f"⚠️ {parse_errors} lines could not be parsed")
                
                return {"processed": lines_processed, "inserted": total_inserted}
                    
        except Exception as e:
            error_msg = translate_error_message(e, str(filepath))
            logger.error(f"Error processing {filepath}: {error_msg}")
            raise Exception(error_msg)
    
    # ========================= database operations =========================
    
    def _insert_batch(self, entries: List[LogEntry]) -> None:
        """Insert batch of entries using efficient bulk operations."""
        if not entries:
            return
        
        with self._db_connection() as conn:
            self._insert_batch_with_conn(entries, conn)
            conn.commit()
    
    def _insert_batch_with_conn(self, entries: List[LogEntry], conn: sqlite3.Connection) -> None:
        """Insert batch using provided connection for atomic operations."""
        if not entries:
            return
        
        # prepare data tuples for bulk insert
        data_tuples = [
            (
                entry.timestamp,
                entry.remote_addr,
                entry.remote_user,
                entry.request_method,
                entry.request_path,
                entry.http_version,
                entry.status,
                entry.bytes_sent,
                entry.referer,
                entry.user_agent,
                entry.processed_at
            )
            for entry in entries
        ]
        
        # bulk insert with parameterised query
        insert_query = """
            INSERT INTO logs (
                timestamp, remote_addr, remote_user, request_method,
                request_path, http_version, status, bytes_sent,
                referer, user_agent, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        conn.executemany(insert_query, data_tuples)
        logger.debug(f"Inserted batch of {len(entries)} entries")
    
    # ========================= statistics and reporting =========================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics and summary information."""
        try:
            with self._db_connection() as conn:
                # basic counts
                total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
                total_files = conn.execute("SELECT COUNT(*) FROM processed_files").fetchone()[0]
                
                # date range
                date_range = conn.execute("""
                    SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest 
                    FROM logs
                """).fetchone()
                date_range_dict = dict(date_range) if date_range and date_range[0] else {}
                
                # top status codes
                status_dist = conn.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM logs 
                    GROUP BY status 
                    ORDER BY count DESC 
                    LIMIT 5
                """).fetchall()
                status_codes = [dict(row) for row in status_dist]
                
                # database file size
                db_size_mb = self.db_path.stat().st_size / (1024 * 1024)
                
                return {
                    "total_logs": total_logs,
                    "processed_files": total_files,
                    "date_range": date_range_dict,
                    "top_status_codes": status_codes,
                    "database_size_mb": db_size_mb
                }
                
        except Exception as e:
            error_msg = translate_error_message(e, str(self.db_path))
            logger.error(f"Failed to get database stats: {error_msg}")
            return {
                "total_logs": 0,
                "processed_files": 0,
                "date_range": {},
                "top_status_codes": [],
                "database_size_mb": 0.0
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
        
        # find matching files
        log_files = list(base_dir.glob(glob_pattern))
        
        # filter to actual files and sort by modification time
        return sorted(
            [f for f in log_files if f.is_file()],
            key=lambda x: x.stat().st_mtime
        )


# ========================= factory functions =========================

def create_processor(db_path: str = "nginx_logs.db", **kwargs) -> NginxProcessor:
    """Create processor instance with validated configuration and sensible defaults."""
    # validate batch_size if provided
    if 'batch_size' in kwargs:
        validate_positive_int(kwargs['batch_size'], "batch_size", 100000)
    
    config = Config(db_path=Path(db_path), **kwargs)
    return NginxProcessor(config)