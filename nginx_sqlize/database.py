"""Database operations for nginx-sqlize."""

import os
import sqlite3
import time
from datetime import datetime
from typing import List, Optional, Tuple


class Database:
    """SQLite database handler for storing and querying Nginx logs."""

    # sql-schema for the database
    SCHEMA = """
        -- Enable foreign keys for data integrity
        PRAGMA foreign_keys = ON;
        
        -- Performance optimizations
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        
        CREATE TABLE IF NOT EXISTS logs (
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

        -- Optimal indexes
        CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_remote_addr ON logs(remote_addr);
        CREATE INDEX IF NOT EXISTS idx_request_path ON logs(request_path);
        CREATE INDEX IF NOT EXISTS idx_status ON logs(status);
        CREATE INDEX IF NOT EXISTS idx_user_agent ON logs(user_agent);  -- For bot detection

        -- Tracking processed files
        CREATE TABLE IF NOT EXISTS processed_files (
            filename TEXT PRIMARY KEY,   -- Full path to the log file
            last_position INTEGER,       -- Last byte position read in the file
            last_processed TEXT,         -- Timestamp when processing occurred
            lines_processed INTEGER,     -- Number of lines processed from this file
            file_hash TEXT               -- File hash to detect changes
        );
    """

    # init database with path and create connection
    def __init__(self, db_path: str):
        """Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._connect()
        self._create_schema()

    # create connection to sqlite database
    def _connect(self) -> None:
        """Connect to the SQLite database."""
        # Create directory if it doesn't exist
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)

        # Connect to database with row factory for easier access
        self.conn = sqlite3.connect(self.db_path, timeout=20)  # Add timeout for busy database
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

    # create tables and indexes if they don't exist
    def _create_schema(self) -> None:
        """Create database schema if it doesn't exist."""
        try:
            self.cursor.executescript(self.SCHEMA)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Error creating schema: {e}")
            raise

    # properly close the database connection
    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()

    # add multiple log entries to the database in one batch
    def insert_logs(self, log_entries: List[Tuple]) -> int:
        """Insert multiple log entries in a batch.

        Recommended batch size is between 500-1000 for optimal performance.

        Args:
            log_entries: List of tuples containing log data

        Returns:
            Number of inserted records
        """
        if not log_entries:
            return 0

        try:
            # use parameterized query to prevent sql injection
            query = """
            INSERT INTO logs (
                timestamp, remote_addr, remote_user, request_method, 
                request_path, http_version, status, bytes_sent, 
                referer, user_agent, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            # execute in a single transaction for better performance
            self.cursor.executemany(query, log_entries)
            self.conn.commit()
            
            return len(log_entries)
        except sqlite3.Error as e:
            self.conn.rollback()
            print(f"Error inserting logs: {e}")
            return 0

    # check if a file has been processed before
    def get_processed_file(self, filename: str) -> Optional[sqlite3.Row]:
        """Get info about previously processed file.

        Args:
            filename: Full path to the log file

        Returns:
            Row with processing info or None if file wasn't processed
        """
        try:
            query = "SELECT * FROM processed_files WHERE filename = ?"
            self.cursor.execute(query, (filename,))
            return self.cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Error checking processed file: {e}")
            return None

    # record information about a processed file
    def update_processed_file(
        self, filename: str, position: int, lines: int, file_hash: str
    ) -> None:
        """Update or insert processed file information.

        Args:
            filename: Full path to the log file
            position: Last read position in the file
            lines: Number of lines processed
            file_hash: Hash of file for change detection
        """
        try:
            now = datetime.now().isoformat()
            
            query = """
            INSERT OR REPLACE INTO processed_files 
            (filename, last_position, last_processed, lines_processed, file_hash)
            VALUES (?, ?, ?, ?, ?)
            """
            
            self.cursor.execute(query, (filename, position, now, lines, file_hash))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            print(f"Error updating processed file: {e}")

    # get the total number of log entries in the database
    def get_log_count(self) -> int:
        """Get total number of log entries.

        Returns:
            Count of log entries
        """
        try:
            query = "SELECT COUNT(*) as count FROM logs"
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            return result['count'] if result else 0
        except sqlite3.Error as e:
            print(f"Error getting log count: {e}")
            return 0

    # get query interface for analytics
    def get_queries(self):
        """Get query interface for analytics.
        
        Returns:
            LogQueries object for analytics
        """
        from nginx_sqlize.queries import LogQueries
        return LogQueries(self.conn)

    # support for using with "with" statement
    def __enter__(self):
        """Context manager entry."""
        return self

    # cleanup when exiting "with" block
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.close()