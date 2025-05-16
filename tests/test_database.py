"""Tests for the database operations."""

import os
import pytest
import sqlite3
import tempfile
from nginx_sqlize.database import Database


# fixture to create a temporary database for testing
@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    # create a temporary file
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    # initialize database
    db = Database(path)
    
    # provide the database to the test
    yield db
    
    # cleanup after test
    db.close()
    os.unlink(path)  # delete the temp file after test


# test that database schema is created correctly
def test_database_initialization(temp_db):
    """Test database schema creation."""
    # execute query to check if tables exist
    temp_db.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row['name'] for row in temp_db.cursor.fetchall()]
    
    # verify expected tables are present
    assert 'logs' in tables
    assert 'processed_files' in tables


# test log entry insertion and retrieval
def test_log_insertion(temp_db):
    """Test inserting log entries."""
    # sample log entry
    log_entry = (
        '16/May/2025:00:06:10 +0000',  # timestamp
        '192.168.1.1',                 # remote_addr
        '-',                           # remote_user
        'GET',                         # method
        '/index.html',                 # path
        'HTTP/1.1',                    # version
        200,                           # status
        1024,                          # bytes
        'https://example.com',         # referer
        'Mozilla/5.0',                 # user agent
        '2025-05-16T12:00:00'          # processed_at
    )
    
    # insert log entry
    count = temp_db.insert_logs([log_entry])
    assert count == 1
    
    # verify it was inserted correctly
    temp_db.cursor.execute("SELECT * FROM logs")
    row = temp_db.cursor.fetchone()
    
    # check key fields match
    assert row['remote_addr'] == '192.168.1.1'
    assert row['status'] == 200
    assert row['bytes_sent'] == 1024


# test handling of empty insertion
def test_empty_insertion(temp_db):
    """Test inserting empty list."""
    # should handle empty list gracefully
    count = temp_db.insert_logs([])
    assert count == 0


# test tracking of processed files
def test_processed_file_tracking(temp_db):
    """Test tracking processed files."""
    # add processed file information
    filename = '/var/log/nginx/access.log'
    position = 1024
    lines = 42
    file_hash = 'abc123'
    
    # update processed file record
    temp_db.update_processed_file(filename, position, lines, file_hash)
    
    # retrieve the information
    file_info = temp_db.get_processed_file(filename)
    
    # verify all fields match
    assert file_info is not None
    assert file_info['filename'] == filename
    assert file_info['last_position'] == position
    assert file_info['lines_processed'] == lines
    assert file_info['file_hash'] == file_hash


# test log count functionality
def test_get_log_count(temp_db):
    """Test counting log entries."""
    # initially should be 0
    count = temp_db.get_log_count()
    assert count == 0
    
    # add some test entries
    log_entries = [
        ('16/May/2025:00:06:10 +0000', '192.168.1.1', '-', 'GET', '/page1.html', 'HTTP/1.1', 200, 1024, '-', 'Mozilla/5.0', '2025-05-16T12:00:00'),
        ('16/May/2025:00:06:11 +0000', '192.168.1.2', '-', 'POST', '/api/data', 'HTTP/1.1', 201, 512, '-', 'curl/7.68.0', '2025-05-16T12:00:01')
    ]
    
    # insert the entries
    temp_db.insert_logs(log_entries)
    
    # now should be 2
    count = temp_db.get_log_count()
    assert count == 2


# test context manager functionality
def test_context_manager(temp_db):
    """Test database as context manager."""
    # verify the database is accessible within the context manager
    with temp_db as db:
        db.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row['name'] for row in db.cursor.fetchall()]
        assert 'logs' in tables