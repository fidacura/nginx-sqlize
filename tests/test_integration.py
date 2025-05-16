"""Integration tests for nginx-sqlize."""

import os
import tempfile
import pytest
from pathlib import Path
from nginx_sqlize.database import Database
from nginx_sqlize.parser import NginxLogParser
from nginx_sqlize.main import process_log_file

# fixture to create a sample log file for testing
@pytest.fixture
def sample_log_file():
    """Create a temporary log file with test entries."""
    # create sample log content with various cases
    content = """192.168.1.1 - - [16/May/2025:00:06:10 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
192.168.1.2 - - [16/May/2025:00:06:11 +0000] "POST /api/data HTTP/1.1" 201 512 "-" "curl/7.68.0"
invalid log line that should be skipped
192.168.1.3 - - [16/May/2025:00:06:12 +0000] "DELETE /resource/123 HTTP/1.1" 204 0 "-" "PostmanRuntime/7.28.0"
192.168.1.4 - - [16/May/2025:00:06:13 +0000] "GET /not-found HTTP/1.1" 404 187 "https://example.com" "Googlebot/2.1"
"""
    
    # create a temporary file
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    
    # provide the file path
    yield path
    
    # cleanup after test
    os.unlink(path)

# fixture for a temporary database
@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db = Database(path)
    yield db
    db.close()
    os.unlink(path)

# test the complete process from file to database
def test_process_log_file(sample_log_file, temp_db):
    """Test processing an entire log file."""
    # process the sample log file
    processed = process_log_file(
        db=temp_db,
        filename=sample_log_file,
        batch_size=10,
        force_reprocess=True
    )
    
    # should have processed 5 lines (4 valid + 1 invalid)
    assert processed == 5
    
    # should have inserted 4 valid records
    log_count = temp_db.get_log_count()
    assert log_count == 4
    
    # check for processed file record
    file_info = temp_db.get_processed_file(sample_log_file)
    assert file_info is not None
    assert file_info['lines_processed'] == 5
    assert file_info['filename'] == os.path.abspath(sample_log_file)

# test the parser and database working together
def test_parser_and_database_integration(temp_db):
    """Test parser and database working together."""
    # sample log line
    log_line = '192.168.1.5 - - [16/May/2025:00:07:10 +0000] "GET /special-page.html HTTP/1.1" 200 2048 "https://referrer.com" "Special Browser/1.0"'
    
    # parse the line directly into a tuple format for database
    parsed_tuple = NginxLogParser.parse_to_tuple(log_line)
    assert parsed_tuple is not None
    
    # insert directly into database
    temp_db.insert_logs([parsed_tuple])
    
    # verify it was stored correctly
    temp_db.cursor.execute("SELECT * FROM logs WHERE request_path = '/special-page.html'")
    result = temp_db.cursor.fetchone()
    
    # check the record
    assert result is not None
    assert result['remote_addr'] == '192.168.1.5'
    assert result['request_method'] == 'GET'
    assert result['status'] == 200
    assert result['referer'] == 'https://referrer.com'

# test resuming file processing
def test_resume_file_processing(sample_log_file, temp_db):
    """Test resuming file processing from last position."""
    # manually process just the first line to establish a position
    first_line_length = 0
    with open(sample_log_file, 'r') as f:
        first_line = f.readline()
        first_line_length = len(first_line.encode('utf-8'))
    
    # parse the first line
    parsed = NginxLogParser.parse_to_tuple(first_line)
    if parsed:
        temp_db.insert_logs([parsed])
    
    # update processed file record to simulate partial processing
    temp_db.update_processed_file(
        filename=os.path.abspath(sample_log_file),
        position=first_line_length,  # only processed first line
        lines=1,
        file_hash=temp_db.compute_file_hash(os.path.abspath(sample_log_file)) if hasattr(temp_db, 'compute_file_hash') else 'test_hash'
    )
    
    # now process the file normally (should resume)
    processed = process_log_file(
        db=temp_db,
        filename=sample_log_file,
        batch_size=10,
        force_reprocess=False  # important - don't force reprocess
    )
    
    # should have processed the remaining lines
    assert processed > 0
    
    # total records should be 4 (all valid log lines)
    log_count = temp_db.get_log_count()
    assert log_count == 4