"""Tests for the Nginx log parser."""

import pytest
from nginx_sqlize.parser import NginxLogParser


# test that a valid log line is parsed correctly
def test_valid_log_parsing():
    """Test parsing a valid log line."""
    # sample log in combined format
    sample_log = '78.153.140.148 - - [16/May/2025:00:06:10 +0000] "GET /.env HTTP/1.1" 404 187 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    
    # parse the log line
    result = NginxLogParser.parse_line(sample_log)
    
    # verify expected values are extracted
    assert result is not None
    assert result['remote_addr'] == '78.153.140.148'
    assert result['request_method'] == 'GET'
    assert result['request_path'] == '/.env'
    assert result['status'] == 404
    assert result['bytes_sent'] == 187


# test how parser handles invalid log formats
def test_invalid_log_parsing():
    """Test handling of invalid log lines."""
    # completely invalid log line
    result = NginxLogParser.parse_line("This is not a valid log line")
    assert result is None
    
    # test empty input
    result = NginxLogParser.parse_line("")
    assert result is None
    
    # test None input
    result = NginxLogParser.parse_line(None)
    assert result is None


# test how parser handles log lines with malformed request parts
def test_malformed_request():
    """Test handling of malformed requests."""
    # log with empty request
    sample_log = '192.168.1.1 - - [16/May/2025:00:06:10 +0000] "" 400 0 "-" "-"'
    
    # parse the malformed log
    result = NginxLogParser.parse_line(sample_log)
    
    # verify parser handles it gracefully
    assert result is not None
    assert result['request_method'] == ''
    assert result['request_path'] == ''
    assert result['http_version'] == ''
    assert result['status'] == 400