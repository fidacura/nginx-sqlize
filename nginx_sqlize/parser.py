"""Log parser for Nginx logs."""

import re
from datetime import datetime
from typing import Dict, Optional, Tuple


class NginxLogParser:
    """Parser for Nginx logs in combined format."""

    # regular expression for the "combined log format"
    # format: %remote_addr - %remote_user [%time_local] "%request" %status %body_bytes_sent "%http_referer" "%http_user_agent"
    COMBINED_LOG_PATTERN = re.compile(
        r'(?P<remote_addr>[\d\.]+) - (?P<remote_user>[^ ]*) \[(?P<time_local>.*?)\] '
        r'"(?P<request>.*?)" (?P<status>\d+) (?P<bytes_sent>\d+) '
        r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
    )

    @classmethod
    def parse_line(cls, line: str) -> Optional[Dict]:
        """Parse a single log line in combined format.

        Args:
            line: Raw log line string

        Returns:
            Dictionary with parsed fields or None if parsing failed
        """
        # handle empty lines gracefully
        if not line or not line.strip():
            return None

        # try to match the log line against our pattern
        match = cls.COMBINED_LOG_PATTERN.match(line.strip())
        if not match:
            # uncomment for debugging malformed lines
            # print(f"Failed to parse line: {line}")
            return None

        # extract matched groups into a dictionary
        data = match.groupdict()
        
        # parse the request into its components (method, path, version)
        request_parts = data['request'].split()
        if len(request_parts) >= 3:
            data['request_method'] = request_parts[0]
            data['request_path'] = request_parts[1]
            data['http_version'] = request_parts[2]
        elif len(request_parts) == 2:
            data['request_method'] = request_parts[0]
            data['request_path'] = request_parts[1]
            data['http_version'] = ''
        else:
            # handle malformed or empty requests
            data['request_method'] = data['request'] if data['request'] else ''
            data['request_path'] = ''
            data['http_version'] = ''
        
        # clean-up and type-conversion with defensive programming
        try:
            data['status'] = int(data['status']) if data['status'].isdigit() else 0
        except (ValueError, TypeError):
            data['status'] = 0
            
        try:
            data['bytes_sent'] = int(data['bytes_sent']) if data['bytes_sent'].isdigit() else 0
        except (ValueError, TypeError):
            data['bytes_sent'] = 0
        
        # add original timestamp for database storage
        data['timestamp'] = data['time_local']
        
        # remove the now split-up request
        del data['request']
        
        return data

    @classmethod
    def parse_to_tuple(cls, line: str) -> Optional[Tuple]:
        """Parse a log line and return data in the format required for database insertion.

        Args:
            line: Raw log line string

        Returns:
            Tuple of values ready for database insertion or None if parsing failed
        """
        try:
            # parse the line into a dictionary
            data = cls.parse_line(line)
            if not data:
                return None
                
            # create a tuple in the exact order needed for the database
            # order must match: timestamp, remote_addr, remote_user, request_method, 
            # request_path, http_version, status, bytes_sent, referer, user_agent, processed_at
            now = datetime.now().isoformat()
            return (
                data['timestamp'],
                data['remote_addr'],
                data['remote_user'],
                data['request_method'],
                data['request_path'],
                data['http_version'],
                data['status'],
                data['bytes_sent'],
                data['referer'],
                data['user_agent'],
                now  # processed_at
            )
        except Exception as e:
            # catch any unexpected errors during parsing
            print(f"Error parsing line to tuple: {e}")
            return None