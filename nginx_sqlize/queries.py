"""Query operations for Nginx logs."""

import sqlite3
from typing import Dict, List, Optional


class LogQueries:
    """Query operations for Nginx logs in SQLite database."""

    # initialize with a database connection
    def __init__(self, db_connection):
        """Initialize with a database connection.
        
        Args:
            db_connection: SQLite connection object
        """
        self.conn = db_connection
        self.cursor = db_connection.cursor()

    # get top paths by request count
    def get_top_paths(self, limit: int = 10) -> List[Dict]:
        """Get most requested paths.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of dictionaries with path and count information
        """
        try:
            query = """
            SELECT request_path, COUNT(*) as count
            FROM logs
            GROUP BY request_path
            ORDER BY count DESC
            LIMIT ?
            """
            
            self.cursor.execute(query, (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Error getting top paths: {e}")
            return []

    # get status code distribution
    def get_status_distribution(self) -> List[Dict]:
        """Get distribution of HTTP status codes.
        
        Returns:
            List of dictionaries with status code and count
        """
        try:
            query = """
            SELECT status, COUNT(*) as count
            FROM logs
            GROUP BY status
            ORDER BY count DESC
            """
            
            self.cursor.execute(query)
            return [dict(row) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Error getting status distribution: {e}")
            return []

    # get potential bot activity
    def get_bot_activity(self, limit: int = 10) -> List[Dict]:
        """Get potential bot activity based on user agent.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of dictionaries with bot info
        """
        try:
            query = """
            SELECT 
                user_agent, 
                COUNT(*) as request_count,
                COUNT(DISTINCT request_path) as unique_paths,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM logs
            WHERE 
                user_agent LIKE '%bot%' 
                OR user_agent LIKE '%spider%'
                OR user_agent LIKE '%crawler%'
                OR user_agent LIKE '%scan%'
            GROUP BY user_agent
            ORDER BY request_count DESC
            LIMIT ?
            """
            
            self.cursor.execute(query, (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Error getting bot activity: {e}")
            return []

    # get requests by time period
    def get_requests_by_time(self, period: str = 'day') -> List[Dict]:
        """Get request counts grouped by time period.
        
        Args:
            period: Time period ('day', 'hour')
            
        Returns:
            List of dictionaries with time period and count
        """
        try:
            if period == 'hour':
                time_format = "SUBSTR(timestamp, 1, 15)"  # Include hour
            else:
                time_format = "SUBSTR(timestamp, 1, 11)"  # Just the day
                
            query = f"""
            SELECT 
                {time_format} as time_period,
                COUNT(*) as count
            FROM logs
            GROUP BY time_period
            ORDER BY time_period DESC
            """
            
            self.cursor.execute(query)
            return [dict(row) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Error getting requests by time: {e}")
            return []

    # get error rates over time
    def get_error_rates(self, period: str = 'day') -> List[Dict]:
        """Get error rates over time.
        
        Args:
            period: Time period ('day', 'hour')
            
        Returns:
            List of dictionaries with time period and error rates
        """
        try:
            if period == 'hour':
                time_format = "SUBSTR(timestamp, 1, 15)"  # Include hour
            else:
                time_format = "SUBSTR(timestamp, 1, 11)"  # Just the day
                
            query = f"""
            SELECT
                {time_format} as time_period,
                COUNT(*) as total_requests,
                SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as client_errors,
                SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as server_errors,
                ROUND(100.0 * SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) as error_rate
            FROM logs
            GROUP BY time_period
            ORDER BY time_period DESC
            """
            
            self.cursor.execute(query)
            return [dict(row) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Error getting error rates: {e}")
            return []

    # get top referrers
    def get_top_referrers(self, limit: int = 10) -> List[Dict]:
        """Get top referrers.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of dictionaries with referrer and count
        """
        try:
            query = """
            SELECT 
                referer, 
                COUNT(*) as count
            FROM logs
            WHERE referer != '-' AND referer != ''
            GROUP BY referer
            ORDER BY count DESC
            LIMIT ?
            """
            
            self.cursor.execute(query, (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Error getting top referrers: {e}")
            return []