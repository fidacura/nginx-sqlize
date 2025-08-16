"""
nginx-sqlize query interface.
"""

import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import contextmanager
from datetime import datetime, timedelta
import re

from loguru import logger

# optional polars import
try:
    import polars as pl
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False


class QueryEngine:
    """
    Query engine for nginx log analytics.
    
    Provides high-level query interface with optimized sql patterns
    and polars integration for complex analytics operations.
    """
    
    # ========================= initialization and connection management =========================
    def __init__(self, db_path: str):
        """initialize query engine with database connection."""
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
    
    @contextmanager
    def _connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    # ========================= query execution helpers =========================
    def _execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute query and return results as list of dictionaries."""
        try:
            with self._connection() as conn:
                cursor = conn.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Query failed: {e}")
            return []
    
    def _execute_polars_query(self, query: str) -> pl.DataFrame:
        """Execute query and return polars dataframe for advanced analytics."""
        if not HAS_POLARS:
            logger.warning("Polars not available, returning empty dataframe")
            return None
        
        try:
            with self._connection() as conn:
                return pl.read_database(query, conn)
        except Exception as e:
            logger.error(f"Polars query failed: {e}")
            return pl.DataFrame()
    
    # ========================= basic overview and statistics =========================
    def overview(self) -> List[Dict[str, Any]]:
        """Get database overview with key metrics."""
        query = """
            WITH stats AS (
                SELECT 
                    COUNT(*) as total_requests,
                    COUNT(DISTINCT remote_addr) as unique_ips,
                    COUNT(DISTINCT request_path) as unique_paths,
                    MIN(timestamp) as earliest_log,
                    MAX(timestamp) as latest_log,
                    AVG(bytes_sent) as avg_response_size,
                    SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as error_rate
                FROM logs
            )
            SELECT 
                'total requests' as metric, 
                printf('%,d', total_requests) as value
            FROM stats
            UNION ALL
            SELECT 'unique ips', printf('%,d', unique_ips) FROM stats
            UNION ALL
            SELECT 'unique paths', printf('%,d', unique_paths) FROM stats  
            UNION ALL
            SELECT 'date range', earliest_log || ' → ' || latest_log FROM stats
            UNION ALL
            SELECT 'avg response size', printf('%.1f kb', avg_response_size/1024) FROM stats
            UNION ALL
            SELECT 'error rate', printf('%.2f%%', error_rate) FROM stats
            """
        return self._execute_query(query)
    
    def status_distribution(self) -> List[Dict[str, Any]]:
        """Get http status code distribution with categories."""
        query = """
        SELECT 
            status,
            COUNT(*) as count,
            printf('%.2f%%', COUNT(*) * 100.0 / (SELECT COUNT(*) FROM logs)) as percentage,
            CASE 
                WHEN status < 300 THEN 'success'
                WHEN status < 400 THEN 'redirect'
                WHEN status < 500 THEN 'client_error'
                ELSE 'server_error'
            END as category
        FROM logs
        GROUP BY status
        ORDER BY count DESC
        """
        return self._execute_query(query)
    
    def method_distribution(self) -> List[Dict[str, Any]]:
        """Get distribution of HTTP request methods."""
        query = """
        SELECT 
            request_method,
            COUNT(*) as count,
            printf('%.2f%%', COUNT(*) * 100.0 / (SELECT COUNT(*) FROM logs)) as percentage
        FROM logs
        WHERE request_method != ''
        GROUP BY request_method
        ORDER BY count DESC
        """
        return self._execute_query(query)
    
    # ========================= traffic and visitor analysis =========================
    def top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most active IP addresses."""
        query = """
        SELECT 
            remote_addr,
            COUNT(*) as requests,
            COUNT(DISTINCT request_path) as unique_paths,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen,
            SUM(bytes_sent) as total_bytes,
            printf('%.2f%%', COUNT(*) * 100.0 / (SELECT COUNT(*) FROM logs)) as percentage,
            CASE 
                WHEN remote_addr LIKE '10.%' OR remote_addr LIKE '192.168.%' 
                     OR remote_addr LIKE '172.%' THEN 'private'
                WHEN remote_addr LIKE '127.%' THEN 'localhost'
                ELSE 'public'
            END as ip_type
        FROM logs
        GROUP BY remote_addr
        ORDER BY requests DESC
        LIMIT ?
        """
        return self._execute_query(query, (limit,))

    def top_paths(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most requested paths with request counts."""
        query = """
        SELECT 
            request_path,
            COUNT(*) as requests,
            COUNT(DISTINCT remote_addr) as unique_visitors,
            AVG(bytes_sent) as avg_size_bytes,
            printf('%.1f%%', COUNT(*) * 100.0 / (SELECT COUNT(*) FROM logs)) as percentage
        FROM logs
        WHERE request_path != ''
        GROUP BY request_path
        ORDER BY requests DESC
        LIMIT ?
        """
        return self._execute_query(query, (limit,))
    
    def top_referrers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top referrers excluding direct traffic."""
        query = """
        SELECT 
            referer,
            COUNT(*) as requests,
            COUNT(DISTINCT remote_addr) as unique_visitors,
            printf('%.2f%%', COUNT(*) * 100.0 / (SELECT COUNT(*) FROM logs)) as percentage
        FROM logs
        WHERE referer != '-' AND referer != '' AND referer IS NOT NULL
        GROUP BY referer
        ORDER BY requests DESC
        LIMIT ?
        """
        return self._execute_query(query, (limit,))
    
    def traffic_analysis(self, time_period: str = 'hour') -> List[Dict[str, Any]]:
        """Analyze traffic patterns with peak detection."""
        time_format = {
            'hour': "substr(timestamp, 1, 15)",
            'day': "substr(timestamp, 1, 11)"
        }.get(time_period, "substr(timestamp, 1, 15)")
        
        query = f"""
        WITH traffic_data AS (
            SELECT 
                {time_format} as time_period,
                COUNT(*) as requests,
                COUNT(DISTINCT remote_addr) as unique_visitors,
                SUM(bytes_sent) as total_bytes,
                AVG(bytes_sent) as avg_response_size
            FROM logs
            GROUP BY time_period
        ),
        traffic_stats AS (
            SELECT 
                AVG(requests) as avg_requests,
                (SELECT requests FROM traffic_data ORDER BY requests DESC LIMIT 1) as peak_requests
            FROM traffic_data
        )
        SELECT 
            td.time_period,
            td.requests,
            td.unique_visitors,
            printf('%.2f mb', td.total_bytes / 1024.0 / 1024.0) as bandwidth,
            printf('%.1f kb', td.avg_response_size / 1024.0) as avg_response_size,
            CASE 
                WHEN td.requests > ts.avg_requests * 2 THEN 'peak'
                WHEN td.requests < ts.avg_requests * 0.5 THEN 'low'
                ELSE 'normal'
            END as traffic_level
        FROM traffic_data td
        CROSS JOIN traffic_stats ts
        ORDER BY td.time_period DESC
        LIMIT 100
        """
        return self._execute_query(query)
    
    # ========================= security and threat analysis =========================
    def analyze_bot_activity(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Identify bot activity with simple behavioral analysis."""
        query = """
        SELECT 
            user_agent,
            COUNT(*) as requests,
            COUNT(DISTINCT request_path) as unique_paths,
            COUNT(DISTINCT remote_addr) as unique_ips,
            printf('%.2f', COUNT(*) * 1.0 / COUNT(DISTINCT request_path)) as requests_per_path,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen,
            CASE 
                WHEN user_agent LIKE '%bot%' OR user_agent LIKE '%spider%' 
                     OR user_agent LIKE '%crawler%' THEN 'identified_bot'
                WHEN COUNT(*) > 1000 AND COUNT(DISTINCT request_path) < 10 THEN 'suspicious_bot'
                WHEN COUNT(*) > 100 AND user_agent LIKE '%curl%' THEN 'api_client'
                ELSE 'unknown'
            END as bot_type
        FROM logs
        WHERE 
            user_agent LIKE '%bot%' OR user_agent LIKE '%spider%' OR 
            user_agent LIKE '%crawler%' OR user_agent LIKE '%scan%' OR
            (user_agent LIKE '%curl%' AND user_agent NOT LIKE '%Mozilla%')
        GROUP BY user_agent
        ORDER BY requests DESC
        LIMIT ?
        """
        return self._execute_query(query, (limit,))
    
    def detect_security_threats(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Detect potential attack patterns with simple threat classification."""
        query = """
        SELECT 
            request_path,
            remote_addr,
            COUNT(*) as attempts,
            COUNT(DISTINCT DATE(substr(timestamp, 1, 11))) as days_active,
            MAX(status) as max_status,
            user_agent,
            CASE 
                WHEN request_path LIKE '%../../%' THEN 'directory_traversal'
                WHEN request_path LIKE '%.php%' AND request_path LIKE '%admin%' THEN 'php_admin_probe'
                WHEN request_path LIKE '%wp-%' THEN 'wordpress_probe'
                WHEN request_path LIKE '%.git%' OR request_path LIKE '%.env%' THEN 'config_file_probe'
                WHEN request_path LIKE '%shell%' OR request_path LIKE '%cmd%' THEN 'shell_probe'
                WHEN request_path LIKE '%passwd%' OR request_path LIKE '%shadow%' THEN 'system_file_probe'
                WHEN request_path LIKE '%sql%' OR request_path LIKE '%union%' THEN 'sql_injection'
                WHEN request_path LIKE '%script%' OR request_path LIKE '%alert%' THEN 'xss_probe'
                ELSE 'generic_probe'
            END as attack_type
        FROM logs
        WHERE 
            request_path LIKE '%../../%' OR request_path LIKE '%.php%' OR
            request_path LIKE '%shell%' OR request_path LIKE '%admin%' OR
            request_path LIKE '%wp-%' OR request_path LIKE '%.git%' OR
            request_path LIKE '%passwd%' OR request_path LIKE '%.env%' OR
            request_path LIKE '%credentials%' OR request_path LIKE '%config%' OR
            request_path LIKE '%sql%' OR request_path LIKE '%union%' OR
            request_path LIKE '%script%' OR request_path LIKE '%alert%'
        GROUP BY request_path, remote_addr
        ORDER BY attempts DESC, days_active DESC
        LIMIT ?
        """
        return self._execute_query(query, (limit,))
    
    # ========================= error and performance analysis =========================
    def error_analysis(self, time_period: str = 'hour') -> List[Dict[str, Any]]:
        """Analyze error patterns over time with detailed breakdown."""
        time_format = {
            'hour': "substr(timestamp, 1, 15)",
            'day': "substr(timestamp, 1, 11)"
        }.get(time_period, "substr(timestamp, 1, 15)")
        
        query = f"""
        SELECT 
            {time_format} as time_period,
            COUNT(*) as total_requests,
            SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as client_errors,
            SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as server_errors,
            printf('%.2f%%', 
                SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)
            ) as error_rate,
            MAX(CASE WHEN status >= 400 THEN request_path ELSE NULL END) as top_error_path
        FROM logs
        GROUP BY time_period
        HAVING SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) > 0
        ORDER BY time_period DESC
        LIMIT 50
        """
        return self._execute_query(query)
    
    def generate_performance_metrics(self) -> List[Dict[str, Any]]:
        """Calculate performance and efficiency metrics."""
        query = """
        WITH performance_data AS (
            SELECT 
                request_path,
                COUNT(*) as requests,
                AVG(bytes_sent) as avg_size,
                MAX(bytes_sent) as max_size,
                SUM(bytes_sent) as total_size,
                COUNT(CASE WHEN status >= 400 THEN 1 END) as errors,
                COUNT(CASE WHEN status = 200 THEN 1 END) as success_count
            FROM logs
            WHERE request_path != ''
            GROUP BY request_path
            HAVING requests >= 10
        )
        SELECT 
            request_path,
            requests,
            printf('%.1f kb', avg_size / 1024.0) as avg_response_size,
            printf('%.2f mb', total_size / 1024.0 / 1024.0) as total_bandwidth,
            printf('%.2f%%', errors * 100.0 / requests) as error_rate,
            printf('%.2f%%', success_count * 100.0 / requests) as success_rate,
            CASE 
                WHEN avg_size > 1024*1024 THEN 'large_response'
                WHEN errors * 100.0 / requests > 10 THEN 'high_error_rate'
                WHEN requests > 1000 THEN 'high_traffic'
                ELSE 'normal'
            END as performance_flag
        FROM performance_data
        ORDER BY total_size DESC
        LIMIT 50
        """
        return self._execute_query(query)
    
    # ========================= database maintenance operations =========================
    def vacuum(self) -> bool:
        """Optimize database by running vacuum operation."""
        try:
            with self._connection() as conn:
                conn.execute("VACUUM")
                logger.info("Database vacuum completed successfully")
                return True
        except sqlite3.Error as e:
            logger.error(f"Vacuum operation failed: {e}")
            return False
    
    def delete_old_logs(self, older_than: str) -> int:
        """Delete logs older than specified period (e.g., '30d', '1y')."""
        # parse time period
        match = re.match(r'(\d+)([dwmy])', older_than.lower())
        if not match:
            raise ValueError("Invalid time format. use format like '30d', '1y', etc.")
        
        amount, unit = match.groups()
        amount = int(amount)
        
        # calculate cutoff date
        now = datetime.now()
        
        if unit == 'd':
            cutoff = now - timedelta(days=amount)
        elif unit == 'w':
            cutoff = now - timedelta(weeks=amount)
        elif unit == 'm':
            cutoff = now - timedelta(days=amount * 30)  # approximate
        elif unit == 'y':
            cutoff = now - timedelta(days=amount * 365)  # approximate
        else:
            raise ValueError(f"Unsupported time unit: {unit}")
        
        cutoff_str = cutoff.strftime("%d/%b/%Y")
        
        try:
            with self._connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM logs WHERE timestamp < ?",
                    (cutoff_str,)
                )
                deleted_count = cursor.rowcount
                conn.commit()
                logger.info(f"Deleted {deleted_count} log entries older than {older_than}")
                return deleted_count
        except sqlite3.Error as e:
            logger.error(f"Failed to delete old logs: {e}")
            return 0
    
    def detect_duplicates(self) -> int:
        """Detect how many duplicate entries exist - faster method."""
        try:
            with self._connection() as conn:
                # much faster: just check for exact duplicate timestamps and IPs
                cursor = conn.execute("""
                    SELECT COUNT(*) as duplicates FROM (
                        SELECT timestamp, remote_addr, request_path, COUNT(*) as cnt
                        FROM logs
                        GROUP BY timestamp, remote_addr, request_path
                        HAVING cnt > 1
                    )
                """)
                result = cursor.fetchone()
                return result[0] if result else 0
        except sqlite3.Error as e:
            logger.error(f"Failed to detect duplicates: {e}")
            return 0
    
    def remove_duplicates(self) -> int:
        """Remove duplicate log entries based on key fields."""
        try:
            with self._connection() as conn:
                # find and delete duplicates, keeping the first occurrence
                cursor = conn.execute("""
                    DELETE FROM logs 
                    WHERE id NOT IN (
                        SELECT MIN(id) 
                        FROM logs 
                        GROUP BY timestamp, remote_addr, request_method, 
                                request_path, status, bytes_sent, user_agent
                    )
                """)
                deleted_count = cursor.rowcount
                conn.commit()
                logger.info(f"Removed {deleted_count} duplicate log entries")
                return deleted_count
        except sqlite3.Error as e:
            logger.error(f"Failed to remove duplicates: {e}")
            return 0
    
    # ========================= export and data output =========================
    def export_to_csv(self, output_path: str, query_type: str = 'all', limit: int = 10000) -> bool:
        """Export query results to csv file."""
        if HAS_POLARS:
            # use polars for performance if available
            try:
                if query_type == 'all':
                    df = self._execute_polars_query(f"SELECT * FROM logs LIMIT {limit}")
                elif query_type == 'errors':
                    df = self._execute_polars_query(
                        f"SELECT * FROM logs WHERE status >= 400 LIMIT {limit}"
                    )
                elif query_type == 'summary':
                    df = self._execute_polars_query("""
                        SELECT 
                            substr(timestamp, 1, 11) as date,
                            COUNT(*) as requests,
                            COUNT(DISTINCT remote_addr) as unique_ips,
                            SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
                        FROM logs 
                        GROUP BY date 
                        ORDER BY date DESC
                    """)
                else:
                    logger.error(f"Unsupported export type: {query_type}")
                    return False
                
                df.write_csv(output_path)
                logger.info(f"Exported {len(df)} rows to {output_path}")
                return True
                
            except Exception as e:
                logger.error(f"Export failed: {e}")
                return False
        else:
            # fallback to manual csv writing
            import csv
            
            try:
                if query_type == 'all':
                    query = f"SELECT * FROM logs LIMIT {limit}"
                elif query_type == 'errors':
                    query = f"SELECT * FROM logs WHERE status >= 400 LIMIT {limit}"
                elif query_type == 'summary':
                    query = """
                        SELECT 
                            substr(timestamp, 1, 11) as date,
                            COUNT(*) as requests,
                            COUNT(DISTINCT remote_addr) as unique_ips,
                            SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
                        FROM logs 
                        GROUP BY date 
                        ORDER BY date DESC
                    """
                else:
                    logger.error(f"Unsupported export type: {query_type}")
                    return False
                
                results = self._execute_query(query)
                
                if not results:
                    logger.warning("No data to export")
                    return False
                
                with open(output_path, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)
                
                logger.info(f"Exported {len(results)} rows to {output_path}")
                return True
                
            except Exception as e:
                logger.error(f"Export failed: {e}")
                return False