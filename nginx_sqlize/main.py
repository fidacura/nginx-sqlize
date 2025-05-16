"""Command-line interface for nginx-sqlize."""

import os
import sys
import hashlib
import gzip
import logging
from pathlib import Path
from typing import List, Optional, Iterator, BinaryIO, TextIO

import click
from tqdm import tqdm

from nginx_sqlize.database import Database
from nginx_sqlize.parser import NginxLogParser

# configs
DEFAULT_BATCH_SIZE = 1000
DEFAULT_DB_PATH = 'nginx_logs.db'

# logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nginx-sqlize')


# compute a hash to detect if a file has changed
def compute_file_hash(filename: str, sample_size: int = 8192) -> str:
    """Compute a hash of the first bytes of a file to detect changes.

    Args:
        filename: Path to the file
        sample_size: Number of bytes to read from start of file

    Returns:
        Hex digest of the hash
    """
    try:
        with open(filename, 'rb') as f:
            sample = f.read(sample_size)
            return hashlib.md5(sample).hexdigest()
    except Exception as e:
        logger.error(f"Error computing file hash for {filename}: {e}")
        return ""


# open log file, handling both plain text and gzipped files
def open_log_file(filename: str) -> TextIO:
    """Open a log file, handling gzip if needed.

    Args:
        filename: Path to the log file

    Returns:
        File object
    """
    try:
        if filename.endswith('.gz'):
            return gzip.open(filename, 'rt', encoding='utf-8')
        return open(filename, 'r', encoding='utf-8')
    except Exception as e:
        logger.error(f"Error opening file {filename}: {e}")
        raise


# find all log files matching a pattern
def find_log_files(path_pattern: str) -> List[Path]:
    """Find log files matching the given pattern.
    
    Args:
        path_pattern: Glob pattern for log files
        
    Returns:
        List of Path objects for matching files
    """
    # Handle absolute and relative paths correctly
    if os.path.isabs(path_pattern):
        base_path = Path(os.path.dirname(path_pattern))
        pattern = os.path.basename(path_pattern)
        log_files = sorted(base_path.glob(pattern))
    else:
        log_files = sorted(Path().glob(path_pattern))
    
    # Filter out directories
    return [f for f in log_files if f.is_file()]


# process a single log file and insert entries into database
def process_log_file(
    db: Database, 
    filename: str, 
    batch_size: int = DEFAULT_BATCH_SIZE,
    force_reprocess: bool = False
) -> int:
    """Process a single log file and insert entries into the database.

    Args:
        db: Database instance
        filename: Path to the log file
        batch_size: Number of records to insert in a batch
        force_reprocess: Whether to reprocess the file even if already processed

    Returns:
        Number of processed lines
    """
    try:
        # get absolute path and file stats
        filename = os.path.abspath(filename)
        file_size = os.path.getsize(filename)
        file_hash = compute_file_hash(filename)
        
        if not file_hash:
            logger.warning(f"Could not compute hash for {filename}, will process anyway")
        
        # check if file was already processed
        processed = db.get_processed_file(filename)
        
        # skip if already processed and not forced to reprocess
        if processed and not force_reprocess:
            # if hash matches, skip the file
            if processed['file_hash'] == file_hash:
                click.echo(f"Skipping already processed file: {filename}")
                return 0
            else:
                click.echo(f"File has changed since last processing: {filename}")
        
        # determine starting position
        start_pos = 0
        if processed and not force_reprocess:
            start_pos = processed['last_position']
        
        # open and process the file
        line_count = 0
        parsed_count = 0
        batch = []
        
        with open_log_file(filename) as f:
            # skip to last position if resuming
            if start_pos > 0:
                f.seek(start_pos)
            
            # create progress bar
            with tqdm(total=file_size - start_pos, unit='B', unit_scale=True, desc=f"Processing {os.path.basename(filename)}") as pbar:
                for line in f:
                    current_pos = f.tell()
                    
                    # parse the line
                    parsed = NginxLogParser.parse_to_tuple(line)
                    if parsed:
                        batch.append(parsed)
                        parsed_count += 1
                        
                    # insert batch if it reaches the specified size
                    if len(batch) >= batch_size:
                        inserted = db.insert_logs(batch)
                        if inserted != len(batch):
                            logger.warning(f"Not all entries were inserted: {inserted}/{len(batch)}")
                        batch = []
                    
                    line_count += 1
                    pbar.update(len(line.encode('utf-8')))  # update progress based on bytes read
                    
                # insert any remaining records
                if batch:
                    db.insert_logs(batch)
        
        # update processed file information
        db.update_processed_file(
            filename=filename,
            position=file_size,  # whole file has been processed
            lines=line_count,
            file_hash=file_hash
        )
        
        logger.info(f"Processed {line_count} lines, extracted {parsed_count} valid entries from {filename}")
        return line_count
    
    except Exception as e:
        logger.error(f"Error processing {filename}: {e}")
        raise


# main command group for cli
@click.group()
def cli():
    """Process Nginx logs into SQLite database for easy querying."""
    pass


# command to ingest logs into the database
@cli.command()
@click.option(
    '--logs', 
    required=True, 
    help='Path to log file(s). Supports glob patterns (e.g., /var/log/nginx/*.log).'
)
@click.option(
    '--db', 
    default=DEFAULT_DB_PATH, 
    help=f'Path to SQLite database file. Default: {DEFAULT_DB_PATH}'
)
@click.option(
    '--batch-size', 
    default=DEFAULT_BATCH_SIZE, 
    help=f'Number of log entries to insert in a batch. Default: {DEFAULT_BATCH_SIZE}'
)
@click.option(
    '--force', 
    is_flag=True, 
    help='Reprocess files even if they have been processed before.'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Enable verbose output with additional processing details.'
)
def ingest(logs: str, db: str, batch_size: int, force: bool, verbose: bool):
    """Ingest Nginx logs into SQLite database."""
    # configure logging based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)
    
    # find log files matching pattern
    log_files = find_log_files(logs)
    
    if not log_files:
        click.echo(f"No log files found matching: {logs}")
        sys.exit(1)
    
    click.echo(f"Found {len(log_files)} log file(s) to process")
    
    # open database connection
    with Database(db) as database:
        total_processed = 0
        files_processed = 0
        
        # process each log file
        for log_file in log_files:
            try:
                processed = process_log_file(
                    db=database,
                    filename=str(log_file),
                    batch_size=batch_size,
                    force_reprocess=force
                )
                total_processed += processed
                if processed:
                    files_processed += 1
                    click.echo(f"Processed {processed} lines from {log_file}")
            except Exception as e:
                click.echo(f"Error processing {log_file}: {e}")
                if verbose:
                    import traceback
                    click.echo(traceback.format_exc())
        
        # show summary
        click.echo(f"\nSummary:")
        click.echo(f"- Files processed: {files_processed}/{len(log_files)}")
        click.echo(f"- Total lines processed: {total_processed}")
        click.echo(f"- Total entries in database: {database.get_log_count()}")
        click.echo(f"- Database location: {os.path.abspath(db)}")


# command to show database information
@cli.command()
@click.option(
    '--db',
    required=True,
    help='Path to SQLite database file.'
)
@click.option(
    '--status',
    is_flag=True,
    help='Show overall database statistics.'
)
def info(db: str, status: bool):
    """Display information about the database."""
    if not os.path.exists(db):
        click.echo(f"Database file not found: {db}")
        sys.exit(1)
        
    with Database(db) as database:
        click.echo(f"Database: {os.path.abspath(db)}")
        click.echo(f"Size: {os.path.getsize(db) / (1024*1024):.2f} MB")
        
        # database statistics
        if status:
            click.echo("\nDatabase Statistics:")
            click.echo(f"- Total log entries: {database.get_log_count()}")
            
            # get processed files
            try:
                database.cursor.execute("SELECT COUNT(*) as count FROM processed_files")
                result = database.cursor.fetchone()
                files_count = result['count'] if result else 0
                click.echo(f"- Processed files: {files_count}")
            except Exception as e:
                click.echo(f"Error getting processed files count: {e}")


if __name__ == '__main__':
    cli()