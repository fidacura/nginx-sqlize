"""
nginx-sqlize streamlined cli interface.
"""

from pathlib import Path
from typing import Optional, List, Dict, Any
import json
import sys

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

try:
    from .core import create_processor, translate_error_message, validate_positive_int
    from .queries import QueryEngine
    from . import __version__
except ImportError:
    # fallback for direct execution
    from core import create_processor, translate_error_message, validate_positive_int
    from queries import QueryEngine
    import __init__
    __version__ = __init__.__version__


# initialize rich console and typer app
console = Console()
app = typer.Typer(
    name="nginx-sqlize",
    help="Process Nginx logs into SQLite for easy querying and analysis.",
    rich_markup_mode="rich"
)


# ========================= version callback =========================

def version_callback(value: bool):
    """Show version and exit."""
    if value:
        typer.echo(f"nginx-sqlize {__version__}")
        raise typer.Exit()

# ========================= main callback for version option =========================

@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None, 
        "--version", 
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit"
    )
):
    """nginx-sqlize: Process Nginx logs into SQLite for easy querying and analysis."""
    pass


# ========================= commands ~ data ingestion =========================

@app.command()
def ingest(
    logs: str = typer.Argument(..., help="Log file pattern (e.g., /var/log/nginx/*.log)"),
    db: Optional[str] = typer.Option(None, "--db", "-d", help="Database path (auto-generated if not specified)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output database name (without extension)"),
    batch_size: int = typer.Option(10000, "--batch-size", "-b", help="Batch size for processing"),
    force: bool = typer.Option(False, "--force", "-f", help="Reprocess all files"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
) -> None:
    """
    Ingest nginx logs into sqlite database.

    Automatically handles gzipped files, resumable processing, and
    provides real-time progress feedback with rich output.
    """
    
    if verbose:
        console.print("[dim]Initializing processor...[/dim]")
    
    # validate cli parameters to prevent crashes
    validate_positive_int(batch_size, "batch_size", 100000)
    
    # smart database naming logic
    db_path = _determine_database_path(logs, db, output, verbose)
    
    # validate database path for safety
    db_path = _validate_db_path(db_path)
    
    # create processor with configuration
    processor = create_processor(
        db_path=db_path,
        batch_size=batch_size
    )
    
    # setup logging based on verbose mode
    processor.setup_logging(verbose)
    
    # find log files
    log_files = processor.find_log_files(logs)
    
    if not log_files:
        console.print(f"[red]❌ No log files found matching: {logs}[/red]")
        raise typer.Exit(1)
    
    if verbose:
        console.print(f"[green]🔍 Found {len(log_files)} log files[/green]")
        console.print(f"[dim]📄 Database: {db_path}[/dim]")
        
        # warn user about force mode
        if force:
            console.print("[bright_yellow]⚠️  Force mode enabled ~ may create duplicate entries[/bright_yellow]")
    else:
        # non-verbose: just show essential info
        if force:
            console.print("[bright_yellow]⚠️  Force mode: may create duplicates[/bright_yellow]")
    
    # process files with progress tracking
    total_processed = 0
    total_inserted = 0
    
    if verbose:
        # verbose mode: show detailed progress with spinner
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for log_file in log_files:
                task = progress.add_task(f"Processing {log_file.name}", total=None)
                
                try:
                    result = processor.process_file(log_file, force=force)
                    total_processed += result['processed']
                    total_inserted += result['inserted']
                    
                    if result['processed'] == 0:
                        progress.update(
                            task, 
                            description=f"⭐️ {log_file.name} (already processed)"
                        )
                    else:
                        progress.update(
                            task, 
                            description=f"✅ {log_file.name} ({result['processed']} lines)"
                        )
                    
                except Exception as e:
                    error_msg = translate_error_message(e, str(log_file))
                    console.print(f"[red]❌ {log_file.name}: {error_msg}[/red]")
    
    else:
        # non-verbose mode: simple, clean output
        for log_file in log_files:
            try:
                result = processor.process_file(log_file, force=force)
                total_processed += result['processed']
                total_inserted += result['inserted']
                
                if result['processed'] == 0:
                    console.print(f"[yellow]⭐️ {log_file.name} already processed[/yellow]")
                else:
                    console.print(f"[green]✅ {log_file.name} ({result['processed']:,} lines)[/green]")
                
            except Exception as e:
                error_msg = translate_error_message(e, str(log_file))
                console.print(f"[red]❌ {log_file.name}: {error_msg}[/red]")
    
    # show summary
    stats = processor.get_stats()
    
    # only show debug info in verbose mode
    if verbose:
        console.print("[dim]Refreshing database statistics...[/dim]")
    
    # determine summary style and message based on what actually happened
    if total_processed == 0:
        # nothing was processed ~ all files were skipped
        summary_style = "yellow"
        summary_icon = "⭐️"
        summary_title = "Files Already Processed"
        summary_message = f"""[yellow]{summary_icon} All files were already processed![/yellow]
        
        📊 Processed: {total_processed:,} lines
        💾 Inserted: {total_inserted:,} entries  
        🔍 Total in db: {stats['total_logs']:,} entries
        💽 Database: [bold]{db_path}[/bold] ({stats['database_size_mb']:.1f} mb)

        [dim]💡 Tip: use --force to reprocess files or check different log files[/dim]"""
    
    elif force and total_processed > 0:
        # force mode was used ~ warn about potential duplicates
        summary_style = "bright_yellow"
        summary_icon = "⚠️"
        summary_title = "Force Reprocessing Complete"
        summary_message = f"""[bright_yellow]{summary_icon} Force reprocessing complete![/bright_yellow]
        
        📊 Processed: {total_processed:,} lines
        💾 Inserted: {total_inserted:,} entries  
        🔍 Total in db: {stats['total_logs']:,} entries
        💽 Database: [bold]{db_path}[/bold] ({stats['database_size_mb']:.1f} mb)

        [bright_yellow]⚠️  Warning: force mode may have created duplicate entries[/bright_yellow]
        [dim]💡 Tip: use 'nginx-sqlize clean --duplicates' to remove duplicates[/dim]"""
            
    else:
        # normal successful processing
        summary_style = "green"
        summary_icon = "✨"
        summary_title = "Processing Complete"
        summary_message = f"""[green]{summary_icon} Ingestion complete![/green]
        
        📊 Processed: {total_processed:,} lines
        💾 Inserted: {total_inserted:,} entries  
        🔍 Total in db: {stats['total_logs']:,} entries
        💽 Database: [bold]{db_path}[/bold] ({stats['database_size_mb']:.1f} mb)"""
    
    summary_panel = Panel.fit(
        summary_message,
        title=summary_title,
        border_style=summary_style
    )
    
    console.print(summary_panel)


# ========================= commands ~ data querying =========================

@app.command()
def query(
    db: Optional[str] = typer.Option(None, "--db", "-d", help="Database path(s) ~ single file, pattern, or comma-separated list"),
    top_ips: Optional[int] = typer.Option(None, "--top-ips", help="Show top N IP addresses"),
    top_paths: Optional[int] = typer.Option(None, "--top-paths", help="Show top N paths"),
    status_codes: bool = typer.Option(False, "--status-codes", help="Show status distribution"),
    methods: bool = typer.Option(False, "--methods", help="Show HTTP method distribution"),
    referrers: Optional[int] = typer.Option(None, "--referrers", help="Show top N referrers"),
    response_sizes: Optional[int] = typer.Option(None, "--response-sizes", help="Show paths with largest response sizes"),
    traffic: Optional[str] = typer.Option(None, "--traffic", help="Show traffic patterns (hour/day)"),
    errors: bool = typer.Option(False, "--errors", help="Show error analysis"),
    bots: Optional[int] = typer.Option(None, "--bots", help="Show bot activity"),
    attacks: Optional[int] = typer.Option(None, "--attacks", help="Show potential attacks"),
    export: Optional[str] = typer.Option(None, "--export", help="Export to JSON file"),
    limit: int = typer.Option(10, "--limit", "-l", help="Result limit"),
    combine: bool = typer.Option(False, "--combine", help="Combine results from multiple databases")
) -> None:
    """
    Query nginx logs with smart analytics.
    
    examples:
      nginx-sqlize query --top-paths 10
      nginx-sqlize query --top-ips 20
      nginx-sqlize query --traffic hour
      nginx-sqlize query --attacks 15
    """
    
    # validate query parameters to prevent crashes
    validate_positive_int(limit, "limit", 10000)
    
    if top_ips:
        validate_positive_int(top_ips, "top_ips", 1000)
    if top_paths:
        validate_positive_int(top_paths, "top_paths", 1000)
    if referrers:
        validate_positive_int(referrers, "referrers", 1000)
    if response_sizes:
        validate_positive_int(response_sizes, "response_sizes", 1000)
    if bots:
        validate_positive_int(bots, "bots", 1000)
    if attacks:
        validate_positive_int(attacks, "attacks", 1000)
    
    # resolve database files
    db_files = _resolve_database_files(db)
    
    if len(db_files) == 1:
        # single database ~ normal operation
        _query_single_database(
            db_files[0], top_paths, top_ips, status_codes, methods, 
            referrers, response_sizes, traffic, errors, bots, attacks, 
            export, limit
        )
    else:
        # multiple databases
        if combine:
            _query_multiple_databases_combined(
                db_files, top_paths, top_ips, status_codes, 
                methods, referrers, response_sizes, traffic, errors, 
                bots, attacks, export, limit
            )
        else:
            _query_multiple_databases_separate(
                db_files, top_paths, top_ips, status_codes, 
                methods, referrers, response_sizes, traffic, errors, 
                bots, attacks, export, limit
            )


# ========================= commands ~ management =========================

@app.command()
def status(
    db: Optional[str] = typer.Option(None, "--db", "-d", help="Database path (auto-detects if not specified)")
) -> None:
    """
    Show database status and statistics.

    Displays comprehensive information about processed files,
    log counts, date ranges, and database health.
    """
    
    # auto-detect database if not specified
    db_path = _auto_detect_database(db)
    
    if not Path(db_path).exists():
        console.print(f"[red]❌ Database not found: {db_path}[/red]")
        _suggest_available_databases()
        raise typer.Exit(1)
    
    processor = create_processor(db_path=db_path)
    stats = processor.get_stats()
    
    # create status display
    status_content = f"""
[bold cyan]📊 Database statistics[/bold cyan]

📁 Database path: {db_path}
💽 File size: {stats['database_size_mb']:.1f} mb
🔍 Total log entries: {stats['total_logs']:,}
📂 Processed files: {stats['processed_files']}

[bold cyan]📅 Date range[/bold cyan]
{_format_date_range(stats.get('date_range', {}))}

[bold cyan]🚦 Top status codes[/bold cyan]
{_format_status_codes(stats.get('top_status_codes', []))}
"""
            
    console.print(Panel(status_content, title="nginx-sqlize status", border_style="blue"))

@app.command()
def clean(
    db: Optional[str] = typer.Option(None, "--db", "-d", help="Database path (auto-detects if not specified)"),
    vacuum: bool = typer.Option(True, "--vacuum", help="Vacuum database after cleaning"),
    older_than: Optional[str] = typer.Option(None, "--older-than", help="Remove logs older than (e.g., '30d', '1y')"),
    duplicates: bool = typer.Option(False, "--duplicates", help="Remove duplicate log entries"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
) -> None:
    """
    Clean and optimize database.
    
    Removes old logs, duplicates, and optimizes database
    for better performance and reduced size.
    """
    
    # auto-detect database if not specified
    db_path = _auto_detect_database(db)
    
    if not Path(db_path).exists():
        console.print(f"[red]❌ Database not found: {db_path}[/red]")
        _suggest_available_databases()
        raise typer.Exit(1)
    
    if not confirm:
        operations = []
        if older_than:
            operations.append(f"Delete logs older than {older_than}")
        if duplicates:
            operations.append("Remove duplicate entries")
        if vacuum:
            operations.append("Vacuum/optimize database")
        
        if operations:
            op_list = ", ".join(operations)
            confirm = typer.confirm(f"This will {op_list}. continue?")
            if not confirm:
                console.print("[yellow]Operation cancelled[/yellow]")
                return
    
    query_engine = QueryEngine(db_path)
    
    with console.status("[bold green]Cleaning database...") as status:
        # check for duplicates first
        if duplicates:
            status.update("[bold green]Checking for duplicates...")
            duplicate_count = query_engine.detect_duplicates()
            if duplicate_count > 0:
                console.print(f"[yellow]📋 Found {duplicate_count:,} duplicate entries[/yellow]")
                deleted = query_engine.remove_duplicates()
                console.print(f"[green]🗑️  Removed {deleted:,} duplicate entries[/green]")
            else:
                console.print("[green]✅ No duplicates found[/green]")
        
        # remove old logs if specified
        if older_than:
            status.update(f"[bold green]Removing logs older than {older_than}...")
            deleted = query_engine.delete_old_logs(older_than)
            console.print(f"[green]🗑️  Deleted {deleted:,} old log entries[/green]")
        
        # vacuum database if requested
        if vacuum:
            status.update("[bold green]Optimizing database...")
            query_engine.vacuum()
            console.print("[green]✨ Database optimized[/green]")
    
    # show new statistics
    processor = create_processor(db_path=db_path)
    stats = processor.get_stats()
    
    console.print(f"[green]✅ Cleanup complete! Database now {stats['database_size_mb']:.1f} mb[/green]")


# ========================= database file resolution helpers =========================

def _resolve_database_files(db_arg: Optional[str]) -> List[str]:
    """Resolve database file specification to list of actual files."""
    if not db_arg:
        # auto-detect single database
        return [_auto_detect_database(None)]
    
    db_files = []
    
    # handle comma-separated list
    if ',' in db_arg:
        for db_path in db_arg.split(','):
            db_path = db_path.strip()
            if not Path(db_path).exists():
                console.print(f"[red]❌ Database not found: {db_path}[/red]")
                raise typer.Exit(1)
            db_files.append(db_path)
    
    # handle glob pattern
    elif '*' in db_arg or '?' in db_arg:
        matched_files = list(Path.cwd().glob(db_arg))
        db_files = [str(f) for f in matched_files if f.suffix in ['.sqlite', '.db']]
        
        if not db_files:
            console.print(f"[red]❌ No database files match pattern: {db_arg}[/red]")
            raise typer.Exit(1)
    
    # single file
    else:
        if not Path(db_arg).exists():
            console.print(f"[red]❌ Database not found: {db_arg}[/red]")
            _suggest_available_databases()
            raise typer.Exit(1)
        db_files = [db_arg]
    
    return db_files

def _auto_detect_database(db_path: Optional[str]) -> str:
    """
    Auto-detect database file only when unambiguous.
    
    rules:
    1. if db_path specified, use it
    2. if exactly one database file exists, use it
    3. otherwise, require explicit specification
    """
    if db_path:
        return db_path
    
    # look for database files in current directory
    current_dir = Path.cwd()
    
    db_files = [
        *current_dir.glob("*.sqlite"),
        *current_dir.glob("*.db"),
    ]
    
    if len(db_files) == 1:
        # exactly one database file ~ safe to auto-detect
        console.print(f"[dim]Auto-detected: {db_files[0].name}[/dim]")
        return str(db_files[0])
    elif len(db_files) == 0:
        # no database files found
        console.print("[red]❌ No database files found[/red]")
        console.print("[dim]Tip: run 'nginx-sqlize ingest <logfile>' first to create a database[/dim]")
        raise typer.Exit(1)
    else:
        # multiple database files ~ require explicit specification
        console.print(f"[red]❌ Multiple database files found ({len(db_files)}), please specify one:[/red]")
        for db_file in sorted(db_files):
            size_mb = db_file.stat().st_size / (1024 * 1024)
            console.print(f"  • {db_file.name} ({size_mb:.1f} mb)")
        console.print("[dim]Tip: use --db <filename> to specify which database to use[/dim]")
        raise typer.Exit(1)

def _suggest_available_databases() -> None:
    """Suggest available database files in current directory."""
    current_dir = Path.cwd()
    db_files = list(current_dir.glob("*.sqlite")) + list(current_dir.glob("*.db"))
    
    if db_files:
        console.print("[yellow]🔍 Available databases in current directory:[/yellow]")
        for db_file in sorted(db_files):
            size_mb = db_file.stat().st_size / (1024 * 1024)
            console.print(f"  • {db_file.name} ({size_mb:.1f} mb)")
        console.print("[dim]Tip: use --db <filename> to specify a database[/dim]")
    else:
        console.print("[dim]Tip: run 'nginx-sqlize ingest <logfile>' first to create a database[/dim]")


# ========================= query handlers =========================

def _query_single_database(
    db_path: str, top_paths: Optional[int], 
    top_ips: Optional[int], status_codes: bool, methods: bool,
    referrers: Optional[int], response_sizes: Optional[int], 
    traffic: Optional[str], errors: bool, bots: Optional[int], 
    attacks: Optional[int], export: Optional[str], limit: int
) -> None:
    """Query a single database."""
    query_engine = QueryEngine(db_path)
    results = []
    title = ""
    display_limit = limit
    
    # execute queries based on flags
    if top_paths:
        results = query_engine.top_paths(top_paths)
        title = f"Top {top_paths} Requested Paths"
        display_limit = top_paths
        
    elif top_ips:
        results = query_engine.top_ips(top_ips)
        title = f"Top {top_ips} IP Addresses"
        display_limit = top_ips
        
    elif status_codes:
        results = query_engine.status_distribution()
        title = "Status Code Distribution"
        display_limit = len(results)
        
    elif methods:
        results = query_engine.method_distribution()
        title = "HTTP Method Distribution"
        display_limit = len(results)
        
    elif referrers:
        results = query_engine.top_referrers(referrers)
        title = f"Top {referrers} Referrers"
        display_limit = referrers
        
    elif response_sizes:
        results = query_engine.generate_performance_metrics()
        title = f"Top {response_sizes} Paths by Response Size"
        display_limit = response_sizes
        
    elif traffic:
        results = query_engine.traffic_analysis(traffic)
        title = f"Traffic Analysis by {traffic.capitalize()}"
        display_limit = limit
        
    elif bots:
        results = query_engine.analyse_bot_activity(bots)
        title = f"Top {bots} Bot Activity"
        display_limit = bots
        
    elif attacks:
        results = query_engine.detect_security_threats(attacks)
        title = f"Top {attacks} Potential Attacks"
        display_limit = attacks
        
    elif errors:
        results = query_engine.error_analysis()
        title = "Error Analysis"
        display_limit = limit
        
    else:
        # default: show overview
        results = query_engine.overview()
        title = "Database Overview"
        display_limit = len(results)
    
    # display results
    _display_query_results(results, title, export, display_limit, db_path)

def _query_multiple_databases_separate(
    db_files: List[str], top_paths: Optional[int], 
    top_ips: Optional[int], status_codes: bool, methods: bool,
    referrers: Optional[int], response_sizes: Optional[int], 
    traffic: Optional[str], errors: bool, bots: Optional[int], 
    attacks: Optional[int], export: Optional[str], limit: int
) -> None:
    """Query multiple databases separately."""
    console.print(f"[bold blue]📊 Querying {len(db_files)} databases separately[/bold blue]")
    
    for i, db_file in enumerate(db_files, 1):
        console.print(f"\n[bold cyan]Database {i}/{len(db_files)}: {Path(db_file).name}[/bold cyan]")
        
        try:
            _query_single_database(
                db_file, top_paths, top_ips, status_codes, methods, 
                referrers, response_sizes, traffic, errors, bots, attacks, 
                None, limit
            )
        except Exception as e:
            console.print(f"[red]❌ Error querying {db_file}: {e}[/red]")

def _query_multiple_databases_combined(
    db_files: List[str], top_paths: Optional[int], 
    top_ips: Optional[int], status_codes: bool, methods: bool,
    referrers: Optional[int], response_sizes: Optional[int], 
    traffic: Optional[str], errors: bool, bots: Optional[int], 
    attacks: Optional[int], export: Optional[str], limit: int
) -> None:
    """Query multiple databases and combine results."""
    console.print(f"[bold blue]📊 Combining results from {len(db_files)} databases[/bold blue]")
    
    combined_results = []
    title = ""
    
    for db_file in db_files:
        try:
            query_engine = QueryEngine(db_file)
            
            # execute same query on each database
            if top_paths:
                results = query_engine.top_paths(top_paths * len(db_files))
                title = f"Combined Top Paths"
            elif top_ips:
                results = query_engine.top_ips(top_ips * len(db_files))
                title = f"Combined Top IP Addresses"
            elif status_codes:
                results = query_engine.status_distribution()
                title = "Combined Status Distribution"
            elif methods:
                results = query_engine.method_distribution()
                title = "Combined Method Distribution"
            elif referrers:
                results = query_engine.top_referrers(referrers * len(db_files))
                title = f"Combined Top Referrers"
            elif response_sizes:
                results = query_engine.generate_performance_metrics()
                title = "Combined Response Size Analysis"
            elif traffic:
                results = query_engine.traffic_analysis(traffic)
                title = f"Combined Traffic Analysis"
            elif errors:
                results = query_engine.error_analysis()
                title = "Combined Error Analysis"
            elif bots:
                results = query_engine.analyse_bot_activity(bots * len(db_files))
                title = "Combined Bot Activity"
            elif attacks:
                results = query_engine.detect_security_threats(attacks * len(db_files))
                title = "Combined Attack Analysis"
            else:
                results = query_engine.overview()
                title = "Combined Database Overview"
            
            # add database source to each result
            for result in results:
                result['_source_db'] = Path(db_file).name
            
            combined_results.extend(results)
            
        except Exception as e:
            console.print(f"[yellow]⚠️  Skipping {db_file}: {e}[/yellow]")
    
    if not combined_results:
        console.print("[red]❌ No results from any database[/red]")
        return
    
    # sort and limit combined results (basic aggregation)
    if top_paths and 'requests' in (combined_results[0] if combined_results else {}):
        # aggregate by path
        from collections import defaultdict
        path_totals = defaultdict(int)
        for result in combined_results:
            path_totals[result['request_path']] += result.get('requests', 0)
        
        combined_results = [
            {'request_path': path, 'requests': count, '_source_db': 'combined'}
            for path, count in sorted(path_totals.items(), key=lambda x: x[1], reverse=True)
        ]
    
    _display_query_results(combined_results, title, export, limit)


# ========================= display and formatting helpers =========================

def _display_query_results(
    results: List[Dict[str, Any]], title: str, export: Optional[str], 
    limit: int, db_name: Optional[str] = None
) -> None:
    """Display query results in a formatted table."""
    if not results:
        console.print("[yellow]⚠️ No results found[/yellow]")
        return
    
    # export if requested
    if export:
        with open(export, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"[green]💾 Exported to {export}[/green]")
    
    # create table
    table_title = title
    if db_name:
        table_title += f" - {Path(db_name).name}"
    
    table = Table(title=table_title, show_header=True, header_style="bold magenta")
    
    # add columns from first result
    for key in results[0].keys():
        if key.startswith('_'):  # skip internal fields
            continue
        table.add_column(key.replace('_', ' ').title())
    
    # add rows with proper formatting
    for row in results[:limit]:
        formatted_row = []
        for key, value in row.items():
            if key.startswith('_'):  # skip internal fields
                continue
            
            # special formatting for status codes
            if key == 'status' and isinstance(value, int):
                if value < 300:
                    formatted_value = f"[green]{value}[/green]"
                elif value < 400:
                    formatted_value = f"[blue]{value}[/blue]"
                elif value < 500:
                    formatted_value = f"[yellow]{value}[/yellow]"
                else:
                    formatted_value = f"[red]{value}[/red]"
                formatted_row.append(formatted_value)
            elif isinstance(value, (int, float)) and value > 1000:
                formatted_row.append(f"{value:,}")
            else:
                formatted_row.append(str(value))
        table.add_row(*formatted_row)
    
    console.print(table)

def _format_date_range(date_range: Dict[str, Any]) -> str:
    """Format date range for display."""
    if not date_range or not date_range.get('earliest'):
        return "[dim]No data available[/dim]"
    
    return f"Earliest: {date_range['earliest']}\nLatest: {date_range['latest']}"

def _format_status_codes(status_codes: List[Dict[str, Any]]) -> str:
    """Format status codes for display."""
    if not status_codes:
        return "[dim]No data available[/dim]"
    
    lines = []
    for item in status_codes:
        status = item['status']
        count = item['count']
        
        # color code by status type
        if status < 300:
            color = "green"
        elif status < 400:
            color = "blue"
        elif status < 500:
            color = "yellow"
        else:
            color = "red"
        
        lines.append(f"[{color}]{status}[/{color}]: {count:,}")
    
    return "\n".join(lines)


# ========================= path and file validation =========================

def _determine_database_path(logs: str, db: Optional[str], output: Optional[str], verbose: bool = False) -> str:
    """
    Determine the database path using smart defaults.
    
    Priority order:
    1. Explicit --db path (full path with extension)
    2. --output name (adds .sqlite extension)
    3. Auto-generated from first log file name
    """
    
    # if explicit db path provided, use it as-is
    if db:
        if verbose:
            console.print(f"[dim]Using explicit database path: {db}[/dim]")
        return db
    
    # if output name provided, add .sqlite extension
    if output:
        db_path = f"{output}.sqlite"
        if verbose:
            console.print(f"[dim]Using output name: {output} -> {db_path}[/dim]")
        return db_path
    
    # auto-generate from log file pattern
    try:
        # find the first log file to base the name on
        log_path = Path(logs)
        
        if log_path.is_file():
            # single file ~ use its name
            base_name = log_path.stem
            if base_name.endswith('.log'):
                base_name = base_name[:-4]  # remove .log if present
        else:
            # pattern ~ try to extract a meaningful name
            if '*' in logs:
                # extract directory and pattern
                parent = log_path.parent
                pattern = log_path.name
                
                # find actual files
                found_files = list(parent.glob(pattern))
                if found_files:
                    # use first file's name
                    base_name = found_files[0].stem
                    if base_name.endswith('.log'):
                        base_name = base_name[:-4]
                else:
                    # fallback to pattern-based name
                    base_name = pattern.replace('*', '').replace('.log', '') or 'nginx_logs'
            else:
                # fallback
                base_name = 'nginx_logs'
        
        # ensure we have a valid name
        if not base_name or base_name in ['.', '..']:
            base_name = 'nginx_logs'
        
        db_path = f"{base_name}.sqlite"
        
        if verbose:
            console.print(f"[dim]Auto-generated database name: {db_path}[/dim]")
        
        return db_path
        
    except Exception as e:
        if verbose:
            console.print(f"[dim]Failed to auto-generate name ({e}), using default[/dim]")
        return "nginx_logs.sqlite"

def _validate_db_path(db_path: str) -> str:
    """Validate database path for safety."""
    path = Path(db_path).resolve()
    
    # prevent writing to system directories
    system_dirs = ['/etc', '/sys', '/proc', '/dev', '/boot', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
    
    for sys_dir in system_dirs:
        if str(path).startswith(sys_dir):
            console.print(f"[red]❌ Cannot create database in system directory: {sys_dir}[/red]")
            raise typer.Exit(1)
    
    # ensure proper extension
    if path.suffix not in ['.sqlite', '.db', '.sqlite3']:
        path = path.with_suffix('.sqlite')
    
    return str(path)


# ========================= main entry point =========================

def main() -> None:
    """Entry point for the cli application."""
    app()

if __name__ == "__main__":
    main()