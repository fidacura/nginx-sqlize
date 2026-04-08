"""
nginx-sqlize streamlined cli interface.
"""

from collections import defaultdict
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
    from core import create_processor, translate_error_message, validate_positive_int
    from queries import QueryEngine
    import __init__
    __version__ = __init__.__version__


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

    try:
        validate_positive_int(batch_size, "batch_size", 100000)
    except ValueError as e:
        raise typer.BadParameter(str(e), param_hint="'--batch-size'")

    db_path = _determine_database_path(logs, db, output, verbose)
    db_path = _validate_db_path(db_path)

    processor = create_processor(
        db_path=db_path,
        batch_size=batch_size
    )

    processor.setup_logging(verbose)

    log_files = processor.find_log_files(logs)

    if not log_files:
        console.print(f"[red]❌ No log files found matching: {logs}[/red]")
        raise typer.Exit(1)

    if verbose:
        console.print(f"[green]🔍 Found {len(log_files)} log files[/green]")
        console.print(f"[dim]📄 Database: {db_path}[/dim]")

        if force:
            console.print("[bright_yellow]⚠️  Force mode enabled ~ may create duplicate entries[/bright_yellow]")
    else:
        if force:
            console.print("[bright_yellow]⚠️  Force mode: may create duplicates[/bright_yellow]")

    total_processed = 0
    total_inserted = 0
    failed = False

    if verbose:
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
                    failed = True
                    error_msg = translate_error_message(e, str(log_file))
                    console.print(f"[red]❌ {log_file.name}: {error_msg}[/red]")

    else:
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
                failed = True
                error_msg = translate_error_message(e, str(log_file))
                console.print(f"[red]❌ {log_file.name}: {error_msg}[/red]")

    stats = processor.get_stats()

    if verbose:
        console.print("[dim]Refreshing database statistics...[/dim]")

    if total_processed == 0 and not failed:
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
        summary_style = "green" if not failed else "red"
        summary_icon = "✨" if not failed else "⚠️"
        summary_title = "Processing Complete" if not failed else "Processing Complete (with errors)"
        summary_message = f"""[{'green' if not failed else 'red'}]{summary_icon} Ingestion complete![/{'green' if not failed else 'red'}]

        📊 Processed: {total_processed:,} lines
        💾 Inserted: {total_inserted:,} entries
        🔍 Total in db: {stats['total_logs']:,} entries
        💽 Database: [bold]{db_path}[/bold] ({stats['database_size_mb']:.1f} mb)"""

    console.print(Panel.fit(
        summary_message,
        title=summary_title,
        border_style=summary_style
    ))

    if failed:
        raise typer.Exit(1)


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

    try:
        validate_positive_int(limit, "limit", 10000)
    except ValueError as e:
        raise typer.BadParameter(str(e), param_hint="'--limit'")

    for val, name, hint in [
        (top_ips, "top_ips", "'--top-ips'"),
        (top_paths, "top_paths", "'--top-paths'"),
        (referrers, "referrers", "'--referrers'"),
        (response_sizes, "response_sizes", "'--response-sizes'"),
        (bots, "bots", "'--bots'"),
        (attacks, "attacks", "'--attacks'"),
    ]:
        if val is not None:
            try:
                validate_positive_int(val, name, 1000)
            except ValueError as e:
                raise typer.BadParameter(str(e), param_hint=hint)

    db_files = _resolve_database_files(db)

    if len(db_files) == 1:
        _query_single_database(
            db_files[0], top_paths, top_ips, status_codes, methods,
            referrers, response_sizes, traffic, errors, bots, attacks,
            export, limit
        )
    else:
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

    db_path = _auto_detect_database(db)

    if not Path(db_path).exists():
        console.print(f"[red]❌ Database not found: {db_path}[/red]")
        _suggest_available_databases()
        raise typer.Exit(1)

    processor = create_processor(db_path=db_path)
    stats = processor.get_stats()

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

    with console.status("[bold green]Cleaning database...") as status_display:
        if duplicates:
            status_display.update("[bold green]Checking for duplicates...")
            duplicate_count = query_engine.detect_duplicates()
            if duplicate_count > 0:
                console.print(f"[yellow]📋 Found {duplicate_count:,} duplicate entries[/yellow]")
                deleted = query_engine.remove_duplicates()
                console.print(f"[green]🗑️  Removed {deleted:,} duplicate entries[/green]")
            else:
                console.print("[green]✅ No duplicates found[/green]")

        if older_than:
            status_display.update(f"[bold green]Removing logs older than {older_than}...")
            deleted = query_engine.delete_old_logs(older_than)
            console.print(f"[green]🗑️  Deleted {deleted:,} old log entries[/green]")

        if vacuum:
            status_display.update("[bold green]Optimizing database...")
            query_engine.vacuum()
            console.print("[green]✨ Database optimized[/green]")

    processor = create_processor(db_path=db_path)
    stats = processor.get_stats()

    console.print(f"[green]✅ Cleanup complete! Database now {stats['database_size_mb']:.1f} mb[/green]")


# ========================= database file resolution helpers =========================

def _resolve_database_files(db_arg: Optional[str]) -> List[str]:
    """Resolve database file specification to list of actual files."""
    if not db_arg:
        return [_auto_detect_database(None)]

    db_files = []

    if ',' in db_arg:
        for db_path in db_arg.split(','):
            db_path = db_path.strip()
            if not Path(db_path).exists():
                console.print(f"[red]❌ Database not found: {db_path}[/red]")
                raise typer.Exit(1)
            db_files.append(db_path)

    elif '*' in db_arg or '?' in db_arg:
        matched_files = list(Path.cwd().glob(db_arg))
        db_files = [str(f) for f in matched_files if f.suffix in ['.sqlite', '.db']]

        if not db_files:
            console.print(f"[red]❌ No database files match pattern: {db_arg}[/red]")
            raise typer.Exit(1)

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

    current_dir = Path.cwd()

    db_files = [
        *current_dir.glob("*.sqlite"),
        *current_dir.glob("*.db"),
    ]

    if len(db_files) == 1:
        console.print(f"[dim]Auto-detected: {db_files[0].name}[/dim]")
        return str(db_files[0])
    elif len(db_files) == 0:
        console.print("[red]❌ No database files found[/red]")
        console.print("[dim]Tip: run 'nginx-sqlize ingest <logfile>' first to create a database[/dim]")
        raise typer.Exit(1)
    else:
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
        results = query_engine.overview()
        title = "Database Overview"
        display_limit = len(results)

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
    """Query multiple databases and combine results with proper per-type aggregation."""
    console.print(f"[bold blue]📊 Combining results from {len(db_files)} databases[/bold blue]")

    combined_results: List[Dict[str, Any]] = []
    title = ""
    query_type = "overview"
    display_limit = limit

    for db_file in db_files:
        try:
            query_engine = QueryEngine(db_file)

            if top_paths:
                results = query_engine.top_paths(top_paths * len(db_files))
                title = "Combined Top Paths"
                query_type = "top_paths"
                display_limit = top_paths
            elif top_ips:
                results = query_engine.top_ips(top_ips * len(db_files))
                title = "Combined Top IP Addresses"
                query_type = "top_ips"
                display_limit = top_ips
            elif status_codes:
                results = query_engine.status_distribution()
                title = "Combined Status Distribution"
                query_type = "status_codes"
                display_limit = limit
            elif methods:
                results = query_engine.method_distribution()
                title = "Combined Method Distribution"
                query_type = "methods"
                display_limit = limit
            elif referrers:
                results = query_engine.top_referrers(referrers * len(db_files))
                title = "Combined Top Referrers"
                query_type = "referrers"
                display_limit = referrers
            elif response_sizes:
                results = query_engine.generate_performance_metrics()
                title = "Combined Response Size Analysis"
                query_type = "response_sizes"
                display_limit = response_sizes or limit
            elif traffic:
                results = query_engine.traffic_analysis(traffic)
                title = "Combined Traffic Analysis"
                query_type = "traffic"
                display_limit = limit
            elif errors:
                results = query_engine.error_analysis()
                title = "Combined Error Analysis"
                query_type = "errors"
                display_limit = limit
            elif bots:
                results = query_engine.analyse_bot_activity(bots * len(db_files))
                title = "Combined Bot Activity"
                query_type = "bots"
                display_limit = bots
            elif attacks:
                results = query_engine.detect_security_threats(attacks * len(db_files))
                title = "Combined Attack Analysis"
                query_type = "attacks"
                display_limit = attacks
            else:
                results = query_engine.overview()
                title = "Combined Database Overview"
                query_type = "overview"
                display_limit = limit

            combined_results.extend(results)

        except Exception as e:
            console.print(f"[yellow]⚠️  Skipping {db_file}: {e}[/yellow]")

    if not combined_results:
        console.print("[red]❌ No results from any database[/red]")
        return

    aggregated = _aggregate_combined_results(combined_results, query_type, display_limit)
    _display_query_results(aggregated, title, export, display_limit)


# ========================= multi-db result aggregation =========================

def _aggregate_combined_results(
    results: List[Dict[str, Any]],
    query_type: str,
    limit: int,
) -> List[Dict[str, Any]]:
    """
    Aggregate raw results collected from multiple databases.

    Each query type has a known group key and a set of summable numeric
    fields. Computed display fields (percentages, formatted strings) are
    dropped because they cannot be meaningfully summed across databases.
    """
    if not results:
        return []

    if query_type == "top_paths":
        totals: Dict[str, int] = defaultdict(int)
        for r in results:
            totals[r["request_path"]] += r.get("requests", 0)
        return [
            {"request_path": path, "requests": count}
            for path, count in sorted(totals.items(), key=lambda x: x[1], reverse=True)
        ][:limit]

    if query_type == "top_ips":
        data: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"requests": 0, "total_bytes": 0, "first_seen": None, "last_seen": None, "ip_type": ""}
        )
        for r in results:
            ip = r["remote_addr"]
            data[ip]["requests"] += r.get("requests", 0)
            data[ip]["total_bytes"] += r.get("total_bytes", 0)
            data[ip]["ip_type"] = r.get("ip_type", "")
            fs = r.get("first_seen")
            ls = r.get("last_seen")
            if fs and (data[ip]["first_seen"] is None or fs < data[ip]["first_seen"]):
                data[ip]["first_seen"] = fs
            if ls and (data[ip]["last_seen"] is None or ls > data[ip]["last_seen"]):
                data[ip]["last_seen"] = ls
        return [
            {"remote_addr": ip, **fields}
            for ip, fields in sorted(data.items(), key=lambda x: x[1]["requests"], reverse=True)
        ][:limit]

    if query_type == "status_codes":
        totals_sc: Dict[Any, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "category": ""})
        for r in results:
            s = r["status"]
            totals_sc[s]["count"] += r.get("count", 0)
            totals_sc[s]["category"] = r.get("category", "")
        return [
            {"status": s, "count": fields["count"], "category": fields["category"]}
            for s, fields in sorted(totals_sc.items(), key=lambda x: x[1]["count"], reverse=True)
        ][:limit]

    if query_type == "methods":
        totals_m: Dict[str, int] = defaultdict(int)
        for r in results:
            totals_m[r["request_method"]] += r.get("count", 0)
        return [
            {"request_method": m, "count": count}
            for m, count in sorted(totals_m.items(), key=lambda x: x[1], reverse=True)
        ][:limit]

    if query_type == "referrers":
        totals_ref: Dict[str, int] = defaultdict(int)
        for r in results:
            totals_ref[r["referer"]] += r.get("requests", 0)
        return [
            {"referer": ref, "requests": count}
            for ref, count in sorted(totals_ref.items(), key=lambda x: x[1], reverse=True)
        ][:limit]

    if query_type == "traffic":
        data_t: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"requests": 0, "unique_visitors": 0}
        )
        for r in results:
            tp = r["time_period"]
            data_t[tp]["requests"] += r.get("requests", 0)
            data_t[tp]["unique_visitors"] += r.get("unique_visitors", 0)
        return [
            {"time_period": tp, "requests": fields["requests"], "unique_visitors": fields["unique_visitors"]}
            for tp, fields in sorted(data_t.items(), reverse=True)
        ][:limit]

    if query_type == "bots":
        data_b: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"requests": 0, "bot_type": ""}
        )
        for r in results:
            ua = r["user_agent"]
            data_b[ua]["requests"] += r.get("requests", 0)
            data_b[ua]["bot_type"] = r.get("bot_type", "")
        return [
            {"user_agent": ua, "requests": fields["requests"], "bot_type": fields["bot_type"]}
            for ua, fields in sorted(data_b.items(), key=lambda x: x[1]["requests"], reverse=True)
        ][:limit]

    if query_type == "attacks":
        data_a: Dict[tuple, Dict[str, Any]] = defaultdict(
            lambda: {"attempts": 0, "attack_type": "", "user_agent": ""}
        )
        for r in results:
            key = (r["request_path"], r["remote_addr"])
            data_a[key]["attempts"] += r.get("attempts", 0)
            data_a[key]["attack_type"] = r.get("attack_type", "")
            data_a[key]["user_agent"] = r.get("user_agent", "")
        return [
            {"request_path": k[0], "remote_addr": k[1], **fields}
            for k, fields in sorted(data_a.items(), key=lambda x: x[1]["attempts"], reverse=True)
        ][:limit]

    if query_type == "errors":
        data_e: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"total_requests": 0, "client_errors": 0, "server_errors": 0}
        )
        for r in results:
            tp = r["time_period"]
            data_e[tp]["total_requests"] += r.get("total_requests", 0)
            data_e[tp]["client_errors"] += r.get("client_errors", 0)
            data_e[tp]["server_errors"] += r.get("server_errors", 0)
        aggregated_errors = []
        for tp, fields in sorted(data_e.items(), reverse=True):
            total = fields["total_requests"]
            errs = fields["client_errors"] + fields["server_errors"]
            rate = f"{errs * 100.0 / total:.2f}%" if total > 0 else "0.00%"
            aggregated_errors.append({
                "time_period": tp,
                "total_requests": total,
                "client_errors": fields["client_errors"],
                "server_errors": fields["server_errors"],
                "error_rate": rate,
            })
        return aggregated_errors[:limit]

    # overview and response_sizes: return as-is (cannot be meaningfully aggregated)
    return results[:limit]


# ========================= display and formatting helpers =========================

def _display_query_results(
    results: List[Dict[str, Any]], title: str, export: Optional[str],
    limit: int, db_name: Optional[str] = None
) -> None:
    """Display query results in a formatted table."""
    if not results:
        console.print("[yellow]⚠️ No results found[/yellow]")
        return

    if export:
        with open(export, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"[green]💾 Exported to {export}[/green]")

    table_title = title
    if db_name:
        table_title += f" - {Path(db_name).name}"

    table = Table(title=table_title, show_header=True, header_style="bold magenta")

    for key in results[0].keys():
        if key.startswith('_'):
            continue
        table.add_column(key.replace('_', ' ').title())

    for row in results[:limit]:
        formatted_row = []
        for key, value in row.items():
            if key.startswith('_'):
                continue

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

    if db:
        if verbose:
            console.print(f"[dim]Using explicit database path: {db}[/dim]")
        return db

    if output:
        db_path = f"{output}.sqlite"
        if verbose:
            console.print(f"[dim]Using output name: {output} -> {db_path}[/dim]")
        return db_path

    try:
        log_path = Path(logs)

        if log_path.is_file():
            base_name = log_path.stem
            if base_name.endswith('.log'):
                base_name = base_name[:-4]
        else:
            if '*' in logs:
                parent = log_path.parent
                pattern = log_path.name

                found_files = list(parent.glob(pattern))
                if found_files:
                    base_name = found_files[0].stem
                    if base_name.endswith('.log'):
                        base_name = base_name[:-4]
                else:
                    base_name = pattern.replace('*', '').replace('.log', '') or 'nginx_logs'
            else:
                base_name = 'nginx_logs'

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

    system_dirs = ['/etc', '/sys', '/proc', '/dev', '/boot', '/bin', '/sbin', '/usr/bin', '/usr/sbin']

    for sys_dir in system_dirs:
        if str(path).startswith(sys_dir):
            console.print(f"[red]❌ Cannot create database in system directory: {sys_dir}[/red]")
            raise typer.Exit(1)

    if path.suffix not in ['.sqlite', '.db', '.sqlite3']:
        path = path.with_suffix('.sqlite')

    return str(path)


# ========================= main entry point =========================

def main() -> None:
    """Entry point for the cli application."""
    app()

if __name__ == "__main__":
    main()
