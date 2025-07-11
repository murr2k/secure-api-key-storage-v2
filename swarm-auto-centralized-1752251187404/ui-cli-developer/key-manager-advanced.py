#!/usr/bin/env python3
"""
Advanced Key Manager CLI

Extended version with auto-completion, interactive mode, and additional features.
"""

import os
import sys
import json
import click
from click_completion import init as init_completion
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.shortcuts import yes_no_dialog
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.tree import Tree
from rich import print as rprint
import time
from pathlib import Path
from datetime import datetime, timedelta
from key_manager_lib import KeyManager, KeyManagerError, AuthenticationError

# Initialize completion
init_completion()

console = Console()
history = FileHistory(str(Path.home() / '.secure-keys' / 'cli_history'))


class InteractiveKeyManager:
    """Interactive mode for the key manager."""
    
    def __init__(self):
        self.km = None
        self.authenticated = False
        self.commands = {
            'help': self.show_help,
            'add': self.add_key,
            'get': self.get_key,
            'remove': self.remove_key,
            'list': self.list_keys,
            'rotate': self.rotate_key,
            'backup': self.backup,
            'restore': self.restore,
            'search': self.search,
            'export': self.export_keys,
            'import': self.import_keys,
            'stats': self.show_stats,
            'tree': self.show_tree,
            'quit': self.quit,
            'exit': self.quit,
        }
        
    def authenticate(self):
        """Authenticate with master password."""
        if self.authenticated:
            return True
            
        password = prompt("Master password: ", is_password=True)
        
        try:
            self.km = KeyManager(master_password=password)
            if self.km.is_initialized():
                # Test authentication
                self.km.list_services()
                self.authenticated = True
                console.print("[green]✓ Authenticated successfully![/green]")
                return True
        except AuthenticationError:
            console.print("[red]✗ Invalid master password[/red]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
        
        return False
    
    def run(self):
        """Run the interactive mode."""
        console.print(Panel(
            "[bold cyan]Secure Key Manager - Interactive Mode[/bold cyan]\n"
            "Type 'help' for available commands, 'quit' to exit.",
            title="Welcome"
        ))
        
        # Authenticate first
        if not self.authenticate():
            return
        
        # Get list of services for auto-completion
        services = [s['name'] for s in self.km.list_services()]
        completer = WordCompleter(
            list(self.commands.keys()) + services,
            ignore_case=True
        )
        
        while True:
            try:
                # Get command
                user_input = prompt(
                    "key-manager> ",
                    completer=completer,
                    history=history
                ).strip()
                
                if not user_input:
                    continue
                
                # Parse command
                parts = user_input.split()
                command = parts[0].lower()
                args = parts[1:]
                
                # Execute command
                if command in self.commands:
                    self.commands[command](args)
                else:
                    console.print(f"[yellow]Unknown command: {command}[/yellow]")
                    console.print("Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'quit' to exit.[/yellow]")
            except EOFError:
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
    
    def show_help(self, args):
        """Show help information."""
        help_text = """
[bold]Available Commands:[/bold]

  [cyan]add[/cyan] <service> <key_name>     Add a new API key
  [cyan]get[/cyan] <service> <key_name>     Get an API key
  [cyan]remove[/cyan] <service> <key_name>  Remove an API key
  [cyan]list[/cyan] [service]               List services and keys
  [cyan]rotate[/cyan] <service> <key_name>  Rotate an API key
  [cyan]search[/cyan] <pattern>             Search for keys
  [cyan]backup[/cyan] [name]                Create a backup
  [cyan]restore[/cyan] <name>               Restore from backup
  [cyan]export[/cyan] <file>                Export keys to file
  [cyan]import[/cyan] <file>                Import keys from file
  [cyan]stats[/cyan]                        Show statistics
  [cyan]tree[/cyan]                         Show key hierarchy
  [cyan]help[/cyan]                         Show this help
  [cyan]quit[/cyan]                         Exit interactive mode
"""
        console.print(help_text)
    
    def add_key(self, args):
        """Add a new key interactively."""
        if len(args) < 2:
            service = prompt("Service name: ")
            key_name = prompt("Key name: ")
        else:
            service = args[0]
            key_name = args[1]
        
        key_value = prompt(f"API key value for {service}/{key_name}: ", is_password=True)
        
        # Optional metadata
        if yes_no_dialog(
            title="Add Metadata?",
            text="Would you like to add metadata to this key?"
        ).run():
            metadata = {}
            metadata['environment'] = prompt("Environment (e.g., prod, dev): ")
            metadata['expires'] = prompt("Expiry date (YYYY-MM-DD, optional): ")
            metadata['notes'] = prompt("Notes (optional): ")
            
            # Clean up empty values
            metadata = {k: v for k, v in metadata.items() if v}
        else:
            metadata = None
        
        try:
            self.km.add_key(service, key_name, key_value, metadata)
            console.print(f"[green]✓ Added key '{key_name}' for service '{service}'[/green]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def get_key(self, args):
        """Get a key interactively."""
        if len(args) < 2:
            service = prompt("Service name: ")
            key_name = prompt("Key name: ")
        else:
            service = args[0]
            key_name = args[1]
        
        try:
            key_value = self.km.get_key(service, key_name)
            if key_value:
                # Show options
                action = prompt(
                    "Action: (s)how, (c)opy, (b)oth? ",
                    completer=WordCompleter(['show', 'copy', 'both', 's', 'c', 'b'])
                ).lower()
                
                if action in ['s', 'show', 'b', 'both']:
                    console.print(f"[cyan]{key_value}[/cyan]")
                
                if action in ['c', 'copy', 'b', 'both']:
                    try:
                        import pyperclip
                        pyperclip.copy(key_value)
                        console.print("[green]✓ Copied to clipboard[/green]")
                    except ImportError:
                        console.print("[yellow]pyperclip not installed[/yellow]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def remove_key(self, args):
        """Remove a key interactively."""
        if len(args) < 2:
            service = prompt("Service name: ")
            key_name = prompt("Key name: ")
        else:
            service = args[0]
            key_name = args[1]
        
        if yes_no_dialog(
            title="Confirm Deletion",
            text=f"Remove key '{key_name}' from service '{service}'?"
        ).run():
            try:
                self.km.remove_key(service, key_name, confirm=False)
                console.print(f"[green]✓ Removed key '{key_name}' from service '{service}'[/green]")
            except Exception as e:
                console.print(f"[red]✗ Error: {e}[/red]")
    
    def list_keys(self, args):
        """List services and keys."""
        try:
            services = self.km.list_services()
            
            if not services:
                console.print("[yellow]No services configured[/yellow]")
                return
            
            # Filter by service if provided
            if args:
                services = [s for s in services if s['name'] == args[0]]
            
            table = Table(title="Configured Services and Keys")
            table.add_column("Service", style="cyan")
            table.add_column("Keys", style="green")
            table.add_column("Count", style="yellow")
            table.add_column("Created", style="magenta")
            
            for service in services:
                table.add_row(
                    service['name'],
                    ", ".join(service['keys']),
                    str(len(service['keys'])),
                    service['created'][:10]
                )
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def rotate_key(self, args):
        """Rotate a key interactively."""
        if len(args) < 2:
            service = prompt("Service name: ")
            key_name = prompt("Key name: ")
        else:
            service = args[0]
            key_name = args[1]
        
        # Ask for new value or generate
        if yes_no_dialog(
            title="Key Rotation",
            text="Generate a new random key?"
        ).run():
            new_value = None
        else:
            new_value = prompt("New key value: ", is_password=True)
        
        try:
            result = self.km.rotate_key(service, key_name, new_value)
            console.print(f"[green]✓ Rotated key '{key_name}' for service '{service}'[/green]")
            
            if result and not new_value:
                if yes_no_dialog(
                    title="Show New Key?",
                    text="Display the generated key?"
                ).run():
                    console.print(f"New key: [cyan]{result}[/cyan]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def search(self, args):
        """Search for keys."""
        if not args:
            pattern = prompt("Search pattern: ")
        else:
            pattern = " ".join(args)
        
        try:
            matches = self.km.search_keys(pattern)
            
            if not matches:
                console.print(f"[yellow]No keys found matching '{pattern}'[/yellow]")
                return
            
            table = Table(title=f"Search Results for '{pattern}'")
            table.add_column("Service", style="cyan")
            table.add_column("Key", style="green")
            table.add_column("Created", style="yellow")
            
            for match in matches:
                table.add_row(
                    match['service'],
                    match['key_name'],
                    match['created'][:10]
                )
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def backup(self, args):
        """Create a backup."""
        if args:
            name = args[0]
        else:
            name = prompt("Backup name (optional): ") or None
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                progress.add_task(description="Creating backup...", total=None)
                backup_path = self.km.backup(name)
            
            console.print(f"[green]✓ Backup created: {backup_path}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def restore(self, args):
        """Restore from backup."""
        try:
            # List backups first
            backups = self.km.list_backups()
            
            if not backups:
                console.print("[yellow]No backups available[/yellow]")
                return
            
            # Show backup list
            table = Table(title="Available Backups")
            table.add_column("#", style="dim")
            table.add_column("Name", style="cyan")
            table.add_column("Created", style="yellow")
            table.add_column("Size", style="green")
            
            for i, backup in enumerate(backups):
                table.add_row(
                    str(i + 1),
                    backup['name'],
                    backup['created'][:19],
                    backup['size']
                )
            
            console.print(table)
            
            # Get selection
            if args:
                backup_name = args[0]
            else:
                selection = prompt("Select backup (name or number): ")
                
                # Check if number
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(backups):
                        backup_name = backups[idx]['name']
                    else:
                        console.print("[red]Invalid selection[/red]")
                        return
                except ValueError:
                    backup_name = selection
            
            # Confirm restore
            if yes_no_dialog(
                title="Confirm Restore",
                text=f"Restore from backup '{backup_name}'?\nCurrent keys will be backed up first."
            ).run():
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    transient=True,
                ) as progress:
                    progress.add_task(description="Restoring backup...", total=None)
                    self.km.restore(backup_name)
                
                console.print(f"[green]✓ Restored from backup '{backup_name}'[/green]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def export_keys(self, args):
        """Export keys to a file."""
        if not args:
            filename = prompt("Export filename: ")
        else:
            filename = args[0]
        
        try:
            services = self.km.list_services()
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'services': {}
            }
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    description="Exporting keys...", 
                    total=len(services)
                )
                
                for service in services:
                    export_data['services'][service['name']] = {}
                    for key_name in service['keys']:
                        try:
                            key_value = self.km.get_key(service['name'], key_name)
                            export_data['services'][service['name']][key_name] = {
                                'value': key_value,
                                'exported': True
                            }
                        except:
                            export_data['services'][service['name']][key_name] = {
                                'value': None,
                                'exported': False
                            }
                    progress.update(task, advance=1)
            
            # Save to file
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            console.print(f"[green]✓ Exported keys to {filename}[/green]")
            console.print("[yellow]Warning: This file contains sensitive data![/yellow]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def import_keys(self, args):
        """Import keys from a file."""
        if not args:
            filename = prompt("Import filename: ")
        else:
            filename = args[0]
        
        if not Path(filename).exists():
            console.print(f"[red]File not found: {filename}[/red]")
            return
        
        try:
            with open(filename, 'r') as f:
                import_data = json.load(f)
            
            if 'services' not in import_data:
                console.print("[red]Invalid import file format[/red]")
                return
            
            # Count keys
            total_keys = sum(
                len(keys) for keys in import_data['services'].values()
            )
            
            if not yes_no_dialog(
                title="Confirm Import",
                text=f"Import {total_keys} keys from {len(import_data['services'])} services?"
            ).run():
                return
            
            # Import keys
            imported = 0
            failed = 0
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    description="Importing keys...", 
                    total=total_keys
                )
                
                for service, keys in import_data['services'].items():
                    for key_name, key_data in keys.items():
                        if key_data.get('value'):
                            try:
                                self.km.add_key(
                                    service, 
                                    key_name, 
                                    key_data['value']
                                )
                                imported += 1
                            except:
                                failed += 1
                        progress.update(task, advance=1)
            
            console.print(f"[green]✓ Imported {imported} keys[/green]")
            if failed:
                console.print(f"[yellow]Failed to import {failed} keys[/yellow]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def show_stats(self, args):
        """Show statistics about stored keys."""
        try:
            services = self.km.list_services()
            
            # Calculate stats
            total_services = len(services)
            total_keys = sum(len(s['keys']) for s in services)
            
            # Find oldest and newest
            if services:
                dates = [datetime.fromisoformat(s['created']) for s in services]
                oldest = min(dates)
                newest = max(dates)
            else:
                oldest = newest = None
            
            # Create stats panel
            stats_text = f"""
[bold]Key Manager Statistics[/bold]

Services: [cyan]{total_services}[/cyan]
Total Keys: [green]{total_keys}[/green]
Average Keys per Service: [yellow]{total_keys/total_services if total_services else 0:.1f}[/yellow]

Oldest Service: [magenta]{oldest.strftime('%Y-%m-%d') if oldest else 'N/A'}[/magenta]
Newest Service: [magenta]{newest.strftime('%Y-%m-%d') if newest else 'N/A'}[/magenta]
"""
            
            console.print(Panel(stats_text, title="Statistics"))
            
            # Show service distribution
            if services:
                table = Table(title="Key Distribution")
                table.add_column("Service", style="cyan")
                table.add_column("Keys", style="green")
                table.add_column("Percentage", style="yellow")
                
                for service in sorted(services, key=lambda s: len(s['keys']), reverse=True):
                    percentage = (len(service['keys']) / total_keys) * 100
                    table.add_row(
                        service['name'],
                        str(len(service['keys'])),
                        f"{percentage:.1f}%"
                    )
                
                console.print(table)
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def show_tree(self, args):
        """Show key hierarchy as a tree."""
        try:
            services = self.km.list_services()
            
            tree = Tree("[bold]Key Manager[/bold]")
            
            for service in sorted(services, key=lambda s: s['name']):
                service_branch = tree.add(f"[cyan]{service['name']}[/cyan]")
                
                for key in sorted(service['keys']):
                    service_branch.add(f"[green]{key}[/green]")
            
            console.print(tree)
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
    
    def quit(self, args):
        """Exit interactive mode."""
        if yes_no_dialog(
            title="Exit",
            text="Exit interactive mode?"
        ).run():
            console.print("[yellow]Goodbye![/yellow]")
            sys.exit(0)


# CLI with advanced features
@click.group()
@click.pass_context
def cli(ctx):
    """Advanced Secure Key Manager CLI."""
    ctx.ensure_object(dict)


@cli.command()
def interactive():
    """Start interactive mode."""
    ikm = InteractiveKeyManager()
    ikm.run()


@cli.command()
@click.argument('duration', type=int, default=300)
def monitor(duration):
    """Monitor key usage and changes."""
    console.print(f"[cyan]Monitoring keys for {duration} seconds...[/cyan]")
    
    km = KeyManager()
    password = prompt("Master password: ", is_password=True)
    km.master_password = password
    
    try:
        initial_state = km.list_services()
        
        with Progress() as progress:
            task = progress.add_task("[green]Monitoring...", total=duration)
            
            for i in range(duration):
                time.sleep(1)
                progress.update(task, advance=1)
                
                # Check for changes
                current_state = km.list_services()
                if current_state != initial_state:
                    console.print("\n[yellow]Change detected![/yellow]")
                    # Show what changed
                    initial_state = current_state
        
        console.print("[green]Monitoring complete.[/green]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")


@cli.command()
@click.option('--older-than', type=int, help='Days since last rotation')
def audit(older_than):
    """Audit keys for security compliance."""
    km = KeyManager()
    password = prompt("Master password: ", is_password=True)
    km.master_password = password
    
    try:
        services = km.list_services()
        
        # This is a mock audit - in reality, you'd check rotation dates
        console.print(Panel("[bold]Security Audit Report[/bold]"))
        
        issues = []
        
        for service in services:
            # Mock checks
            if len(service['keys']) > 5:
                issues.append(f"[yellow]Service '{service['name']}' has {len(service['keys'])} keys (consider cleanup)[/yellow]")
            
            for key in service['keys']:
                # In a real implementation, check rotation dates
                if 'prod' in key.lower() or 'production' in key.lower():
                    issues.append(f"[orange3]Production key '{service['name']}/{key}' should be rotated regularly[/orange3]")
        
        if issues:
            console.print("\n[bold]Issues Found:[/bold]")
            for issue in issues:
                console.print(f"  • {issue}")
        else:
            console.print("[green]✓ No issues found![/green]")
        
        # Recommendations
        console.print("\n[bold]Recommendations:[/bold]")
        console.print("  • Rotate production keys every 90 days")
        console.print("  • Use different keys for different environments")
        console.print("  • Regularly backup your keys")
        console.print("  • Remove unused keys")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


if __name__ == '__main__':
    # Check if running without arguments
    if len(sys.argv) == 1:
        # Start interactive mode by default
        ikm = InteractiveKeyManager()
        ikm.run()
    else:
        cli()