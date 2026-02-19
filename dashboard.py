from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from time import sleep
from detector import get_session_stats
from logger import read_recent_alerts

console = Console()

def make_layout():
    layout = Layout()

    layout.split(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
    )

    layout["body"].split_row(
        Layout(name="stats"),
        Layout(name="alerts")
    )

    return layout


def render_header():
    return Panel(
        "[bold cyan]NETWORK GUARDIAN — REAL-TIME MONITORING DASHBOARD[/bold cyan]",
        style="bold blue",
        padding=(1, 2)
    )


def render_stats():
    stats = get_session_stats()

    table = Table(title="Session Statistics", expand=True)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="yellow")

    table.add_row("Total Alerts", str(stats["total_alerts"]))
    table.add_row("Internal Alerts", str(stats["internal_alerts"]))
    table.add_row("External Alerts", str(stats["external_alerts"]))
    table.add_row("Unique IPs Seen", str(len(stats["unique_ips"])))

    return table


def render_alerts():
    recent = read_recent_alerts()

    if recent == ["No alerts logged yet."]:
        text = "\n".join(["No alerts logged yet."])
    else:
        text = "\n".join(recent[-12:])

    return Panel(text, title="Recent Alerts", border_style="red", padding=1)


def build_dashboard():
    layout = make_layout()
    layout["header"].update(render_header())
    layout["stats"].update(render_stats())
    layout["alerts"].update(render_alerts())
    return layout


def run_dashboard():
    layout = build_dashboard()

    with Live(layout, refresh_per_second=2, screen=True):
        while True:
            layout["stats"].update(render_stats())
            layout["alerts"].update(render_alerts())
            sleep(1)


if __name__ == "__main__":
    run_dashboard()
