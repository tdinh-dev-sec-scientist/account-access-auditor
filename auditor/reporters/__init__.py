from . import csv_reporter, html_reporter, json_reporter, terminal, ticket

WRITERS = {
    "json": json_reporter.write,
    "csv": csv_reporter.write,
    "tickets": ticket.write,
    "html": html_reporter.write,
}

EXTENSIONS = {"json": "json", "csv": "csv", "tickets": "txt", "html": "html"}

__all__ = [
    "EXTENSIONS",
    "WRITERS",
    "csv_reporter",
    "html_reporter",
    "json_reporter",
    "terminal",
    "ticket",
]
