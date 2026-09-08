from . import csv_reporter, json_reporter, terminal, ticket

WRITERS = {
    "json": json_reporter.write,
    "csv": csv_reporter.write,
    "tickets": ticket.write,
}

EXTENSIONS = {"json": "json", "csv": "csv", "tickets": "txt"}

__all__ = ["WRITERS", "EXTENSIONS", "csv_reporter", "json_reporter", "terminal", "ticket"]
