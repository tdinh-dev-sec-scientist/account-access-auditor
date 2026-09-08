"""Logging setup. The scanner logs; it does not print() from library code."""

from __future__ import annotations

import logging
import sys


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # force=True so the level applies even when something else (a host
    # application, or pytest) has already configured the root logger --
    # otherwise basicConfig is a silent no-op and -v does nothing.
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
