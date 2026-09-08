"""Deliberately misconfigured AWS test environment.

Everything in this package makes *write* calls. It is deliberately outside the
``auditor`` package so that the auditor's read-only property stays provable:
the static read-only test scans ``auditor/`` for write calls, and nothing in
``lab/`` is imported by the auditor at any point.
"""
