# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Python 3.11 or 3.12 is required. No AWS account is needed for development.

## Checks to run before opening a pull request

```bash
python -m pytest -q
node --test tests/*.test.cjs
ruff check auditor phase3 lab tests scripts examples conftest.py
ruff format --check auditor phase3 lab tests scripts examples conftest.py
python -m auditor.cli validate-policy
```

If you change the generated evidence (rules, lab fixtures, or reports), refresh
it and commit the result:

```bash
python -m lab.run_benchmark
python scripts/collect_metrics.py
```

## Ground rules

- **Keep AWS access read-only.** Never add a create, update, put, or delete
  call. If a new collector needs an extra read permission, regenerate the
  policy with `python -m auditor.cli generate-policy --write`.
- **Never commit credentials, real account IDs, or real scan output.** Use the
  AWS documentation placeholder `123456789012` in fixtures.
- **Add tests with every rule or behavior change**, including clean, edge, and
  malformed cases under `tests/cases/`.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
  messages (`feat:`, `fix:`, `docs:`, `refactor:`, `ci:`, `chore:`).
