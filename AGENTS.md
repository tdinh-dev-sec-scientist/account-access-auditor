# Engineering Instructions

## Project
AWS Account & Access Configuration Auditor.

## Core Principles
- Inspect existing code before modifying it.
- Preserve existing architecture unless justified.
- Prioritize security, correctness and maintainability.
- Prefer modular, testable implementations.
- Do not invent implemented capabilities.

## Security Requirements
- Preserve read-only AWS behavior.
- Never introduce AWS write operations.
- Never expose credentials, tokens or secrets.
- Follow least-privilege principles.
- Treat external input and AWS responses as untrusted.
- Validate IAM policies carefully.

## Development Requirements
- Follow existing coding conventions.
- Add tests for every new feature.
- Cover edge cases and failure scenarios.
- Avoid unnecessary dependencies.
- Do not remove existing functionality without approval.

## Testing
- Run relevant pytest tests after changes.
- Run the full test suite before completing a milestone.
- Report actual test results.
- Never claim tests passed without executing them.

## Git Rules
- Never commit or push without explicit approval.
- Never modify main directly.
- Review git diff before finishing.
- Never overwrite unrelated user changes.

## Completion Report
1. Summary of changes.
2. Files modified.
3. Technical decisions.
4. Tests executed and results.
5. Known limitations.
6. Suggested next steps.
