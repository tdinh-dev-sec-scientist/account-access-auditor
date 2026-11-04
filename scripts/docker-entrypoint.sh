#!/bin/sh
# Container entry point.
#
#   demo [args...]    audit the emulated lab account and write reports to /out
#   verify            run the core test and AWS benchmark checks, then copy
#                     their artifacts to /out; scanner integration tests skip
#                     unless optional tools are installed in the image
#   <anything else>   passed through to `python -m auditor.cli`
#
# `set -e` matters here: `verify` is a sequence of checks, and a failure in the
# middle of it must not be hidden by a later success.
set -e

OUT="${AUDITOR_OUTPUT_DIR:-/out}"

# No arguments at all means the demo, which is what CMD says too.
[ "$#" -eq 0 ] && set -- demo

command="$1"
shift

case "$command" in
    demo)
        exec python -m lab.demo --output-dir "$OUT" "$@"
        ;;
    verify)
        # Everything writes to the repository's own results/ directory, because
        # that is the layout scripts/collect_metrics.py reads and the layout the
        # README documents. The artifacts are copied out at the end.
        echo "== test suite =========================================================="
        # .coveragerc enables branch coverage; the floor covers auditor/ and phase3/ at 86%.
        python -m pytest -q --cov=auditor --cov=phase3 --cov-report=term-missing \
                            --cov-report=json:results/coverage.json \
                            --cov-fail-under=86
        echo
        echo "== self-audit of the auditor's own IAM policy =========================="
        python -m auditor.cli validate-policy
        echo
        echo "== the generated policy has not drifted from the code =================="
        python -m auditor.cli generate-policy > /tmp/generated-policy.json
        diff -u policies/auditor-readonly-policy.json /tmp/generated-policy.json
        echo "The committed policy matches the one generated from the code."
        echo
        echo "== lab benchmark (emulated account, no AWS credentials) ================"
        python -m lab.run_benchmark
        echo
        echo "== evidence table ======================================================"
        python scripts/collect_metrics.py
        if [ -d "$OUT" ] && [ -w "$OUT" ]; then
            cp -r results/. "$OUT"/
            echo
            echo "Artifacts copied to $OUT (including aws_audit_report.html)."
        fi
        ;;
    *)
        exec python -m auditor.cli "$command" "$@"
        ;;
esac
