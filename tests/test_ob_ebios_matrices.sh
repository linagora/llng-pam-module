#!/bin/bash
#
# Every EBIOS risk matrix in doc/security/ must agree with the risk sheets it
# summarises (#213, #214).
#
# The matrices were maintained by hand next to the sheets and drifted from them
# in at least thirteen places: a risk shown one column to the left, a residual
# impact no sheet states, a consolidated table missing eleven analysed risks and
# carrying two identifiers that had no sheet at all. An evaluator reads the
# matrix, not the sheets, so a matrix that contradicts its own study is worse
# than no matrix.
#
# The check is mechanical: a matrix cell is not a claim of its own, it must be
# derivable from the (Probabilite, Impact) written in the corresponding sheet.
# See tests/ebios_matrix_check.py.
#

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
    exit 0
fi

echo "=== EBIOS matrices vs risk sheets (#213, #214) ==="
if python3 "$ROOT_DIR/tests/ebios_matrix_check.py"; then
    echo ""
    echo "Tests run: 1, passed: 1, failed: 0"
    exit 0
else
    echo ""
    echo "Tests run: 1, passed: 0, failed: 1"
    exit 1
fi
