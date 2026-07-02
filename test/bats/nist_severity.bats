#!/usr/bin/env bats
load helpers

setup() {
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/nist.sh"
}

@test "9.8 maps to critical" { [ "$(_nist_severity 9.8)" = "critical" ]; }
@test "9.0 maps to critical" { [ "$(_nist_severity 9.0)" = "critical" ]; }
@test "7.5 maps to high"     { [ "$(_nist_severity 7.5)" = "high" ]; }
@test "4.0 maps to medium"   { [ "$(_nist_severity 4.0)" = "medium" ]; }
@test "3.9 maps to low"      { [ "$(_nist_severity 3.9)" = "low" ]; }
@test "0 maps to low"        { [ "$(_nist_severity 0)" = "low" ]; }
