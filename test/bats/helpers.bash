# Shared bats helpers for Look4Gold13 module tests.
REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

# Source common.sh, then neutralize side-effecting helpers for hermetic tests.
load_common() {
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/common.sh"
    log_debug()  { :; }
    log_info()   { :; }
    log_warn()   { :; }
    log_error()  { :; }
    # Header temp files go to the bats-managed tmp dir.
    _mktemp() { mktemp "$BATS_TEST_TMPDIR/hr.XXXXXX"; }
}

# Install a scripted `curl` stub on PATH. Args: space-separated status codes.
# The nth curl invocation returns "body-<code>\n<code>". If STUB_RETRY_AFTER
# is set and the code is 429, writes "Retry-After: <val>" to the -D header file.
install_curl_stub() {
    export STUB_SEQ="$*"
    export STUB_COUNT_FILE="$BATS_TEST_TMPDIR/curl.count"
    : > "$STUB_COUNT_FILE"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    cat > "$BATS_TEST_TMPDIR/bin/curl" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_COUNT_FILE"
hdr=""; prev=""
for a in "$@"; do [[ "$prev" == "-D" ]] && hdr="$a"; prev="$a"; done
read -ra seq <<< "${STUB_SEQ:-200}"
code="${seq[$((n-1))]:-${seq[${#seq[@]}-1]}}"
if [[ -n "${STUB_RETRY_AFTER:-}" && "$code" == "429" && -n "$hdr" ]]; then
    printf 'Retry-After: %s\r\n' "$STUB_RETRY_AFTER" > "$hdr"
fi
printf 'body-%s\n%s' "$code" "$code"
STUB
    chmod +x "$BATS_TEST_TMPDIR/bin/curl"
    PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

curl_call_count() { cat "$STUB_COUNT_FILE" 2>/dev/null || echo 0; }
