#!/usr/bin/env bats
load helpers

setup() {
    load_common
    export RETRY_MAX_ATTEMPTS=3 API_TIMEOUT=5 RETRY_BACKOFF_BASE=0 HTTP_THROTTLE_SECONDS=0
}

@test "returns body+code and calls curl once on 200" {
    install_curl_stub 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
    [ "$(curl_call_count)" -eq 1 ]
}

@test "retries once on 429 then succeeds" {
    install_curl_stub 429 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
    [ "$(curl_call_count)" -eq 2 ]
}

@test "retries 5xx up to RETRY_MAX_ATTEMPTS then returns last response" {
    install_curl_stub 500 500 500 500
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "500" ]
    [ "$(curl_call_count)" -eq 3 ]
}

@test "does not retry a non-429 4xx" {
    install_curl_stub 404 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "404" ]
    [ "$(curl_call_count)" -eq 1 ]
}

@test "honors integer Retry-After on 429" {
    export STUB_RETRY_AFTER=0
    install_curl_stub 429 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
    [ "$(curl_call_count)" -eq 2 ]
}

@test "POST forwards a body" {
    install_curl_stub 200
    local -a h=(-H "Content-Type: application/json")
    run http_request POST "https://example.test/" h '{"q":"x"}'
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
}
