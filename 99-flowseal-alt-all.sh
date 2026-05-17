#!/bin/sh

FLOWSEAL_ALT_DIR=${./converted_alt/}

conf_to_params()
{
    sed -e 's/#.*$//' -e '/^[[:space:]]*$/d' "$1" | tr '\n' ' '
}

try_flowseal_confs()
{
    local conf opts

    for conf in "$FLOWSEAL_ALT_DIR"/*.nfqws2.conf; do
        [ -f "$conf" ] || continue

        echo "> custom flowseal strategy: $(basename "$conf")"

        opts="$(conf_to_params "$conf")"
        [ -n "$opts" ] || continue

        # shellcheck disable=SC2086
        pktws_curl_test_update "$@" $opts && return 0
    done

    return 1
}

pktws_check_https_tls12()
{
    try_flowseal_confs "$@"
}

pktws_check_https_tls13()
{
    try_flowseal_confs "$@"
}

pktws_check_http3()
{
    try_flowseal_confs "$@"
}