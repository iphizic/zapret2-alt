#!/bin/sh

FLOWSEAL_ALT_DIR=<set_path>

conf_to_params()
{
    awk '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }

        function flush_profile() {
            if (has_tcp443 && has_tls && profile != "") {
                if (selected > 0) {
                    print "--new"
                }
                printf "%s", profile
                selected++
            }

            profile = ""
            has_tcp443 = 0
            has_tls = 0
        }

        {
            sub(/#.*/, "", $0)
            line = trim($0)

            if (line == "") {
                next
            }

            if (line ~ /^--blob=/) {
                print line
                next
            }

            if (line == "--new" || line ~ /^--new=/) {
                flush_profile()
                next
            }

            if (line == "--filter-tcp=443") {
                has_tcp443 = 1
                next
            }

            if (line == "--filter-l7=tls") {
                has_tls = 1
                next
            }

            profile = profile line "\n"
        }

        END {
            flush_profile()
        }
    ' "$1" | tr '\n' ' '
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
