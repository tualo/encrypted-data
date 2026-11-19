#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: $0 BASE_URL ID PRIVATE_KEY.asc [COOKIE_JAR]" >&2
    echo "       COOKIE_JAR is an optional curl cookie jar for the authenticated session." >&2
    exit 2
}

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage
base_url=${1%/}
id=$2
private_key=$3

case "$id" in
    ''|*[!A-Za-z0-9_-]*)
        echo "ID must contain only letters, digits, underscores, and hyphens." >&2
        exit 2
        ;;
esac
[ -r "$private_key" ] || {
    echo "Private key is not readable: $private_key" >&2
    exit 2
}
if [ "$#" -eq 4 ] && [ ! -r "$4" ]; then
    echo "Cookie jar is not readable: $4" >&2
    exit 2
fi

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
url="$base_url/encrypted-data/get/$id"
if [ "$#" -eq 4 ]; then
    curl --fail --silent --show-error --location --cookie "$4" "$url" |
        "$script_dir/decrypt-response.sh" "$private_key"
else
    curl --fail --silent --show-error --location "$url" |
        "$script_dir/decrypt-response.sh" "$private_key"
fi
