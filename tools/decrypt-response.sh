#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: $0 PRIVATE_KEY.asc [RESPONSE.json]" >&2
    echo "       Omit RESPONSE.json to read the /encrypted-data/get/<id> JSON from stdin." >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
private_key=$1
[ -r "$private_key" ] || {
    echo "Private key is not readable: $private_key" >&2
    exit 2
}

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ "$#" -eq 2 ]; then
    [ -r "$2" ] || {
        echo "Response file is not readable: $2" >&2
        exit 2
    }
    exec node "$script_dir/decrypt-item.js" "$private_key" < "$2"
fi

exec node "$script_dir/decrypt-item.js" "$private_key"
