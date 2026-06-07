#!/bin/bash
# Usage: ./send_udp.sh <host> <port> <hex_string>

[[ $# -ne 3 ]] && { echo "Usage: $0 <host> <port> <hex_data>"; exit 1; }

echo "${3//[ :]}" | xxd -r -p | nc -u -w1 "$1" "$2"
