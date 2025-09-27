#!/bin/bash

# This script runs ffuf with a wordlist, URL, and Host header provided as arguments.

# Check if the required arguments (and optional -fs) are provided
if [ "$#" -ne 3 ] && [ "$#" -ne 5 ]; then
    echo "Usage: $0 <wordlist_file> <target_url> <target_host> [-fs <size>]"
    echo "Example: $0 wordlist.txt http://10.10.10.10 example.com"
    echo "Example: $0 wordlist.txt http://10.10.10.10 example.com -fs 4242"
    exit 1
fi

# Assign arguments to variables for clarity
WORDLIST=$1
URL=$2
HOST=$3
FILTER_SIZE=""

# Parse optional -fs flag when provided
if [ "$#" -eq 5 ]; then
    if [ "$4" != "-fs" ] || [ -z "$5" ]; then
        echo "Error: Optional flag must be provided as -fs <size>."
        echo "Usage: $0 <wordlist_file> <target_url> <target_host> [-fs <size>]"
        exit 1
    fi
    FILTER_SIZE=$5
fi

# Run ffuf once without filtering to let the user observe the response size
echo "🚀 Running initial command (without -fs): ffuf -w $WORDLIST -u $URL -H \"Host: FUZZ.$HOST\""
ffuf -w "$WORDLIST" -u "$URL" -H "Host: FUZZ.$HOST"

# Prompt the user for the response size to filter out if not supplied via -fs
if [[ -z "$FILTER_SIZE" ]]; then
    read -p $'Enter the response size to filter with -fs (press Enter to skip): ' FILTER_SIZE
fi

if [[ -n "$FILTER_SIZE" ]]; then
    echo "🚀 Running command with -fs $FILTER_SIZE: ffuf -w $WORDLIST -u $URL -H \"Host: FUZZ.$HOST\" -fs $FILTER_SIZE"
    ffuf -w "$WORDLIST" -u "$URL" -H "Host: FUZZ.$HOST" -fs "$FILTER_SIZE"
else
    echo "ℹ️ Skipping filtered run; no -fs size provided."
fi
