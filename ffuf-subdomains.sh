#!/bin/bash

# This script runs ffuf with a wordlist, URL, and Host header provided as arguments.

# Check if all three arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <wordlist_file> <target_url> <target_host>"
    echo "Example: $0 wordlist.txt http://10.10.10.10 example.com"
    exit 1
fi

# Assign arguments to variables for clarity
WORDLIST=$1
URL=$2
HOST=$3

# Run ffuf once without filtering to let the user observe the response size
echo "🚀 Running initial command (without -fs): ffuf -w $WORDLIST -u $URL -H \"Host: FUZZ.$HOST\""
ffuf -w "$WORDLIST" -u "$URL" -H "Host: FUZZ.$HOST"

# Prompt the user for the response size to filter out
read -p $'Enter the response size to filter with -fs (press Enter to skip): ' FILTER_SIZE

if [[ -n "$FILTER_SIZE" ]]; then
    echo "🚀 Running command with -fs $FILTER_SIZE: ffuf -w $WORDLIST -u $URL -H \"Host: FUZZ.$HOST\" -fs $FILTER_SIZE"
    ffuf -w "$WORDLIST" -u "$URL" -H "Host: FUZZ.$HOST" -fs "$FILTER_SIZE"
else
    echo "ℹ️ Skipping filtered run; no -fs size provided."
fi
