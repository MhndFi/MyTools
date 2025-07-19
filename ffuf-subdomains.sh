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

# Print the command that is about to be executed
echo "🚀 Running command: ffuf -w $WORDLIST -u $URL -H \"Host: FUZZ.$HOST\""

# Execute the ffuf command
ffuf -w "$WORDLIST" -u "$URL" -H "Host: FUZZ.$HOST"
