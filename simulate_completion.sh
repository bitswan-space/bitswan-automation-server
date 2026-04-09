#!/bin/bash

# This simulates what happens when bash completion is invoked
# Simulate the COMP_LINE and COMP_WORDS that bash would set

# When user types: ./bitswan workspace up[TAB]
export COMP_LINE="./bitswan workspace up"
export COMP_POINT=${#COMP_LINE}

# Parse COMP_LINE into words (this is what bash does)
words=($COMP_LINE)
echo "words array: ${words[@]}"
echo "words[0]: ${words[0]}"
echo ""

# This is what the completion script does in __bitswan_get_completion_results
args=("${words[@]:1}")
requestComp="${words[0]} __complete ${args[*]}"

echo "requestComp: $requestComp"
echo ""
echo "Running: $requestComp"
echo ""

# Actually run it
eval "$requestComp"
