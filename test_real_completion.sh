#!/bin/bash

cd /home/john/bitswan-automation-server

# Source the completion - this registers it only for 'bitswan'
eval "$(./bitswan completion bash)"

# Now check what completions are registered
echo "=== Completions registered (via 'complete -p') ==="
complete -p | grep bitswan || echo "No completions found for 'bitswan'"
echo ""

# Try to manually trigger completion as if user typed ./bitswan workspace up[TAB]
echo "=== Attempting completion for ./bitswan workspace up[TAB] ==="
# In real bash, when you have completion registered for 'bitswan' but type './bitswan',
# bash won't use the __start_bitswan completion function at all.
# Instead, it will fall back to default file completion (showing directory contents)

# Simulate the test
export COMP_LINE="./bitswan workspace up"
export COMP_POINT=${#COMP_LINE}
export COMP_WORDS=($COMP_LINE)
export COMP_CWORD=2

# The problem: __start_bitswan is registered for the command 'bitswan'
# When you type './bitswan', bash doesn't match it against 'bitswan'
# So __start_bitswan is never called

echo "The real issue:"
echo "1. Completion is registered for: 'bitswan'"
echo "2. But the command typed is: './bitswan'"
echo "3. Bash doesn't match these, so __start_bitswan is NOT invoked"
echo "4. Instead, bash falls back to default completion (file listing)"
