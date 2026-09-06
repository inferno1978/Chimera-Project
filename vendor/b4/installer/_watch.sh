#!/bin/sh
# Watch for changes and rebuild

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$SCRIPT_DIR/_build.sh"

# Try inotifywait first (Linux)
if command -v inotifywait >/dev/null 2>&1; then
    echo "Watching installer2/ with inotifywait..."
    while true; do
        inotifywait -r -q -e modify,create,delete "$SCRIPT_DIR" --exclude '_watch\.sh|\.swp'
        echo "Change detected, rebuilding..."
        "$SCRIPT_DIR/_build.sh"
    done
# Try fswatch (macOS)
elif command -v fswatch >/dev/null 2>&1; then
    echo "Watching installer2/ with fswatch..."
    fswatch -r -o "$SCRIPT_DIR" | while read _; do
        echo "Change detected, rebuilding..."
        "$SCRIPT_DIR/_build.sh"
    done
# Fallback: polling
else
    echo "No inotifywait/fswatch, using polling (2s)..."
    last_hash=""
    while true; do
        current_hash=$(find "$SCRIPT_DIR" -name '*.sh' ! -name '_watch.sh' -exec cat {} + 2>/dev/null | md5sum | cut -d' ' -f1)
        if [ "$current_hash" != "$last_hash" ]; then
            [ -n "$last_hash" ] && echo "Change detected, rebuilding..." && "$SCRIPT_DIR/_build.sh"
            last_hash="$current_hash"
        fi
        sleep 2
    done
fi
