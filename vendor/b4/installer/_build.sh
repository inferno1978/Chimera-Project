#!/bin/sh
# Builds install.sh from installer2/ components
# Auto-discovers platforms and features — just add files and rebuild

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="${SCRIPT_DIR}/../install.sh"

>"$OUTPUT"

# Append a file to output. First arg: file path, second: "header" to keep shebang
append() {
    file="$1"
    mode="$2"
    basename=$(echo "$file" | sed "s|${SCRIPT_DIR}/||")

    if [ ! -f "$file" ]; then
        echo "Missing: $basename" >&2
        exit 1
    fi

    if [ "$mode" = "header" ]; then
        # Header goes first — no prefix comment before shebang
        cat "$file" >>"$OUTPUT"
    else
        echo "" >>"$OUTPUT"
        # Skip shebang, strip comment-only lines (outside heredocs), collapse leading blanks
        tail -n +2 "$file" | awk '
            /<<[[:space:]]*EOF/ || /<<[[:space:]]*'\''EOF'\''/ { heredoc=1 }
            heredoc { print; if (/^EOF$/) heredoc=0; next }
            /^[[:space:]]*#/ { next }
            { print }
        ' | sed '/./,$!d' >>"$OUTPUT"
    fi

    echo "" >>"$OUTPUT"
}

# 1. Header (keep shebang)
append "${SCRIPT_DIR}/header.sh" "header"

# 2. Lib modules (fixed order: colors first, then log, then rest)
append "${SCRIPT_DIR}/lib/colors.sh"
append "${SCRIPT_DIR}/lib/log.sh"
append "${SCRIPT_DIR}/lib/utils.sh"
append "${SCRIPT_DIR}/lib/wizard.sh"

# 3. Platform system: interface, detect, then auto-discover platform files
append "${SCRIPT_DIR}/platforms/_interface.sh"
append "${SCRIPT_DIR}/platforms/_detect.sh"
for f in "${SCRIPT_DIR}"/platforms/*.sh; do
    case "$(basename "$f")" in
    _*) continue ;; # skip _interface.sh, _detect.sh
    esac
    append "$f"
done

# 4. Feature system: interface, then auto-discover feature files
append "${SCRIPT_DIR}/features/_interface.sh"
for f in "${SCRIPT_DIR}"/features/*.sh; do
    case "$(basename "$f")" in
    _*) continue ;; # skip _interface.sh
    esac
    append "$f"
done

# 5. Service system: interface, then auto-discover service files
append "${SCRIPT_DIR}/services/_interface.sh"
for f in "${SCRIPT_DIR}"/services/*.sh; do
    case "$(basename "$f")" in
    _*) continue ;; # skip _interface.sh
    esac
    append "$f"
done

# 6. Actions (fixed order)
for action in install remove update sysinfo; do
    file="${SCRIPT_DIR}/actions/${action}.sh"
    [ -f "$file" ] && append "$file"
done

# 7. Main entry point
append "${SCRIPT_DIR}/main.sh"

# Collapse multiple consecutive blank lines
sed -i '/^$/N;/^\n$/d' "$OUTPUT"

chmod +x "$OUTPUT"
echo "Built: $OUTPUT ($(wc -l <"$OUTPUT") lines)"
