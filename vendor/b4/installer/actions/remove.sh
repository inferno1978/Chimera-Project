#!/bin/sh
# Action: Remove b4

action_remove() {
    check_root

    log_header "Removing B4"

    # Detect platform if not set
    if [ -z "$B4_PLATFORM" ]; then
        platform_auto_detect || true
        if [ -n "$B4_PLATFORM" ]; then
            platform_call info
        fi
    fi

    # Find config file — check all known locations
    _remove_find_config

    # Stop running process
    stop_b4

    # Remove service
    if [ -n "$B4_SERVICE_TYPE" ] && [ "$B4_SERVICE_TYPE" != "none" ]; then
        log_info "Removing service..."
        service_call remove 2>/dev/null || true
    else
        # Manual cleanup of known service locations
        for svc in \
            /etc/systemd/system/b4.service \
            /etc/init.d/b4 \
            /opt/etc/init.d/S99b4; do
            if [ -f "$svc" ]; then
                rm -f "$svc"
                log_info "Removed: $svc"
            fi
        done
        command_exists systemctl && systemctl daemon-reload 2>/dev/null || true
    fi

    # Remove features (geodat etc. — reads paths from config)
    features_remove

    # Remove binary from known locations
    for dir in /usr/local/bin /usr/bin /usr/sbin /opt/bin /opt/sbin /tmp/b4; do
        if [ -f "${dir}/${BINARY_NAME}" ]; then
            rm -f "${dir}/${BINARY_NAME}"
            rm -f "${dir}/${BINARY_NAME}".backup.* 2>/dev/null || true
            log_info "Removed binary from: ${dir}"
        fi
    done

    # Ask about config directories
    _remove_config_dirs

    # Cleanup
    rm -f /var/run/b4.pid 2>/dev/null || true
    rm -f /var/log/b4.log /opt/var/log/b4.log /tmp/log/b4.log 2>/dev/null || true
    rm -rf /var/log/b4 2>/dev/null || true

    echo ""
    log_ok "B4 has been removed"
    echo ""
}

# Find the active config file so features can read paths from it
_remove_find_config() {
    # Already set by platform detection or user override
    if [ -n "$B4_CONFIG_FILE" ] && [ -f "$B4_CONFIG_FILE" ]; then
        log_info "Using config: $B4_CONFIG_FILE"
        return 0
    fi

    # Search known locations
    for cfg in /etc/b4/b4.json /opt/etc/b4/b4.json /etc/storage/b4/b4.json; do
        if [ -f "$cfg" ]; then
            B4_CONFIG_FILE="$cfg"
            B4_DATA_DIR=$(dirname "$cfg")
            log_info "Found config: $B4_CONFIG_FILE"
            return 0
        fi
    done

    log_warn "No config file found"
}

# Remove config directories, but list what's inside first
_remove_config_dirs() {
    # Collect unique config dirs to check
    checked=""
    for cfg_dir in "$B4_DATA_DIR" /etc/b4 /opt/etc/b4 /etc/storage/b4; do
        [ -z "$cfg_dir" ] && continue
        [ -d "$cfg_dir" ] || continue
        # Skip if already checked (exact match to avoid substring false positives)
        case " $checked " in
        *" $cfg_dir "*) continue ;;
        esac
        checked="${checked} ${cfg_dir}"

        # Show remaining contents
        remaining=$(ls -1 "$cfg_dir" 2>/dev/null)
        if [ -n "$remaining" ]; then
            log_info "Remaining files in ${cfg_dir}:"
            echo "$remaining" | while read -r f; do
                printf "    %s\n" "$f" >&2
            done
        fi

        if [ "$QUIET_MODE" -eq 1 ] || confirm "Remove config directory ${cfg_dir}?" "n"; then
            rm -rf "$cfg_dir"
            log_info "Removed: ${cfg_dir}"
        else
            log_info "Keeping: ${cfg_dir}"
        fi
    done
}
