#!/bin/sh
# Service type: none
# No-op service management — used when no init system is available

service_none_install() {
    log_warn "No init system configured — b4 will not start automatically"
    log_info "Start manually: ${B4_BIN_DIR}/${BINARY_NAME} --config ${B4_CONFIG_FILE}"
}

service_none_remove() {
    return 0
}

service_none_start() {
    log_warn "No service configured — start b4 manually"
    return 1
}

service_none_stop() {
    return 0
}

register_service "none"
