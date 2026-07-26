"""
chimera/modules/awg_constants.py
───────────────────────────────────────────────────────────────────────────────
Константы и пути для AmneziaWG 2.0 standalone-режима.

Это АВТОНОМНЫЙ модуль — он не переиспользует globals AWG_* из _core.py
(те относятся к chain Mode B transport). Все standalone-константы имеют
префикс AWGS_* (AWG Standalone), чтобы избежать любых коллизий.

Структура путей (совместима с upstream amneziawg-installer):
  /etc/amnezia/amneziawg/awg0.conf         — серверный конфиг
  /root/awg/                                — рабочая директория
  /root/awg/keys/                           — клиентские ключи и конфиги
  /root/awg/awgsetup_cfg.init               — primary state (init-файл)
  /var/lib/xray-installer/awg_standalone_state.json — state.json для нашего проекта
  /etc/cron.d/awg-standalone-expires        — cron автоудаления истёкших клиентов
  /etc/systemd/system/awg-cascade-routing.service — systemd для каскада (опционально)
"""
from __future__ import annotations

from pathlib import Path

# ── Имена и порты ────────────────────────────────────────────────────────────
AWGS_INTERFACE:        str  = "awg0"           # имя интерфейса (как в upstream)
AWGS_DEFAULT_PORT:     int  = 51820            # стандартный UDP-порт AWG
AWGS_DEFAULT_SUBNET:   str  = "10.66.66.0/24"  # /24 для клиентов (как в upstream)
AWGS_DEFAULT_SUBNET_V6: str = "fd66:66:66::/64"
AWGS_DEFAULT_MTU:      int  = 1280             # безопасный MTU для мобильных

# ── Пути ─────────────────────────────────────────────────────────────────────
AWGS_CONF_DIR:        Path = Path("/etc/amnezia/amneziawg")
AWGS_SERVER_CONF:     Path = AWGS_CONF_DIR / "awg0.conf"
AWGS_AWG_DIR:         Path = Path("/root/awg")
AWGS_KEYS_DIR:        Path = AWGS_AWG_DIR / "keys"
AWGS_INIT_FILE:       Path = AWGS_AWG_DIR / "awgsetup_cfg.init"
AWGS_LOG_FILE:        Path = AWGS_AWG_DIR / "awg_standalone.log"
AWGS_MANAGE_LOG:      Path = AWGS_AWG_DIR / "manage_awg.log"

# State для нашего проекта (отдельный файл, не смешиваем с основным state.json)
AWGS_STATE_FILE:      Path = Path("/var/lib/xray-installer/awg_standalone_state.json")

# Backup-директория
AWGS_BACKUP_DIR:      Path = AWGS_AWG_DIR / "backups"

# Cascade-файлы (опционально, только при установке каскада)
AWGS_CASCADE_DIR:     Path = Path("/etc/awg-cascade")
AWGS_RU_ZONE_FILE:    Path = AWGS_CASCADE_DIR / "ru.zone"
AWGS_ROUTING_SCRIPT:  Path = AWGS_CASCADE_DIR / "awg-routing.sh"
AWGS_IPSET_NAME:      str  = "awg_ru_networks"

# Cron-файлы
AWGS_CRON_EXPIRES:    Path = Path("/etc/cron.d/awg-standalone-expires")
AWGS_CRON_RU_UPDATE:  Path = Path("/etc/cron.d/awg-cascade-ru-update")

# Wrapper-скрипты для cron (bash with PYTHONPATH export).
# v5.1: bare `python3 -c "from chimera.modules..."` в cron НЕ работает —
# cron запускается с произвольной cwd и без PYTHONPATH, поэтому
# `from chimera...` падает с ModuleNotFoundError. Wrapper-скрипт
# экспорит PYTHONPATH перед вызовом python3 (тот же паттерн, что в
# node_health_monitor.py::install_health_monitor и geo_files.py).
AWGS_CRON_EXPIRES_SCRIPT:    Path = Path("/usr/local/sbin/awg-expires-check.sh")
AWGS_CRON_RU_UPDATE_SCRIPT:  Path = Path("/usr/local/sbin/awg-cascade-ru-update.sh")

# Systemd-юниты
AWGS_SYSTEMD_AWG_QUICK: str = "awg-quick@awg0.service"
AWGS_SYSTEMD_CASCADE:   Path = Path("/etc/systemd/system/awg-cascade-routing.service")

# ── Бинарники ────────────────────────────────────────────────────────────────
AWGS_BIN:       str = "awg"
AWGS_QUICK_BIN: str = "awg-quick"
AWGS_WG_BIN:    str = "wg"

# ── Применение конфига (syncconf vs restart) ────────────────────────────────
AWGS_APPLY_MODE_SYNCCONF: str = "syncconf"  # без даунтайма (по умолчанию)
AWGS_APPLY_MODE_RESTART:  str = "restart"   # fallback при kernel panic

# ── Дефолтные параметры обфускации (preset=default) ─────────────────────────
# Используются при первой установке, до применения carrier-пресета.
AWGS_DEFAULT_PARAMS: dict = {
    "jc":   4,
    "jmin": 40,
    "jmax": 70,
    "s1":   0,
    "s2":   0,
    "s3":   0,
    "s4":   0,
    "h1":   1,
    "h2":   2,
    "h3":   3,
    "h4":   4,
    "i1":   "",   # I1-I5 опциональны (пустая строка = не указывать)
    "i2":   "",
    "i3":   "",
    "i4":   "",
    "i5":   "",
}

# ── Валидационные диапазоны (из upstream) ───────────────────────────────────
AWGS_JC_MIN:        int = 1
AWGS_JC_MAX:        int = 128
AWGS_JMIN_MAX:      int = 1280
AWGS_JMAX_MAX:      int = 1280
AWGS_S3_MAX:        int = 64
AWGS_S4_MAX:        int = 32
AWGS_PORT_MIN:      int = 1
AWGS_PORT_MAX:      int = 65535

# ── Оптимизация sysctl (idempotent-применение) ──────────────────────────────
# Эти параметры будут применены ТОЛЬКО если текущее значение не оптимально.
AWGS_SYSCTL_TARGETS: dict = {
    "net.ipv4.ip_forward":              1,
    "net.ipv6.conf.all.forwarding":     1,   # только если IPv6 включён
    "net.core.default_qdisc":           "fq",
    "net.ipv4.tcp_congestion_control":  "bbr",
    "net.core.rmem_max":                7500000,
    "net.core.wmem_max":                7500000,
    "net.core.rmem_default":            7500000,
    "net.core.wmem_default":            7500000,
}

# ── IP-аллокация для пиров ──────────────────────────────────────────────────
# В /24 доступно 254 клиента (.1 = сервер, .2..254 = клиенты)
AWGS_PEER_IP_START: int = 2
AWGS_PEER_IP_END:   int = 254

# ── Fwmark для каскада (не конфликтует с chain Mode B, который использует 1000) ─
AWGS_CASCADE_FWMARK: int = 0x2000  # 8192 — отличается от AWG_FWMARK=1000

# ── Источники ru.zone для каскада ───────────────────────────────────────────
AWGS_RU_ZONE_URL: str = "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
AWGS_RU_ZONE_FALLBACK_GH: str = (
    "https://raw.githubusercontent.com/bivlked/amneziawg-installer/"
    "v5.18.4/cascade/ru.zone"
)

# ── Имена спец-пиров ────────────────────────────────────────────────────────
AWGS_CASCADE_ENTRY_PEER: str = "cascade_entry"   # пир на AWG0 для подключения к AWG1

# ── Timeout'ы ───────────────────────────────────────────────────────────────
AWGS_SYNC_TIMEOUT_SEC:    int = 15   # syncconf применение
AWGS_RESTART_TIMEOUT_SEC: int = 30   # restart сервиса
AWGS_PING_TIMEOUT_SEC:    int = 5    # проверка handshake
