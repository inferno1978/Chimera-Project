"""
chimera/modules/awg_constants.py
───────────────────────────────────────────────────────────────────────────────
Константы и пути для AmneziaWG standalone-режима (протокол 2.0 и 3.1).

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
# конфиг каскадного туннеля awg1 на entry-ноде (RU → активный exit).
# Константа (не литерал в коде) — тестируемость + единая точка правды.
AWGS_AWG1_CONF:       Path = AWGS_CONF_DIR / "awg1.conf"
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

# ── Мульти-exit каскад + авто-failover ──────────────────────────────
# Каскад RU (вход) → несколько зарубежных выходов. Активен один awg1-туннель;
# failover-таймер раз в минуту проверяет handshake и при смерти активного
# exit переключает awg1 на следующий по списку (порядок = приоритет).
AWGS_CASCADE_EXITS_KEY:  str  = "cascade_exits"        # список exit-боксов в state
AWGS_CASCADE_ACTIVE_KEY: str  = "cascade_active_exit"  # имя активного exit
AWGS_FAILOVER_SCRIPT:     Path = Path("/usr/local/sbin/awg-cascade-failover.sh")
AWGS_SYSTEMD_FAILOVER_SVC: Path = Path("/etc/systemd/system/awg-cascade-failover.service")
AWGS_SYSTEMD_FAILOVER_TIMER: Path = Path("/etc/systemd/system/awg-cascade-failover.timer")
# handshake старше N секунд = подозрение на мёртвый туннель. Keepalive 25с +
# RejectAfterTime 161-216с (3.1) дают максимум ~4 мин между handshake при
# живом туннеле — 300с = безопасный порог без ложных срабатываний.
AWGS_FAILOVER_STALE_SEC: int = 300
# Сколько секунд ждать handshake после переключения на exit-кандидата.
AWGS_FAILOVER_PROBE_SEC: int = 18
# Разумный верхний предел списка exit-нод.
AWGS_FAILOVER_MAX_EXITS: int = 16

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

# ── Версия протокола AmneziaWG (2.0 / 3.1) ────────────────────────────────
# Единая точка правды — chimera/modules/awg_protocol.py (awg_normalize_version).
# Здесь — только константы для standalone-мира (AWGS_*).
# Отсутствие protocol_version в state.json = старая установка = "2.0".
AWGS_PROTOCOL_VERSION_20: str = "2.0"
AWGS_PROTOCOL_VERSION_31: str = "3.1"
AWGS_PROTOCOL_VERSIONS:  tuple = (AWGS_PROTOCOL_VERSION_20, AWGS_PROTOCOL_VERSION_31)
AWGS_DEFAULT_PROTOCOL_VERSION: str = AWGS_PROTOCOL_VERSION_20

# ── Валидационные диапазоны AWG 3.1 (констрейнты GenerateObfuscation31, ─────
# те же, что в wpp_awg.py — мир WPP-профилей уже поддерживает 3.1):
# S1/S2 ≥ 12 байт (HeaderProtectionKey требует паддинга ≥ 12),
# S3 12-55, S4 12-27, Jmax ≤ 339 (Jmin ≤ 89 + delta ≤ 250).
AWGS31_S1_MIN: int = 15
AWGS31_S1_MAX: int = 150
AWGS31_S2_MIN: int = 15
AWGS31_S2_MAX: int = 150
AWGS31_S3_MIN: int = 12
AWGS31_S3_MAX: int = 55
AWGS31_S4_MIN: int = 12
AWGS31_S4_MAX: int = 27
AWGS31_JMIN_MIN: int = 40
AWGS31_JMIN_MAX: int = 89
AWGS31_JMAX_DELTA_MIN: int = 50
AWGS31_JMAX_DELTA_MAX: int = 250
AWGS31_JMAX_MAX: int = 339   # 89 + 250

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
# марка каскада = 0x2000 | 0x8000. Бит 0x8000 — «b4-exempt»: на нодах
# с DPI-bypass b4 (nft inet b4_mangle: tcp/443 ct<20 → nfqueue 537-540)
# помеченные этим битом флоу пропускаются мимо перехвата. Без бита b4
# пере-инжектирует обработанные (fragmentation/desync) пакеты БЕЗ fwmark —
# они уходят raw с WAN entry-ноды, и TSPU/Google убивают их по SNI
# (E2E 2026-10-05: YouTube через каскад не работал у юзера ровно по этой
# причине; api64/cloudflare при этом работали). Каскадный трафик
# шифруется до exit-ноды — DPI-bypass ему не нужен. На системах без b4
# бит 0x8000 безвреден (никем не проверяется).
AWGS_B4_EXEMPT_BIT: int = 0x8000
AWGS_CASCADE_FWMARK_LEGACY: int = 0x2000  # легаси-марка (без b4-exempt бита) — только для cleanup
AWGS_CASCADE_FWMARK: int = 0x8200  # 33280 = 0x8000 (b4-exempt) | 0x0200 (тег каскада)

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
