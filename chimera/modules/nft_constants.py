"""
chimera/modules/nft_constants.py
───────────────────────────────────────────────────────────────────────────────
Реестр констант для nftables-уровня Chimera.

Содержит:
  • Имена таблиц и цепочек Chimera (единый namespace для всех модулей)
  • Реестр comment-тегов (используются для идемпотентности и безопасного
    удаления правил — заменяют сценарии "удалять в цикле пока -D не вернёт
    ошибку" на "найти и удалить все правила с comment = X")
  • Реестр fwmark-ов (для policy routing)
  • Реестр ipset-имён (псевдонимы для nft sets, для совместимости со старыми
    именами при сохранении/восстановлении)

Вся магия констант должна жить здесь, чтобы при миграции можно было
аудитировать их в одном месте. Соответствующие числовые значения для
ip rule (fwmark → routing table → priority) определены в _core.py и
остаются неизменными — миграция не должна их трогать.

 migrations notes:
  • Все nft sets теперь живут в одной таблице `chimera` (family inet) —
    это даёт и v4, и v6 в одной таблице, без дублирования ip6tables.
  • Все comment-теги сохраняют префикс "xray-" / "telemt-" / "chimera-"
    чтобы при просмотре `nft list ruleset` было видно, что правило создано
    Chimera (а не ufw, docker или кем-то ещё).
  • Имена nft sets несут тот же суффикс что и ipset-имена — для ease of
    migration review и для сохранения semantics в state.json.
"""
from __future__ import annotations

# ════════════════════════════════════════════════════════════════════════════
#  NFTABLES TABLE / CHAIN NAMESPACE
# ════════════════════════════════════════════════════════════════════════════
# Единая таблица для всех правил Chimera. family=inet покрывает и v4, и v6
# (большая победа над дублированием iptables/ip6tables).
NFT_TABLE_FAMILY = "inet"
NFT_TABLE_NAME   = "chimera"

# Имена базовых цепочек (hooks). Имена lowercase чтобы соответствовать
# nftables конвенции (input/forward/output/prerouting/postrouting).
NFT_CHAIN_INPUT       = "input"
NFT_CHAIN_FORWARD     = "forward"
NFT_CHAIN_OUTPUT      = "output"
NFT_CHAIN_PREROUTING  = "prerouting"
NFT_CHAIN_POSTROUTING = "postrouting"

# Mangle-цепочки в nftables используют тип hook=route (для OUTPUT) и
# hook=filter priority=mangle (для FORWARD).
NFT_CHAIN_MANGLE_OUTPUT  = "mangle_output"
NFT_CHAIN_MANGLE_FORWARD = "mangle_forward"

# Пользовательские цепочки Chimera (аналоги iptables -N XRU_BLOCK, TELEMT_STATS_IN и т.д.)
NFT_CHAIN_XRU_BLOCK      = "xru_block"          # ingress_geoip — geo-block chain
NFT_CHAIN_TELEMT_STATS_IN  = "telemt_stats_in"   # mtproto_stats — per-port in accounting
NFT_CHAIN_TELEMT_STATS_OUT = "telemt_stats_out"  # mtproto_stats — per-port out accounting

# ════════════════════════════════════════════════════════════════════════════
#  COMMENT TAGS — для идемпотентности и безопасного удаления
# ════════════════════════════════════════════════════════════════════════════
# Все Chimera-правила несут comment из этого реестра. Это позволяет:
#   • Безопасно удалять все правила тега за один вызов
#     nft_rule_delete_by_comment(table, chain, comment)
#   • Легко найти "свои" правила в `nft list ruleset`
#   • Избегать коллизий с правилами UFW/docker/手工-администратора
COMMENT_AUTOBAN_BAN        = "xray-autoban"
COMMENT_AUTOBAN_UNBAN       = "xray-autoban"  # тот же тег, удаление по -D
COMMENT_MANUAL_BAN         = "xray-manual-ban"
COMMENT_INGRESS_GEO_BLOCK  = "xray-ru-ingress-block"
COMMENT_INGRESS_WL_PREFIX  = "xray-ru-wl-"     # + IP для per-IP whitelist
COMMENT_GEOBLOCK_PREFIX    = "telemt-geoblock-"  # + country code
COMMENT_CLIENTS_WL         = "chimera-clients-wl"
COMMENT_MITA_STATS         = "mita-stats"
COMMENT_PORT_HOPPING       = "xray-port-hopping"
COMMENT_SYN_LIMIT_ACCEPT   = "telemt-syn-limit-accept"
COMMENT_SYN_LIMIT_REJECT   = "telemt-syn-limit-reject"
COMMENT_DNS_REDIRECT       = "xray-dns-redirect"   # dns_redirect.py (PREROUTING for VPN clients)
COMMENT_DNS_LOCAL_REDIRECT = "chimera-dns-fix"     # resolv_conf_fix.py (OUTPUT for local processes)
COMMENT_AWG_MASQ           = "awg-masquerade"
COMMENT_AWG_FWMARK_XRAY    = "awg-fwmark-xray"
COMMENT_AWG_FWMARK_DNSCRYPT = "awg-fwmark-dnscrypt"
COMMENT_AWG_FWMARK_PER_NODE = "awg-fwmark-node-"   # + node_index
COMMENT_AWG_CASCADE_MARK   = "awg-cascade-fwmark"
COMMENT_TELEMT_WARP_MARK   = "telemt-warp-fwmark"
COMMENT_TELEMT_TPROXY_BYPASS = "telemt-tproxy-bypass"
COMMENT_MSS_CLAMP          = "chimera-mss-clamp"
COMMENT_OPEN_PORT_PREFIX   = "chimera-open-port-"  # + proto-port (для audit)
COMMENT_SINGBOX_CDN_PREFIX = "chimera-singbox-cdn-"  # + port

# ════════════════════════════════════════════════════════════════════════════
#  FWMARK REGISTRY — для policy routing
# ════════════════════════════════════════════════════════════════════════════
# ВАЖНО: эти значения НЕ должны меняться без синхронизации с соответствующими
# ip rule / ip route конфигурациями. Миграция на nft не меняет fwmark —
# только меняет способ установки MARK правила (iptables -j MARK → nft meta mark set).
#
# Соответствующие ip rule / routing tables определены в:
#   • awg_transport.py — AWG_FWMARK, AWG_ROUTE_TABLE
#   • awg_cascade.py — AWGS_CASCADE_FWMARK=0x2000, ROUTE_TABLE=2000
#   • telemt_warp_route.py — FWMARK=300, ROUTE_TABLE=300, RULE_PRIORITY=150
#   • awg Multi-Node — per-node fwmark (1000 + node_index)

# AWG основной fwmark (значение берётся из _core.AWG_FWMARK)
# Здесь только документация — реальное значение живёт в _core.py

# AWG каскад: fwmark 0x2000 (8192), routing table 2000
AWGS_CASCADE_FWMARK = 0x2000
AWGS_CASCADE_ROUTE_TABLE = 2000

# Telemt → WARP: fwmark 300, table 300, priority 150
TELEMT_WARP_FWMARK = 300
TELEMT_WARP_ROUTE_TABLE = 300
TELEMT_WARP_RULE_PRIORITY = 150

# AWG Multi-Node: per-node fwmark (1000 + node_index)
AWG_MULTINODE_FWMARK_BASE = 1000

# ════════════════════════════════════════════════════════════════════════════
#  NFT SETS REGISTRY — заменa ipset-имён
# ════════════════════════════════════════════════════════════════════════════
# Все nft sets живут в одной таблице chimera. Имена максимально приближены
# к старым ipset-именам, чтобы было легче ревьюить миграцию.

# ipban.py — manual ban sets (v4 + v6)
NFT_SET_MANUAL_BAN_V4 = "manual_ban_v4"
NFT_SET_MANUAL_BAN_V6 = "manual_ban_v6"

# ingress_geoip.py — Russia/geo-egress block (default cc=ru)
NFT_SET_INGRESS_BLOCK_V4 = "ingress_block_v4"
NFT_SET_INGRESS_BLOCK_V6 = "ingress_block_v6"

# geoblock.py — per-country geoblock (telemt-geoblock-<cc>)
# Имя генерируется динамически: f"geoblock_{cc.lower()}_v4"
def geoblock_set_name(cc: str, ipv6: bool = False) -> str:
    """Имя nft set для geoblock страны cc (ISO 3166-1 alpha-2 lower)."""
    suffix = "v6" if ipv6 else "v4"
    return f"geoblock_{cc.lower()}_{suffix}"

# user_ip_whitelist.py — clients whitelist (chimera-clients-wl)
NFT_SET_CLIENTS_WL_V4 = "clients_wl_v4"
NFT_SET_CLIENTS_WL_V6 = "clients_wl_v6"

# singbox_cdn_nets.py — per-port CDN allowlist
def singbox_cdn_set_name(port: int) -> str:
    """Имя nft set для sing-box CDN allowlist на конкретном порту."""
    return f"singbox_cdn_{port}"

# awg_cascade.py — AWG-servers cascade set
NFT_SET_AWG_CASCADE = "awg_cascade_nodes"

# ════════════════════════════════════════════════════════════════════════════
#  PERSIST FILE PATHS
# ════════════════════════════════════════════════════════════════════════════
# nftables.service (Debian/Ubuntu package) reads /etc/nftables.conf by default
# on `systemctl reload nftables`. Заменяет /etc/iptables/rules.v4 + rules.v6 +
# /etc/ipset.conf тремя отдельными файлами.
NFT_PERSIST_FILE = "/etc/nftables.conf"

# Альтернативный persist-файл для отдельных подсистем (для совместимости
# с legacy telemt-iptables.service — переходный период):
# /etc/nftables-chimera-include.conf — инклудится из /etc/nftables.conf
# через `include "/etc/nftables-chimera-include.conf"`.
NFT_PERSIST_INCLUDE_FILE = "/etc/nftables-chimera-include.conf"

# ════════════════════════════════════════════════════════════════════════════
#  BACKWARD COMPAT — сохранение для state.json и interop
# ════════════════════════════════════════════════════════════════════════════
# При миграции важно: state.json, генерируемый каждым модулем, может содержать
# имена ipset-ов. Чтобы не сломать чтение старых state-файлов, при загрузке
# state мы конвертируем старые имена в новые через map ниже.
LEGACY_IPSET_NAME_MAP = {
    # ipban.py
    "xray_manual_ban":   NFT_SET_MANUAL_BAN_V4,
    "xray_manual_ban6":  NFT_SET_MANUAL_BAN_V6,
    # ingress_geoip.py
    "xray_ru_block":     NFT_SET_INGRESS_BLOCK_V4,
    "xray_ru_block6":    NFT_SET_INGRESS_BLOCK_V6,
    # user_ip_whitelist.py
    "chimera_clients_wl":    NFT_SET_CLIENTS_WL_V4,
    "chimera_clients_wl6":    NFT_SET_CLIENTS_WL_V6,
    # awg_cascade.py
    "awgs_ipset":        NFT_SET_AWG_CASCADE,
}

# Реестр всех известных Chimera comment-тегов (для safe cleanup — удалить
# вообще все правила Chimera из таблицы). Используется в emergency_repair.py.
ALL_CHIMERA_COMMENT_PREFIXES = (
    "xray-", "telemt-", "chimera-", "mita-", "awg-",
)

# Реестр всех известных Chimera nft sets (для safe cleanup).
ALL_CHIMERA_SETS = (
    NFT_SET_MANUAL_BAN_V4, NFT_SET_MANUAL_BAN_V6,
    NFT_SET_INGRESS_BLOCK_V4, NFT_SET_INGRESS_BLOCK_V6,
    NFT_SET_CLIENTS_WL_V4, NFT_SET_CLIENTS_WL_V6,
    NFT_SET_AWG_CASCADE,
)
