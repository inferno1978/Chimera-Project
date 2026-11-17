"""
chimera/modules/smartdns_stack.py
───────────────────────────────────────────────────────────────────────────────
Компонентный слой SmartDNS-ноды: DoH/DoT stealth + прозрачный SNI-прокси.

Python-переписывание bash-установщика smartdns-installer v2.10.0-stealth
(репо EvgenyElizarenko/smartdns-installer) в экосистему Chimera — v3.0.0.
Решение владельца 17.11.2026: bash → Python, паттерн интеграции — модуль B4
(dpi_bypass.py): установка через download_manager, порты через port_registry,
обновление «руками + авто-latest при первичной установке».

АРХИТЕКТУРА СТЕКА (паритет с bash v2.10.0, paths неймспейснуты под v3):

  клиент DoH → :8444 xray dokodemo (SNI sniff, stealth)
                  └─ SNI=наш домен → 127.0.0.1:9444 nginx (proxy_protocol v1)
                       └─ /resolve/<SECRET> → 127.0.0.1:8053 движок DoH
  клиент DoT → :853 xray dokodemo → 127.0.0.1:8853 nginx stream (TLS term)
                  └─ → 127.0.0.1:5353 движок plain DNS
  браузер    → :80 nginx (redirect), :9443 nginx TLS (cover site + web-auth
               закладка /auth/<SECRET> — ipset-авторизация на 24ч)
  GeoHide:   заблокированные домены резолвятся движком в SERVER_IP
             (smart_a/hosts), клиент идёт на 443 → NAT REDIRECT → 8444/9443.

  Движок: oxidns (YAML, x86_64) или AdGuardHome (YAML, все arch).
  Компоненты: /opt/smartdns/bin/{xray,oxidns,AdGuardHome} — СВОИ бинарники,
  юниты smartdns-*.service — не пересекаются со стеком Химеры НИКОГДА
  (companion-режим: тот же VPS + второй IP, см. smartdns.py).

Слои (три модуля, как b4_monitor/b4_route_addon/dpi_bypass):
  smartdns.py        — оркестрация: режимы standalone/companion, wizard-боксы,
                       install/update/uninstall/status/backup/rollback, CLI/TUI;
  smartdns_stack.py  — ЭТОТ модуль: загрузки (download_manager), конфиги,
                       nginx, сертификат/Cloudflare, юниты, geo-списки;
  smartdns_firewall.py — iptables/ipset/ufw (per-IP в companion), ватчеры,
                       DoT/DoH whitelist.

Публичный API (для smartdns.py):
    install_system_packages() / setup_users_and_dirs(cfg)
    install_binaries(cfg) -> dict[versions]
    write_xray_config(cfg) / write_engine_config(cfg) / link_routing(cfg)
    generate_cover_site(cfg, seed) -> Path
    apply_nginx(cfg) -> (bool, str)      # full | drop-in + stream-include
    sync_cloudflare_records(cfg, ipv4, ipv6) -> bool
    issue_wildcard_certificate(cfg) -> bool
    write_systemd_units(cfg) / enable_and_start(cfg)
    update_geosite(cfg) / update_geohide(cfg) -> bool
    verify_dns_backend(cfg) -> (bool, list[str])
    github_latest_tag(owner, repo) / version_key(v)

CLI (для systemd-таймеров, PYTHONPATH от юнита):
    python3 -m chimera.modules.smartdns_stack update-geosite|update-geohide
"""
from __future__ import annotations

import json
import os
import random
import re
import secrets as _pysecrets
import shutil
import string
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

from chimera.modules.download_manager import PackageSpec, fetch_package
from chimera.modules.github_mirrors import build_mirror_urls

# ── Логирование (единый формат с остальными модулями) ──────────────────────
_LOG_FILE = Path("/var/log/chimera.log")


def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r"\x1b\[[0-9;]*m", "", msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [smartdns] [{level}] {clean}\n")
    except Exception:
        pass


def _info(msg: str) -> None: print(f"  [INFO]  {msg}"); _log("INFO", msg)
def _ok(msg: str) -> None:   print(f"  [OK]    {msg}"); _log("OK", msg)
def _warn(msg: str) -> None: print(f"  [WARN]  {msg}"); _log("WARN", msg)
def _err(msg: str) -> None:  print(f"  [ERR]   {msg}"); _log("ERR", msg)


# ══════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ: пути (неймспейс v3 — ничего общего со стеком Химеры)
# ══════════════════════════════════════════════════════════════════════════

STACK_VERSION = "3.0.0"          # версия Python-стека (наследник bash 2.10.0)

SMARTDNS_BASE    = Path("/opt/smartdns")
BIN_DIR          = SMARTDNS_BASE / "bin"          # xray, oxidns, AdGuardHome + runtime-скрипты
XRAY_BIN         = BIN_DIR / "xray"
OXIDNS_BIN       = BIN_DIR / "oxidns"
AGH_BIN          = BIN_DIR / "AdGuardHome"

CONF_ROOT        = Path("/etc/smartdns")
XRAY_CONF_DIR    = CONF_ROOT / "xray" / "conf.d"
XRAY_RULES_DIR   = CONF_ROOT / "xray" / "rules.d"
OXIDNS_CONF_DIR  = CONF_ROOT / "oxidns"
AGH_CONF_DIR     = CONF_ROOT / "adguardhome"
XRAY_LOG_DIR     = Path("/var/log/smartdns/xray")

STATE_DIR        = Path("/var/lib/xray-installer/smartdns")
SETTINGS_FILE    = STATE_DIR / "settings.json"
SECRETS_FILE     = STATE_DIR / "secrets.json"
VERSIONS_FILE    = STATE_DIR / "versions.json"
BACKUP_ROOT      = STATE_DIR / "backups"
IPSET_SAVE_FILE  = STATE_DIR / "ipset-whitelist.save"

ASSETS_DIR       = Path("/var/lib/smartdns-dns-assets")
GEOSITE_DAT      = ASSETS_DIR / "geosite.dat"
GEOHIDE_HOSTS_URL_RAW = ("https://raw.githubusercontent.com/Internet-Helper/"
                         "GeoHideDNS/refs/heads/main/hosts/hosts")

LOG_DIR          = Path("/var/log/smartdns")
CERT_DIR         = Path("/etc/ssl/smartdns")
WEB_ROOT         = Path("/var/www/smartdns-cover")

# nginx drop-in'ы (companion/чужой nginx) — НИКОГДА не правим основной
# /etc/nginx/nginx.conf, кроме идемпотентного stream-include-хука.
NGINX_HTTP_DROPIN  = Path("/etc/nginx/conf.d/smartdns.conf")
NGINX_STREAM_DROPIN_DIR = Path("/etc/nginx/stream-conf.d")
NGINX_STREAM_DROPIN = NGINX_STREAM_DROPIN_DIR / "smartdns-dot.conf"
NGINX_MARKER     = "# managed by smartdns-installer (chimera)"

# Порты стека (регистрируются в port_registry тегами SERVICE_SMARTDNS_*)
PORT_HTTP    = 80     # nginx → https redirect (companion: bind_ip)
PORT_DOT     = 853    # xray DoT dokodemo (companion: bind_ip)
PORT_DOH     = 8444   # xray DoH stealth dokodemo (companion: bind_ip)
PORT_WEB     = 9443   # nginx cover-site TLS (companion: bind_ip)
PORT_ENGINE  = 5353   # DNS-движок loopback (tcp+udp)
PORT_DOHLOC  = 8053   # DNS-движок DoH loopback
PORT_DOTHERM = 8853   # nginx stream DoT-терминатор loopback
PORT_STEALTH = 9444   # nginx stealth-фронт loopback (proxy_protocol)

# systemd-юниты (полный неймспейс — сосуществуют со стеком Химеры)
UNIT_XRAY        = "smartdns-xray.service"
UNIT_OXIDNS      = "smartdns-oxidns.service"
UNIT_AGH         = "smartdns-adguardhome.service"
UNIT_FW          = "smartdns-firewall.service"
UNIT_DOH_WATCH   = "smartdns-doh-watcher.service"
UNIT_DOT_WATCH   = "smartdns-dot-watcher.service"
UNIT_RELOAD_PATH = "smartdns-xray-reload.path"
UNIT_RELOAD_SVC  = "smartdns-xray-reload.service"
UNIT_GEOSITE_SVC = "smartdns-geosite-update.service"
UNIT_GEOSITE_TMR = "smartdns-geosite-update.timer"
UNIT_GEOHIDE_SVC = "smartdns-geohide-update.service"
UNIT_GEOHIDE_TMR = "smartdns-geohide-update.timer"
ALL_UNITS = [UNIT_XRAY, UNIT_OXIDNS, UNIT_AGH, UNIT_FW, UNIT_DOH_WATCH,
             UNIT_DOT_WATCH, UNIT_RELOAD_PATH, UNIT_RELOAD_SVC,
             UNIT_GEOSITE_SVC, UNIT_GEOSITE_TMR, UNIT_GEOHIDE_SVC, UNIT_GEOHIDE_TMR]

# Системные пользователи (companion: Химера не использует эти имена)
USER_XRAY = "smartdns"
USER_OXIDNS = "oxidns"
USER_AGH = "adguard"
GRP_SSL = "ssl-smartdns"

# Источники компонентов: GitHub latest-release + проверенный фолбэк-тег
# (паттерн B4: _resolve_install_version — свежий release при живом GitHub,
# зашитая версия при недоступном; установка НЕ падает из-за метаданных).
XRAY_REPO     = ("XTLS", "Xray-core")
XRAY_FALLBACK_TAG = "v26.11.9"
OXIDNS_REPO   = ("svenshi", "oxidns")
OXIDNS_FALLBACK_TAG = "v1.7.1"
OXIDNS_ASSET_RE = r"^(oxidns-)?x86_64.*linux.*\.tar\.gz$"
AGH_REPO      = ("AdguardTeam", "AdGuardHome")
AGH_FALLBACK_TAG = "v0.107.62"
GEOSITE_REPO  = ("Loyalsoldier", "v2ray-rules-dat")
GEOSITE_MIN_SIZE = 100_000

MIN_GE0HIDE_DOMAINS = 5          # защита от битого списка (как bash: <5 → откат)

# Исходные домены GeoHide, добавляемые при EXCLUDE_GOOGLE_SYS=N (паритет bash)
_EXTRA_GOOGLE_DOMAINS = [
    "apis.google.com", "suggestqueries.google.com", "clients6.google.com",
    "clients.google.com", "withgoogle.com", "o.pki.goog",
    "googleapis.com", "generativelanguage.googleapis.com",
]
_EXTRA_XBOX_DOMAINS = ["xboxlive.com", "xbox.com", "sfx.ms", "msgamestudios.com"]

# Безусловные исключения (x.com/meta.ai + captive-portal детект Wi-Fi):
# пока гаджет не авторизован, его запросы к детект-доменам НЕ должны
# попадать в спуфнутый 443 (иначе каптив-чек зависает) — как в bash.
_ALWAYS_EXCLUDE_RE = [
    r"^x\.com$", r"\.x\.com$",
    r"^meta\.ai$", r"\.meta\.ai$",
    r"^connectivitycheck\.gstatic\.com$", r"^connectivitycheck\.android\.com$",
    r"^clients[0-9]*\.google\.com$",
    r"^captive\.apple\.com$", r"^connect\.rom\.miui\.com$",
    r"^msftconnecttest\.com$", r"\.msftconnecttest\.com$",
    r"^msftncsi\.com$", r"\.msftncsi\.com$",
]
_EXCLUDE_GOOGLE_RE = [
    r"^apis\.google\.com$", r"^suggestqueries\.google\.com$",
    r"^o\.pki\.goog$", r"^clients6\.google\.com$", r"\.clients6\.google\.com$",
    r"^clients\.google\.com$", r"\.clients\.google\.com$",
    r"^withgoogle\.com$", r"\.withgoogle\.com$",
    r"^googleapis\.com$", r"\.googleapis\.com$",
]
_EXCLUDE_XBOX_RE = [r"^xboxlive\.com$", r"\.xboxlive\.com$",
                    r"^xbox\.com$", r"\.xbox\.com$"]

_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


# ══════════════════════════════════════════════════════════════════════════
#  ВЕРСИИ / GITHUB LATEST (паттерн _detect_latest_version + _b4_version_key)
# ══════════════════════════════════════════════════════════════════════════

def version_key(v: str) -> tuple:
    """Ключ сравнения semver-подобных версий ('v26.11.9', '1.7.1', 'v0.107.62').

    Возвращает (numbers, is_release, suffix): release > pre-release при
    равных числах; мусор/пусто → ((0,), 0, '') — «не сравнимо».
    Зеркалирует dpi_bypass._b4_version_key.
    """
    v = str(v or "").strip().lstrip("vV")
    m = re.match(r"^(\d+(?:\.\d+)*)", v)
    if not m:
        return ((0,), 0, "")
    nums = tuple(int(x) for x in m.group(1).split("."))
    suffix = v[m.end():]
    # release (без суффикса) СТАРШЕ pre-release с теми же числами:
    # is_release=1 > is_release=0 — как dpi_bypass._b4_version_key.
    return (nums, 0 if suffix else 1, suffix)


def github_latest_tag(owner: str, repo: str, timeout: int = 10) -> str:
    """Последний СТАБИЛЬНЫЙ release-тег GitHub-репо ('' при недоступности).

    Только tag_name последнего НЕ pre-release (как _resolve_install_version
    из dpi_bypass.py — pre-release не предлагаем, это ручной флоу).
    """
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
            headers={"User-Agent": "chimera-installer/5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        tag = str(data.get("tag_name", "") or "")
        return tag if tag and tag != "null" else ""
    except Exception as e:
        _log("WARN", f"github_latest_tag({owner}/{repo}): {e}")
        return ""


def github_latest_asset_url(owner: str, repo: str, asset_re: str,
                            timeout: int = 10) -> tuple:
    """(tag, asset_url) последнего стабильного release, где asset матчит
    asset_re. ('', '') при недоступности — caller откатывается на фолбэк-тег
    и прямой URL (зеркала добавит _release_mirror_urls)."""
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
            headers={"User-Agent": "chimera-installer/5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        if data.get("prerelease"):
            return ("", "")
        tag = str(data.get("tag_name", "") or "")
        rx = re.compile(asset_re)
        for a in data.get("assets", []) or []:
            if rx.search(str(a.get("name", ""))):
                return (tag, str(a.get("browser_download_url", "")))
    except Exception as e:
        _log("WARN", f"github_latest_asset_url({owner}/{repo}): {e}")
    return ("", "")


def _release_mirror_urls(owner: str, repo: str, tag: str, filename: str) -> list:
    """Зеркала для RELEASE-ассета: jsDelivr/raw/statically НЕ раздают
    release-файлы, поэтому оставляем только GitHub + gh-прокси
    (build_mirror_urls с выключенными неприменимыми семействами)."""
    return build_mirror_urls(
        owner=owner, repo=repo, filename=filename, tag=tag,
        jsdelivr_hosts=(), include_raw_github=False,
        include_release_github=True, include_statically=False,
    )


# ══════════════════════════════════════════════════════════════════════════
#  ЗАГРУЗКИ КОМПОНЕНТОВ (download_manager: PackageSpec, авто-latest)
# ══════════════════════════════════════════════════════════════════════════

def _xray_asset_name(arch: str) -> str:
    return {"x86_64": "Xray-linux-64.zip",
            "aarch64": "Xray-linux-arm64-v8a.zip"}.get(arch, "")


def _zip_post_install(dest: Path, tag: str) -> bool:
    """Общий post_install: /tmp/_download_mgr_xray.zip → unzip → dest."""
    src = Path("/tmp/_download_mgr_Xray.zip")
    try:
        with zipfile.ZipFile(src) as zf:
            member = [n for n in zf.namelist() if n.endswith("xray")]
            if not member:
                _err("В архиве Xray нет бинарника xray")
                return False
            with zf.open(member[0]) as fsrc, open(dest, "wb") as fdst:
                shutil.copyfileobj(fsrc, fdst)
        dest.chmod(0o755)
        _ok(f"xray {tag} → {dest}")
        return True
    except Exception as e:
        _err(f"Распаковка Xray не удалась: {e}")
        return False


def resolve_component_versions(arch: str = "",
                               net_probe: bool = True) -> dict:
    """Версии компонентов для УСТАНОВКИ (паттерн B4 _resolve_install_version):
    GitHub /releases/latest при живой сети, зашитый фолбэк при недоступности.
    Возвращает {'xray': tag, 'oxidns': tag, 'agh': tag}."""
    cpu = arch or os.uname().machine
    out = {"xray": XRAY_FALLBACK_TAG, "oxidns": OXIDNS_FALLBACK_TAG,
           "agh": AGH_FALLBACK_TAG}
    if net_probe:
        tag = github_latest_tag(*XRAY_REPO)
        if tag:
            out["xray"] = tag
        otag, _ = github_latest_asset_url(*OXIDNS_REPO, OXIDNS_ASSET_RE)
        if otag:
            out["oxidns"] = otag
        atag = github_latest_tag(*AGH_REPO)
        if atag:
            out["agh"] = atag
    if cpu != "x86_64":
        out["oxidns"] = ""      # oxidns — только x86_64 (официальные сборки)
    return out


def install_xray_binary(tag: str = "", arch: str = "") -> bool:
    """Скачивает xray через download_manager (зеркала + manual-incoming),
    распаковывает в /opt/smartdns/bin/xray. tag='' → фолбэк."""
    tag = tag or XRAY_FALLBACK_TAG
    cpu = arch or os.uname().machine
    asset = _xray_asset_name(cpu)
    if not asset:
        _err(f"Xray: неподдерживаемая архитектура {cpu}")
        return False
    _info(f"Скачиваю Xray-core {tag} ({asset}) — последний стабильный release…")

    def _urls(filename: str, **kw) -> list:
        return _release_mirror_urls(*XRAY_REPO, tag, asset)

    spec = PackageSpec(
        name=f"xray {tag}",
        filename_builder=lambda **kw: "Xray.zip",
        mirror_urls_builder=_urls,
        install_dests=[BIN_DIR],
        manual_incoming_dir=Path("/root"),
        min_size=5_000_000,
        post_install=lambda tmp, dests, _t=tag: _zip_post_install(XRAY_BIN, _t),
        checksum_urls=[f"https://github.com/{XRAY_REPO[0]}/{XRAY_REPO[1]}"
                       f"/releases/download/{tag}/{asset}.dgst"],
    )
    return fetch_package(spec, progress_label="[xray]")


def _tar_post_install(dest: Path, binary_name: str, label: str) -> bool:
    """Общий post_install tar.gz: /tmp/_download_mgr_<file> → tar → dest."""
    src = Path("/tmp/_download_mgr_smartdns-engine.tar.gz")
    try:
        with tarfile.open(src) as tf:
            member = [m for m in tf.getmembers()
                      if m.name.rstrip("/").split("/")[-1] == binary_name]
            if not member:
                _err(f"В архиве {label} нет бинарника {binary_name}")
                return False
            tf.extract(member[0], dest.parent)
            extracted = dest.parent / member[0].name
            shutil.move(str(extracted), dest)
        dest.chmod(0o755)
        _ok(f"{label} → {dest}")
        return True
    except Exception as e:
        _err(f"Распаковка {label} не удалась: {e}")
        return False


def install_oxidns_binary(tag: str = "") -> bool:
    """OxiDNS (Rust, только x86_64) через download_manager."""
    if os.uname().machine != "x86_64":
        _err("OxiDNS: официальные сборки только x86_64")
        return False
    tag = tag or OXIDNS_FALLBACK_TAG
    latest_tag, latest_url = github_latest_asset_url(*OXIDNS_REPO, OXIDNS_ASSET_RE)
    direct = latest_url if latest_url else (
        f"https://github.com/{OXIDNS_REPO[0]}/{OXIDNS_REPO[1]}"
        f"/releases/download/{tag}/oxidns-x86_64-unknown-linux-musl.tar.gz")
    _info(f"Скачиваю OxiDNS {latest_tag or tag} — последний стабильный release…")

    def _urls(filename: str, **kw) -> list:
        urls = _release_mirror_urls(*OXIDNS_REPO, latest_tag or tag,
                                    "oxidns-x86_64-unknown-linux-musl.tar.gz")
        if direct not in urls:
            urls.insert(0, direct)
        return urls

    spec = PackageSpec(
        name=f"oxidns {latest_tag or tag}",
        filename_builder=lambda **kw: "smartdns-engine.tar.gz",
        mirror_urls_builder=_urls,
        install_dests=[BIN_DIR],
        manual_incoming_dir=Path("/root"),
        min_size=1_000_000,
        post_install=lambda tmp, dests: _tar_post_install(OXIDNS_BIN, "oxidns", "OxiDNS"),
    )
    return fetch_package(spec, progress_label="[oxidns]")


def install_agh_binary(tag: str = "", arch: str = "") -> bool:
    """AdGuardHome через download_manager (все архитектуры)."""
    cpu = arch or os.uname().machine
    tag = tag or AGH_FALLBACK_TAG
    asset = {"x86_64": "AdGuardHome_linux_amd64.tar.gz",
             "aarch64": "AdGuardHome_linux_arm64.tar.gz",
             "armv7l": "AdGuardHome_linux_armv7.tar.gz"}.get(cpu, "")
    if not asset:
        _err(f"AdGuardHome: неподдерживаемая архитектура {cpu}")
        return False
    _info(f"Скачиваю AdGuardHome {tag} ({asset})…")

    def _urls(filename: str, **kw) -> list:
        return _release_mirror_urls(*AGH_REPO, tag, asset)

    spec = PackageSpec(
        name=f"AdGuardHome {tag}",
        filename_builder=lambda **kw: "smartdns-engine.tar.gz",
        mirror_urls_builder=_urls,
        install_dests=[BIN_DIR],
        manual_incoming_dir=Path("/root"),
        min_size=5_000_000,
        post_install=lambda tmp, dests: _tar_post_install(AGH_BIN, "AdGuardHome",
                                                          "AdGuardHome"),
    )
    return fetch_package(spec, progress_label="[agh]")


def install_binaries(cfg: dict) -> dict:
    """Ставит бинарники движка+xray согласно cfg['engine']. Возвращает
    фактически резолвнутые версии (для versions.json)."""
    versions = resolve_component_versions(net_probe=True)
    ok = install_xray_binary(versions["xray"])
    if not ok:
        return {}
    if cfg.get("engine") == "oxidns":
        ok = install_oxidns_binary(versions["oxidns"])
    else:
        ok = install_agh_binary(versions["agh"])
    if not ok:
        return {}
    return versions


def update_geosite(cfg: dict) -> bool:
    """Обновляет geosite.dat (Loyalsoldier, latest release) через
    download_manager; атомарная замена + рестарт движка."""
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    def _urls(filename: str, **kw) -> list:
        return _release_mirror_urls(*GEOSITE_REPO, "latest", "geosite.dat")

    spec = PackageSpec(
        name="geosite.dat",
        filename_builder=lambda **kw: "geosite.dat",
        mirror_urls_builder=_urls,
        install_dests=[ASSETS_DIR],
        manual_incoming_dir=Path("/root"),
        min_size=GEOSITE_MIN_SIZE,
    )
    ok = fetch_package(spec, progress_label="[geosite]")
    if ok and cfg.get("engine"):
        _restart_unit(_engine_unit(cfg), restart=True)
    return ok


def _engine_unit(cfg: dict) -> str:
    return UNIT_OXIDNS if cfg.get("engine") == "oxidns" else UNIT_AGH


# ══════════════════════════════════════════════════════════════════════════
#  СИСТЕМНЫЕ ПАКЕТЫ / ПОЛЬЗОВАТЕЛИ / КАТАЛОГИ
# ══════════════════════════════════════════════════════════════════════════

def install_system_packages(companion: bool = False) -> bool:
    """Базовые пакеты + nginx (nginx.org репо — ТОЛЬКО если nginx ещё не
    установлен; в companion-режиме живёт nginx Химеры — не трогаем)."""
    _info("Установка системных пакетов (curl, jq, ufw, ipset, dnsutils…)…")
    pkgs = ["curl", "ca-certificates", "gnupg2", "lsb-release", "jq", "ufw",
            "ipset", "conntrack", "dnsutils", "openssl", "tar", "unzip",
            "socat", "cron", "logrotate", "python3-bcrypt"]
    r = subprocess.run(["apt-get", "update", "-y", "-q"],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        _warn(f"apt-get update: {r.stderr.strip()[:200]}")
    r = subprocess.run(["apt-get", "install", "-y", "-q", *pkgs],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        _err(f"Не удалось установить пакеты: {r.stderr.strip()[:300]}")
        return False

    if shutil.which("nginx"):
        _ok("nginx уже установлен — репо/пакет не трогаем "
            "(companion: nginx Химеры; standalone: чужая установка)")
    else:
        _info("Установка nginx из официального репо nginx.org…")
        keyring = Path("/etc/apt/keyrings/nginx-archive-keyring.gpg")
        keyring.parent.mkdir(parents=True, exist_ok=True)
        if not keyring.exists():
            r = subprocess.run(
                "curl -fsSL https://nginx.org/keys/nginx_signing.key"
                " | gpg --dearmor -o /etc/apt/keyrings/nginx-archive-keyring.gpg",
                shell=True, capture_output=True, text=True, check=False)
            if r.returncode != 0:
                _err(f"Не удалось импортировать ключ nginx: {r.stderr[:200]}")
                return False
        codename = ""
        try:
            with open("/etc/os-release") as f:
                m = re.search(r"^VERSION_CODENAME=(\S+)", f.read(), re.M)
                codename = m.group(1).strip('"') if m else ""
        except Exception:
            pass
        distro = "debian" if Path("/etc/debian_version").exists() else "ubuntu"
        if not codename:
            _err("Не удалось определить коднейм ОС для репо nginx")
            return False
        Path("/etc/apt/sources.list.d/nginx-official.list").write_text(
            f"deb [signed-by={keyring}] http://nginx.org/packages/{distro} "
            f"{codename} nginx\n")
        Path("/etc/apt/preferences.d/99nginx-official").write_text(
            "Package: *\nPin: origin nginx.org\nPin: release o=nginx\n"
            "Pin-Priority: 900\n")
        subprocess.run(["apt-get", "update", "-y", "-q"],
                       capture_output=True, text=True, check=False)
        r = subprocess.run(["apt-get", "install", "-y", "-q", "nginx"],
                           capture_output=True, text=True, check=False)
        if r.returncode != 0:
            _err(f"Не удалось установить nginx: {r.stderr.strip()[:300]}")
            return False
    _ok("Системные пакеты готовы")
    return True


def setup_users_and_dirs(cfg: dict) -> bool:
    """Пользователи (smartdns/oxidns/adguard + ssl-smartdns) и дерево
    каталогов с правами. Идемпотентно; существующие пользователи не трогает."""
    dns_user = USER_OXIDNS if cfg.get("engine") == "oxidns" else USER_AGH

    def _ensure_user(name: str) -> None:
        if not subprocess.run(["getent", "group", name],
                              capture_output=True).returncode == 0:
            subprocess.run(["groupadd", "--system", name], check=False)
        if not subprocess.run(["id", "-u", name],
                              capture_output=True).returncode == 0:
            subprocess.run(["useradd", "--system", "--gid", name,
                            "--no-create-home", "--home-dir", "/nonexistent",
                            "--shell", "/usr/sbin/nologin", name], check=False)
        else:
            subprocess.run(["usermod", "--shell", "/usr/sbin/nologin",
                            "--home", "/nonexistent", name], check=False)

    _ensure_user(USER_XRAY)
    _ensure_user(dns_user)
    if not subprocess.run(["getent", "group", GRP_SSL],
                          capture_output=True).returncode == 0:
        subprocess.run(["groupadd", "--system", GRP_SSL], check=False)
    # Движок состоит в группе xray-пользователя (читает rules.d) и наоборот.
    subprocess.run(["usermod", "-aG", USER_XRAY, dns_user], check=False)
    subprocess.run(["usermod", "-aG", dns_user, USER_XRAY], check=False)
    if not subprocess.run(["id", "-u", "www-data"],
                          capture_output=True).returncode == 0:
        subprocess.run(["useradd", "--system", "--no-create-home",
                        "--shell", "/usr/sbin/nologin", "www-data"], check=False)
    subprocess.run(["usermod", "-aG", GRP_SSL, "www-data"], check=False)
    subprocess.run(["gpasswd", "-d", USER_XRAY, GRP_SSL],
                   capture_output=True, check=False)

    dirs = [
        (STATE_DIR, 0o700, "root", "root"),
        (BACKUP_ROOT, 0o700, "root", "root"),
        (CONF_ROOT, 0o755, "root", "root"),
        (XRAY_CONF_DIR, 0o750, "root", USER_XRAY),
        (XRAY_RULES_DIR, 0o750, USER_XRAY, USER_XRAY),
        (XRAY_LOG_DIR, 0o750, USER_XRAY, USER_XRAY),
        (LOG_DIR, 0o755, "root", "root"),
        (CERT_DIR, 0o750, "root", GRP_SSL),
        (WEB_ROOT, 0o755, "root", "root"),
        (ASSETS_DIR, 0o2750, dns_user, USER_XRAY),
        (BIN_DIR, 0o755, "root", "root"),
    ]
    for d, mode, owner, group in dirs:
        d.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(["chown", f"{owner}:{group}", str(d)], check=False)
            subprocess.run(["chmod", oct(mode)[2:], str(d)], check=False)
        except Exception:
            pass
    for f in (ASSETS_DIR / "custom-allow.txt", ASSETS_DIR / "custom-deny.txt"):
        f.touch(exist_ok=True)
    _ok("Пользователи и каталоги готовы")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  КОНФИГ XRAY (dokodemo 8444 stealth + 853 DoT; BIND_ADDR от режима)
# ══════════════════════════════════════════════════════════════════════════

def xray_bind_addr(cfg: dict) -> str:
    """Адрес публичных inbound'ов: companion → второй IP, standalone → все."""
    return str(cfg.get("bind_ip") or "0.0.0.0")


def build_xray_base_config(cfg: dict) -> dict:
    """00-base.json (паритет bash configure_xray_base + bind из режима)."""
    bind = xray_bind_addr(cfg)
    return {
        "log": {
            "access": str(XRAY_LOG_DIR / "access.log"),
            "error": str(XRAY_LOG_DIR / "error.log"),
            "loglevel": "info",
        },
        "dns": {
            "servers": ["https+local://1.1.1.1/dns-query",
                        "https+local://8.8.8.8/dns-query"],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [
            {
                "tag": "https-in",
                "listen": bind,
                "port": PORT_DOH,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1", "port": 443,
                             "network": "tcp", "followRedirect": False},
                "sniffing": {"enabled": True, "destOverride": ["tls"],
                             "routeOnly": False},
                "streamSettings": {"sockopt": {
                    "tcpKeepAliveInterval": 120, "tcpNoDelay": True}},
            },
            {
                "tag": "dot-in",
                "listen": bind,
                "port": PORT_DOT,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1", "port": PORT_DOTHERM,
                             "network": "tcp", "followRedirect": False},
                "sniffing": {"enabled": True, "destOverride": ["tls"],
                             "routeOnly": True},
                "streamSettings": {"sockopt": {
                    "tcpKeepAliveInterval": 60, "tcpNoDelay": True}},
            },
        ],
        "outbounds": [
            {"tag": "direct-v4", "protocol": "freedom",
             "settings": {"domainStrategy": "UseIPv4"},
             "streamSettings": {"sockopt": {"tcpKeepAliveInterval": 120}}},
            {"tag": "nginx-local", "protocol": "freedom",
             "settings": {"redirect": f"127.0.0.1:{PORT_STEALTH}",
                          "proxyProtocol": 1}},
            {"tag": "dot-backend", "protocol": "freedom",
             "settings": {"redirect": f"127.0.0.1:{PORT_DOTHERM}"}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
    }


def build_routing_rules(domain: str, dot_host: str, allowed_domains: list,
                        srv_ipv4: str, srv_ipv6: str = "") -> dict:
    """10-smartdns-routing.json (паритет jq-шаблона bash update-geohide):
    DoT: только DOT_HOST → терминатор, остальное block;
    DoH: наши домены → nginx-local, GeoHide-домены → direct-v4
    (движок уже зарезолвил их на SERVER_IP — клиент идёт на 443 этого
    сервера), локальные/private → block, всё прочее → cover-site."""
    ip_block = [srv_ipv4, "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                "::1/128", "fc00::/7", "fe80::/10"]
    if srv_ipv6 and srv_ipv6 not in ("", "::1"):
        ip_block.insert(1, srv_ipv6)
    return {
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["dot-in"],
                 "domain": [f"full:{dot_host}"], "outboundTag": "dot-backend"},
                {"type": "field", "inboundTag": ["dot-in"],
                 "port": "0-65535", "outboundTag": "block"},
                {"type": "field", "inboundTag": ["https-in"],
                 "domain": [f"full:{domain}", f"full:www.{domain}",
                            f"full:{dot_host}"],
                 "outboundTag": "nginx-local"},
                {"type": "field", "inboundTag": ["https-in"],
                 "domain": [f"domain:{d}" for d in allowed_domains],
                 "outboundTag": "direct-v4"},
                {"type": "field", "inboundTag": ["https-in"],
                 "ip": ip_block, "outboundTag": "block"},
                {"type": "field", "inboundTag": ["https-in"],
                 "port": "0-65535", "outboundTag": "nginx-local"},
            ],
        }
    }


def write_xray_config(cfg: dict) -> bool:
    """Пишет 00-base.json + симлинк routing-правил в conf.d (bash: rules.d —
    источник, conf.d/10-*.json — симлинк; safe-restart через validate)."""
    XRAY_LOG_DIR.mkdir(parents=True, exist_ok=True)
    for lf in ("access.log", "error.log"):
        p = XRAY_LOG_DIR / lf
        p.touch(exist_ok=True)
        try:
            subprocess.run(["chown", f"{USER_XRAY}:{USER_XRAY}", str(p)],
                           check=False)
            subprocess.run(["chmod", "640", str(p)], check=False)
        except Exception:
            pass
    base = build_xray_base_config(cfg)
    tmp = XRAY_CONF_DIR / "00-base.json.tmp"
    tmp.write_text(json.dumps(base, indent=2, ensure_ascii=False) + "\n")
    tmp.replace(XRAY_CONF_DIR / "00-base.json")
    _ok(f"Xray base-конфиг: {XRAY_CONF_DIR}/00-base.json "
        f"(listen {xray_bind_addr(cfg)})")
    return True


def link_routing_into_confdir() -> None:
    """Симлинк rules.d/10-smartdns-routing.json → conf.d/ (паритет bash)."""
    src = XRAY_RULES_DIR / "10-smartdns-routing.json"
    dst = XRAY_CONF_DIR / "10-smartdns-routing.json"
    if src.exists():
        if dst.is_symlink() or dst.exists():
            dst.unlink()
        dst.symlink_to(src)


def validate_xray_config() -> bool:
    """xray run -test (валидация confdir перед рестартом)."""
    r = subprocess.run([str(XRAY_BIN), "run", "-test", "-confdir",
                        str(XRAY_CONF_DIR)], capture_output=True, text=True,
                       check=False)
    return r.returncode == 0


# ══════════════════════════════════════════════════════════════════════════
#  GEOHIDE: парсинг hosts-списка → домены / hosts / AGH-правила (чистые)
# ══════════════════════════════════════════════════════════════════════════

def parse_geohide_hosts(text: str,
                        exclude_google_sys: bool = True,
                        include_xbox_ipify: bool = False,
                        custom_allow: str = "",
                        custom_deny: str = "") -> list:
    """hosts-файл GeoHideDNS → отсортированный список доменов.

    Полный паритет awk-конвейера bash: извлечение доменных имён,
    нормализация (*.foo → foo), валидация, безусловные исключения
    (captive-portal детекты, x.com/meta.ai), опциональные Google/Xbox,
    custom-allow/deny; generativelanguage.googleapis.com — всегда в списке.
    """
    domains = set()
    for raw in text.splitlines():
        line = raw.rstrip("\r").strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        candidates = []
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", fields[0]) or ":" in fields[0]:
            for f in fields[1:]:
                if f.startswith("#"):
                    break
                candidates.append(f.lower())
        else:
            candidates.append(fields[0].lower())
        for c in candidates:
            c = re.sub(r"^\*\.", "", c)
            c = re.sub(r"^\.", "", c)
            if _DOMAIN_RE.match(c):
                domains.add(c)

    if not exclude_google_sys:
        domains.update(_EXTRA_GOOGLE_DOMAINS)
    if include_xbox_ipify:
        domains.update(_EXTRA_XBOX_DOMAINS)
    for line in (custom_allow or "").splitlines():
        c = line.strip().lower()
        if c and _DOMAIN_RE.match(c):
            domains.add(c)

    def _excluded(d: str) -> bool:
        for rx in _ALWAYS_EXCLUDE_RE:
            if re.match(rx, d):
                return True
        if exclude_google_sys:
            for rx in _EXCLUDE_GOOGLE_RE:
                if re.match(rx, d):
                    return True
        if not include_xbox_ipify:
            for rx in _EXCLUDE_XBOX_RE:
                if re.match(rx, d):
                    return True
        return False

    domains = {d for d in domains if not _excluded(d)}
    domains.add("generativelanguage.googleapis.com")
    for line in (custom_deny or "").splitlines():
        d = line.strip().lower()
        domains.discard(d)
    return sorted(domains)


def render_engine_domain_lists(domains: list, srv_ipv4: str) -> dict:
    """Список доменов → артефакты движка (чистая функция):
    oxidns hosts-файл + AGH dnsrewrite-правила (паритет awk-рендеров bash)."""
    hosts_lines = [f"domain:{d} {srv_ipv4}" for d in domains]
    agh_lines = []
    for d in domains:
        agh_lines.append(f"||{d}^$dnstype=A,dnsrewrite=NOERROR;A;{srv_ipv4}")
        agh_lines.append(f"||{d}^$dnstype=AAAA,dnsrewrite=NOERROR")
        agh_lines.append(f"||{d}^$dnstype=HTTPS|SVCB,dnsrewrite=NOERROR")
    return {"hosts": "\n".join(hosts_lines) + "\n",
            "agh_rules": "\n".join(agh_lines) + "\n",
            "domains": "\n".join(domains) + "\n",
            "count": len(domains)}


def update_geohide(cfg: dict) -> bool:
    """Полный цикл GeoHide: скачать hosts → распарсить → сгенерировать
    routing.json + артефакты движка → валидация xray → атомарная замена."""
    _info("Обновление списка GeoHideDNS…")
    try:
        req = urllib.request.Request(
            GEOHIDE_HOSTS_URL_RAW,
            headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        _err(f"Не удалось скачать GeoHideDNS: {e}")
        return False
    domains = parse_geohide_hosts(
        text,
        exclude_google_sys=cfg.get("exclude_google_sys", True),
        include_xbox_ipify=cfg.get("include_xbox_ipify", False),
        custom_allow=_read_text(ASSETS_DIR / "custom-allow.txt"),
        custom_deny=_read_text(ASSETS_DIR / "custom-deny.txt"))
    if len(domains) < MIN_GE0HIDE_DOMAINS:
        _err(f"Список GeoHide подозрительно мал ({len(domains)}) — откат")
        return False
    arts = render_engine_domain_lists(domains, cfg["server_ipv4"])

    # routing.json во временный confdir → xray -test → атомарная замена
    routing = build_routing_rules(cfg["domain"], cfg["dot_host"], domains,
                                  cfg["server_ipv4"],
                                  cfg.get("server_ipv6", ""))
    with tempfile.TemporaryDirectory(prefix="smartdns-validate-") as td:
        test_dir = Path(td)
        shutil.copy(XRAY_CONF_DIR / "00-base.json", test_dir / "00-base.json")
        (test_dir / "10-smartdns-routing.json").write_text(
            json.dumps(routing, indent=2, ensure_ascii=False))
        r = subprocess.run([str(XRAY_BIN), "run", "-test", "-confdir",
                            str(test_dir)], capture_output=True, text=True,
                           check=False)
        if r.returncode != 0:
            _err("Сгенерированный routing.json не прошёл xray -test — откат")
            return False

    _atomic_write(ASSETS_DIR / "geohide-hosts.txt", arts["hosts"])
    _atomic_write(ASSETS_DIR / "ag-smartdns-rules.txt", arts["agh_rules"])
    _atomic_write(ASSETS_DIR / "geohide-domains.txt", arts["domains"])
    routing_path = XRAY_RULES_DIR / "10-smartdns-routing.json"
    _atomic_write(routing_path,
                  json.dumps(routing, indent=2, ensure_ascii=False) + "\n")
    link_routing_into_confdir()
    if cfg.get("engine"):
        _restart_unit(_engine_unit(cfg), restart=True)
    _ok(f"GeoHide: {arts['count']} доменов, routing.json применён")
    return True


def _read_text(p: Path) -> str:
    try:
        return p.read_text()
    except Exception:
        return ""


def _atomic_write(p: Path, content: str, mode: int = 0o640) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(content)
    try:
        os.chmod(tmp, mode)
    except Exception:
        pass
    tmp.replace(p)


# ══════════════════════════════════════════════════════════════════════════
#  КОНФИГИ DNS-ДВИЖКОВ (oxidns / AdGuardHome — loopback 5353/8053)
# ══════════════════════════════════════════════════════════════════════════

def render_oxidns_config() -> str:
    """config.yaml OxiDNS (паритет bash; все листенеры loopback)."""
    return """log:
  level: info

plugins:
  - tag: ads_domains
    type: geosite
    args:
      file: "%(geosite)s"
      selectors:
        - "category-ads-all"

  - tag: proxied_sites
    type: domain_set
    args:
      files:
        - "%(geohide_domains)s"

  - tag: smart_a
    type: hosts
    args:
      files:
        - "%(geohide_hosts)s"

  - tag: cache
    type: cache
    args:
      size: 4096
      short_circuit: true
      cache_negative: true

  - tag: upstream_doh
    type: forward
    args:
      upstreams:
        - addr: "https://1.1.1.1/dns-query"
        - addr: "https://8.8.8.8/dns-query"

  - tag: main
    type: sequence
    args:
      - matches: "qname $ads_domains"
        exec: "reject 3"
      - matches:
          - "qname $proxied_sites"
          - "qtype 64 65"
        exec: "reject 5"
      - matches:
          - "qname $proxied_sites"
          - "qtype 1 28"
        exec: "$smart_a"
      - matches: "has_resp"
        exec: "accept"
      - exec: "$cache"
      - matches: "!has_resp"
        exec: "$upstream_doh"

  - tag: udp_local
    type: udp_server
    args:
      entry: "main"
      listen: "127.0.0.1:%(engine_port)d"

  - tag: tcp_local
    type: tcp_server
    args:
      entry: "main"
      listen: "127.0.0.1:%(engine_port)d"

  - tag: doh_local
    type: http_server
    args:
      listen: "127.0.0.1:%(dohloc_port)d"
      entries:
        - path: "/dns-query"
          exec: "main"
""" % {"geosite": GEOSITE_DAT, "geohide_domains": ASSETS_DIR / "geohide-domains.txt",
       "geohide_hosts": ASSETS_DIR / "geohide-hosts.txt",
       "engine_port": PORT_ENGINE, "dohloc_port": PORT_DOHLOC}


def render_agh_config(admin_user: str, password_hash: str,
                      domain: str) -> str:
    """AdGuardHome.yaml (паритет bash; web+dns на loopback, DoT/DoH TLS off —
    TLS терминирует nginx/xray стека)."""
    return """http:
  address: 127.0.0.1:%(dohloc_port)d
  session_ttl: 720h
users:
  - name: "%(user)s"
    password: "%(pass)s"
dns:
  bind_hosts:
    - 127.0.0.1
  port: %(engine_port)d
  upstream_dns:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  cache_size: 4194304
  ratelimit: 0
  refuse_any: true
  serve_plain_dns: true
tls:
  enabled: false
  server_name: "%(domain)s"
  port_https: 0
  port_dns_over_tls: 0
  allow_unencrypted_doh: true
filtering:
  protection_enabled: true
  filtering_enabled: true
  filters_update_interval: 24
  safe_fs_patterns:
    - %(assets)s/*
    - /var/lib/smartdns-adguardhome/*
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: %(agh_rules)s
    name: GeoHide SmartDNS Rules
    id: 2
schema_version: 29
""" % {"dohloc_port": PORT_DOHLOC, "engine_port": PORT_ENGINE,
       "user": admin_user, "pass": password_hash,
       "domain": domain, "assets": ASSETS_DIR,
       "agh_rules": ASSETS_DIR / "ag-smartdns-rules.txt"}


def agh_password_hash(password: str) -> str:
    """bcrypt-хэш пароля панели AGH (python3-bcrypt; фолбэк htpasswd -B)."""
    try:
        import bcrypt  # type: ignore
        return bcrypt.hashpw(password.encode(),
                             bcrypt.gensalt(rounds=10)).decode()
    except ImportError:
        r = subprocess.run(["htpasswd", "-nbB", "", password],
                           capture_output=True, text=True, check=False)
        if r.returncode == 0 and ":" in r.stdout:
            return r.stdout.rstrip("\n").split(":", 1)[1]
    raise RuntimeError("Нет bcrypt/htpasswd для хэша пароля AGH")


def write_engine_config(cfg: dict) -> bool:
    """Пишет конфиг активного движка (oxidns | adguardhome)."""
    if cfg.get("engine") == "oxidns":
        OXIDNS_CONF_DIR.mkdir(parents=True, exist_ok=True)
        _atomic_write(OXIDNS_CONF_DIR / "config.yaml", render_oxidns_config())
        _ok(f"Конфиг OxiDNS: {OXIDNS_CONF_DIR}/config.yaml")
    else:
        AGH_CONF_DIR.mkdir(parents=True, exist_ok=True)
        admin_user = cfg.get("agh_admin_user") or (
            "admin_" + _random_lower(6))
        password = cfg.get("agh_admin_pass") or _random_alnum(24)
        cfg["agh_admin_user"] = admin_user
        cfg["agh_admin_pass"] = password
        _atomic_write(AGH_CONF_DIR / "AdGuardHome.yaml",
                      render_agh_config(admin_user,
                                        agh_password_hash(password),
                                        cfg["domain"]))
        _ok(f"Конфиг AdGuardHome: {AGH_CONF_DIR}/AdGuardHome.yaml")
    return True


def _random_alnum(n: int) -> str:
    return "".join(_pysecrets.choice(string.ascii_letters + string.digits)
                   for _ in range(n))


def _random_lower(n: int) -> str:
    return "".join(_pysecrets.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))


# ══════════════════════════════════════════════════════════════════════════
#  PROCEDURAL COVER SITE (компактный Python-генератор; паритет по духу
#  bash-генератора: уникальный «студийный» сайт-визитка на каждый инсталл)
# ══════════════════════════════════════════════════════════════════════════

_BRAND_HEADS = ["Nord", "Fjord", "Bergen", "Aurora", "Polar", "Viking",
                "Frost", "Storm", "Baltic", "Arctic", "Mist", "Cobalt"]
_BRAND_TAILS = ["Studio", "Labs", "Works", "Design", "Architecture",
                "Atelier", "Collective", "Systems", "Craft", "Partners"]
_COVER_TITLES = [
    ("Architecture & Spatial Design",
     "We shape environments where light, material and structure converge."),
    ("Digital Product Studio",
     "Interfaces engineered with restraint — from first sketch to shipped."),
    ("Nordic Engineering Collective",
     "Systems thinking for buildings, products and everything between."),
    ("Photography & Visual Research",
     "Documenting structures, landscapes and the space in between."),
]
_PALETTES = [
    ("#0f172a", "#e2e8f0", "#94a3b8", "#38bdf8"),
    ("#111827", "#f3f4f6", "#9ca3af", "#f59e0b"),
    ("#14202e", "#e5e9ee", "#8b98a5", "#34d399"),
    ("#1c1917", "#f5f5f4", "#a8a29e", "#fb7185"),
    ("#12211d", "#e8f0ec", "#93a8a0", "#a3e635"),
]


def generate_cover_site(cfg: dict, seed: int = 0) -> Path:
    """Генерирует уникальный cover-site в WEB_ROOT. seed=0 → случайный;
    фиксированный seed → воспроизводимо (тесты). Возвращает путь index.html."""
    rng = random.Random(seed if seed else None)
    brand = (rng.choice(_BRAND_HEADS) + " " + rng.choice(_BRAND_TAILS))
    title, tagline = rng.choice(_COVER_TITLES)
    dark, light, muted, accent = rng.choice(_PALETTES)
    hero_align = rng.choice(["left", "center"])
    grid_cols = rng.choice(["2", "3"])
    year = rng.choice(["2024", "2025", "2026"])
    WEB_ROOT.mkdir(parents=True, exist_ok=True)
    (WEB_ROOT / "assets").mkdir(parents=True, exist_ok=True)

    projects = []
    for i in range(1, rng.randint(4, 7)):
        projects.append(
            f'<article class="work"><h3>Project {rng.randint(10, 99)}'
            f'/{rng.choice(["A", "B", "C", "D"])}</h3>'
            f"<p>{rng.choice(['Residential', 'Commercial', 'Research', 'Public', 'Private'])} "
            f"· {rng.choice(['Oslo', 'Bergen', 'Malmo', 'Helsinki', 'Tallinn'])} "
            f"· {rng.randint(200, 2600)} m²</p></article>")
    works = "\n            ".join(projects)

    css = f""":root {{
  --bg: {dark}; --fg: {light}; --muted: {muted}; --accent: {accent};
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font: 16px/1.65 Georgia, 'Times New Roman', serif;
  background: var(--bg); color: var(--fg);
}}
header {{
  border-bottom: 1px solid color-mix(in srgb, var(--fg) 12%, transparent);
}}
.nav {{ display: flex; justify-content: space-between; align-items: center;
  max-width: 1080px; margin: 0 auto; padding: 22px 24px; }}
.brand {{ font-size: 19px; letter-spacing: .12em; text-transform: uppercase; }}
.brand a {{ color: var(--fg); text-decoration: none; }}
nav a {{ color: var(--muted); text-decoration: none; margin-left: 26px;
  font-size: 14px; letter-spacing: .05em; }}
nav a:hover {{ color: var(--accent); }}
.hero {{ text-align: {hero_align}; padding: 110px 24px 96px; }}
.hero h1 {{ font-size: clamp(30px, 5vw, 52px); font-weight: 400;
  letter-spacing: .01em; max-width: 780px; margin: 0 auto 18px; }}
.hero h1 em {{ color: var(--accent); font-style: italic; }}
.hero p {{ color: var(--muted); max-width: 560px; margin: {('0 auto' if hero_align == 'center' else '0')}; }}
.section {{ max-width: 1080px; margin: 0 auto; padding: 56px 24px; }}
.section h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .22em;
  color: var(--muted); margin-bottom: 26px; }}
.grid {{ display: grid; grid-template-columns: repeat({grid_cols}, 1fr); gap: 18px; }}
.work {{ border: 1px solid color-mix(in srgb, var(--fg) 10%, transparent);
  padding: 22px; }}
.work h3 {{ font-weight: 400; font-size: 18px; margin-bottom: 8px; }}
.work p {{ color: var(--muted); font-size: 14px; }}
.btn {{ display: inline-block; margin-top: 30px; padding: 12px 26px;
  border: 1px solid var(--accent); color: var(--accent);
  text-decoration: none; letter-spacing: .08em; font-size: 14px; }}
.btn:hover {{ background: var(--accent); color: var(--bg); }}
footer {{ border-top: 1px solid color-mix(in srgb, var(--fg) 12%, transparent);
  color: var(--muted); font-size: 13px; text-align: center; padding: 28px 24px; }}
"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{brand} — {title}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<header>
    <div class="nav">
        <a href="/" class="brand">{brand}</a>
        <nav>
            <a href="#work">Work</a>
            <a href="#studio">Studio</a>
            <a href="#contact">Contact</a>
        </nav>
    </div>
</header>
<section class="hero">
    <h1>{title.split(' & ')[0]} <em>&amp;</em> {title.split(' & ')[-1]}</h1>
    <p>{tagline}</p>
    <a class="btn" href="#contact">Get in touch</a>
</section>
<section class="section" id="work">
    <h2>Selected work</h2>
    <div class="grid">
            {works}
    </div>
</section>
<section class="section" id="studio">
    <h2>Studio</h2>
    <div class="work"><p>{brand} is an independent practice founded in {year}.
    We work across disciplines — research, design and engineering — with a
    focus on long-lived, honest solutions. Every engagement starts with the
    site, the brief and the people.</p></div>
</section>
<section class="section" id="contact">
    <h2>Contact</h2>
    <div class="work"><p>hello@{cfg['domain'].lower()}<br>
    By appointment only.</p></div>
</section>
<footer>&copy; {year} {brand}. All rights reserved.</footer>
</body>
</html>
"""
    (WEB_ROOT / "assets" / "style.css").write_text(css)
    (WEB_ROOT / "index.html").write_text(html)
    (WEB_ROOT / "404.html").write_text(
        html.replace("<title>", "<title>404 — ").replace(
            'class="hero"', 'class="hero" data-404="1"'))
    (WEB_ROOT / "favicon.svg").write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        f'<rect width="32" height="32" fill="{dark}"/>'
        f'<circle cx="16" cy="16" r="7" fill="{accent}"/></svg>\n')
    _ok(f"Cover site «{brand}» сгенерирован: {WEB_ROOT}")
    return WEB_ROOT / "index.html"


# ══════════════════════════════════════════════════════════════════════════
#  NGINX: cover-site + DoH endpoint + web-auth (full | drop-in)
# ══════════════════════════════════════════════════════════════════════════

def _nginx_http_directives() -> str:
    """http-уровень: лог-форматы/лимиты/мапы (неймспейс smartdns_, чтобы
    никогда не конфликтовать с http-контекстом nginx Химеры)."""
    return """    # {marker}
    log_format smartdns_doh_fmt '$time_iso8601|$remote_addr|$status|$upstream_status|$upstream_http_content_type|$bytes_sent';
    log_format smartdns_web_fmt '$time_iso8601|$remote_addr|$status|200|web-auth-verified|$bytes_sent';
    access_log /var/log/nginx/smartdns-access.log smartdns_doh_fmt;

    limit_req_zone $binary_remote_addr zone=smartdns_doh:10m rate=200r/s;
    limit_req_zone $binary_remote_addr zone=smartdns_web:10m rate=30r/s;

    map "$request_method:$arg_dns" $smartdns_doh_get_ok {{
        "~^GET:[A-Za-z0-9_=-]{{12,2048}}$" 1;
        default 0;
    }}
    map "$request_method:$content_type" $smartdns_doh_post_ok {{
        "~*^POST:application/dns-message" 1;
        default 0;
    }}
    map "$smartdns_doh_get_ok:$smartdns_doh_post_ok" $smartdns_doh_req_valid {{
        "1:0" 1;
        "0:1" 1;
        default 0;
    }}
    map "$request_method" $smartdns_web_auth_ok {{
        GET 1;
        HEAD 1;
        default 0;
    }}
    map "$status:$upstream_status:$upstream_http_content_type" $smartdns_doh_verified {{
        "200:200:application/dns-message" 1;
        default 0;
    }}
""".format(marker=NGINX_MARKER)


def _nginx_server_blocks(cfg: dict, dropin: bool) -> str:
    """server-блоки. Публичные листенеры:
      full   → 0.0.0.0:80/9443 (+default_server) — наш nginx целиком;
      dropin → строго <bind_ip>:80/9443 БЕЗ default_server (соседство с
               серверами Химеры в одном процессе; wildcard+specific bind
               ядро разрешает, specific-сокет забирает свой адрес)."""
    b = str(cfg.get("bind_ip") or "")
    l80 = f"{b}:80" if (dropin and b) else "80 default_server"
    l80v6 = (f"[::]:80 default_server" if not dropin else "")
    l9443 = f"{b}:9443 ssl" if (dropin and b) else "9443 ssl default_server"
    listen80 = f"        listen {l80};"
    if l80v6 and not (dropin and b):
        listen80 += f"\n        listen {l80v6};"
    auth_page = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
        "<title>Session Active</title>"
        '<link rel="stylesheet" href="/assets/style.css"></head><body>'
        '<header><div class="nav"><a href="/" class="brand">Client Portal</a>'
        "</div></header><section class=\"section\"><div class=\"work\">"
        "<h3>Session Synchronized</h3><p>Network endpoint "
        "<strong>$remote_addr</strong> is verified for active workspace "
        "access (24h lease).</p></div></section>"
        "<footer>&copy; 2026. All rights reserved.</footer></body></html>")
    return """    # ── HTTP → HTTPS redirect (cover + ACME-friendly) ────────────────────
    server {{
{listen80}
        server_name _;

        location ~ ^/(generate_204|gen_204)$ {{
            return 204;
        }}
        location / {{
            return 301 https://$host$request_uri;
        }}
    }}

    # ── Unified Stealth Server: cover site + DoH + web-auth ─────────────
    server {{
        listen {l9443};
        listen 127.0.0.1:{stealth} ssl proxy_protocol;
        http2 on;
        server_name {domain} www.{domain} {dot_host} _;

        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;

        ssl_certificate {cert}/fullchain.pem;
        ssl_certificate_key {cert}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Robots-Tag "noindex, nofollow" always;

        root {webroot};
        index index.html;
        error_page 404 /404.html;
        location = /404.html {{ internal; }}

        # Secret browser-bookmark endpoint (one-tap Wi-Fi IP authorization)
        location = /auth/{doh_path} {{
            limit_req zone=smartdns_web burst=15 nodelay;
            if ($smartdns_web_auth_ok = 0) {{ return 404; }}
            default_type text/html;
            charset utf-8;
            add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
            add_header Pragma "no-cache" always;
            add_header X-Robots-Tag "noindex, nofollow" always;
            access_log /var/log/nginx/smartdns-auth.log smartdns_web_fmt;
            return 200 '{auth_page}';
        }}

        # Secret DoH endpoint disguised inside root domain
        location = /resolve/{doh_path} {{
            limit_req zone=smartdns_doh burst=300 nodelay;
            if ($smartdns_doh_req_valid = 0) {{ return 404; }}
            proxy_http_version 1.1;
            proxy_request_buffering on;
            proxy_buffering on;
            proxy_set_header Host $host;
            proxy_set_header Connection "";
            proxy_hide_header Server;
            proxy_hide_header X-Powered-By;
            proxy_pass http://127.0.0.1:{dohloc}/dns-query;
            access_log /var/log/nginx/smartdns-auth.log smartdns_doh_fmt if=$smartdns_doh_verified;
        }}

        location / {{
            limit_req zone=smartdns_web burst=40 nodelay;
            try_files $uri $uri/ =404;
        }}
    }}
""".format(listen80=listen80, l9443=l9443, stealth=PORT_STEALTH,
           domain=cfg["domain"], dot_host=cfg["dot_host"], cert=CERT_DIR,
           webroot=WEB_ROOT, doh_path=cfg["doh_path"], dohloc=PORT_DOHLOC,
           auth_page=auth_page)


def _nginx_stream_block() -> str:
    """stream-сервер DoT-терминатора (loopback 8853 → движок 5353)."""
    return """# {marker}
# Internal DoT TLS terminator (SNI-verified stream from Xray dot-in)
server {{
    listen 127.0.0.1:{dotterm} ssl;
    ssl_certificate {cert}/fullchain.pem;
    ssl_certificate_key {cert}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_handshake_timeout 10s;
    proxy_pass 127.0.0.1:{engine};
    proxy_timeout 30s;
    proxy_connect_timeout 5s;
    access_log /var/log/nginx/smartdns-dot.log '$time_iso8601|$remote_addr|$protocol|$status|$bytes_sent|$bytes_received';
}}
""".format(marker=NGINX_MARKER, dotterm=PORT_DOTHERM, cert=CERT_DIR,
           engine=PORT_ENGINE)


def ensure_stream_include(nginx_conf_text: str) -> "tuple[str, bool]":
    """Идемпотентный stream-include-хук (зеркало singbox_nginx._nginx_ensure_
    stream_include): если stream{} есть без include — вставить include;
    если stream{} нет — добавить блок в конец. Возвращает (new_text, changed).

    ВАЖНО: правим ТОЛЬКО stream-блок; http/user/events — не трогаем.
    """
    if "stream-conf.d" in nginx_conf_text:
        return nginx_conf_text, False
    include_line = "    include /etc/nginx/stream-conf.d/*.conf;"
    if re.search(r"^\s*stream\s*\{", nginx_conf_text, re.M):
        # stream { ... } есть → вставить include сразу после открывающей
        def _inject(m):
            return m.group(0) + "\n" + include_line
        new = re.sub(r"^\s*stream\s*\{", _inject, nginx_conf_text, count=1,
                     flags=re.M)
        return new, (new != nginx_conf_text)
    # stream{} нет → добавить в конец (top-level)
    new = nginx_conf_text.rstrip("\n") + (
        f"\n\n# {NGINX_MARKER}\nstream {{\n{include_line}\n}}\n")
    return new, True


def apply_nginx(cfg: dict) -> "tuple[bool, str]":
    """Конфигурирует nginx. Режимы:
      full    — standalone на чистой машине (nginx не занят): пишем
                /etc/nginx/nginx.conf целиком (наш маркер в шапке);
      drop-in — companion (nginx Химеры) ЛИБО standalone с чужим nginx:
                conf.d/smartdns.conf + stream-conf.d/smartdns-dot.conf,
                основной nginx.conf не трогаем (кроме stream-include-хука).
    Гейт: nginx -t; провал → откат наших файлов, (False, причина)."""
    conf_path = Path("/etc/nginx/nginx.conf")
    existing = _read_text(conf_path) if conf_path.exists() else ""
    ours_full = existing.startswith(NGINX_MARKER) or (
        NGINX_MARKER in existing and "stream-conf.d" in existing)

    dropin_mode = (cfg.get("mode") == "companion") or bool(
        existing and not ours_full)

    if not dropin_mode:
        # ── FULL: наш nginx целиком (standalone, чистый/наш conf) ────────
        conf = f"""{NGINX_MARKER}
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {{
    worker_connections 2048;
    multi_accept on;
}}

stream {{
{stream_inc}
{stream_srv}}}
http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    error_log /var/log/nginx/error.log warn;

{directives}
{servers}}}
""".format(stream_inc="    include /etc/nginx/stream-conf.d/*.conf;\n",
           stream_srv=_nginx_stream_block(),
           directives=_nginx_http_directives(),
           servers=_nginx_server_blocks(cfg, dropin=False))
        backup = _backup_file(conf_path)
        conf_path.write_text(conf)
        ok, err = _nginx_test()
        if not ok:
            if backup and backup.exists():
                shutil.copy2(backup, conf_path)
            return False, f"nginx -t провал (full): {err}"
        _ok(f"nginx: полный конфиг ({conf_path}, бэкап: {backup})")
    else:
        # ── DROP-IN: соседство с nginx Химеры/чужим ───────────────────────
        NGINX_STREAM_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
        Path("/etc/nginx/conf.d").mkdir(parents=True, exist_ok=True)
        dropin = (f"{_nginx_http_directives()}\n"
                  + _nginx_server_blocks(cfg, dropin=True))
        backup_http = _backup_file(NGINX_HTTP_DROPIN)
        NGINX_HTTP_DROPIN.write_text(dropin)
        backup_stream = _backup_file(NGINX_STREAM_DROPIN)
        NGINX_STREAM_DROPIN.write_text(_nginx_stream_block())

        if existing and "stream-conf.d" not in existing:
            new_main, changed = ensure_stream_include(existing)
            if changed:
                _backup_file(conf_path)
                conf_path.write_text(new_main)
        ok, err = _nginx_test()
        if not ok:
            for p, b in ((NGINX_HTTP_DROPIN, backup_http),
                         (NGINX_STREAM_DROPIN, backup_stream)):
                if b and b.exists():
                    shutil.copy2(b, p)
                else:
                    p.unlink(missing_ok=True)
            return False, f"nginx -t провал (drop-in): {err}"
        _ok(f"nginx: drop-in режим ({NGINX_HTTP_DROPIN} + "
            f"{NGINX_STREAM_DROPIN}) — основной конфиг не тронут")

    _reload_nginx()
    return True, "ok"


def _nginx_test() -> "tuple[bool, str]":
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True,
                       check=False)
    return (r.returncode == 0, (r.stderr or r.stdout).strip()[:400])


def _reload_nginx() -> None:
    """reload (не restart): в companion-режиме nginx Химеры продолжает
    обслуживать свои vhost'ы без разрыва соединений."""
    subprocess.run(["systemctl", "reload", "nginx"],
                   capture_output=True, check=False)


def _backup_file(p: Path) -> "Optional[Path]":
    """Бэкап рядом с файлом: <name>.smartdns-bak-<ts> (для отката)."""
    if not p.exists():
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    bak = p.with_name(p.name + f".smartdns-bak-{ts}")
    shutil.copy2(p, bak)
    return bak


def remove_nginx_dropins() -> None:
    """Удаление drop-in'ов + nginx -t + reload (uninstall companion/чужой)."""
    changed = False
    for p in (NGINX_HTTP_DROPIN, NGINX_STREAM_DROPIN):
        if p.exists():
            p.unlink()
            changed = True
    if changed:
        ok, _ = _nginx_test()
        if ok:
            _reload_nginx()
        else:
            _warn("nginx -t провал после удаления drop-in'ов — проверьте "
                  "конфиг вручную (nginx -t)")


# ══════════════════════════════════════════════════════════════════════════
#  CLOUDFLARE DNS SYNC + WILDCERT (ACME DNS-01, паритет bash)
# ══════════════════════════════════════════════════════════════════════════

def _cf_api(path: str, token: str, method: str = "GET",
            payload: "Optional[dict]" = None, timeout: int = 15) -> dict:
    url = f"https://api.cloudflare.com/client/v4{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"success": False, "errors": [{"message": str(e)}]}
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}


def sync_cloudflare_records(cfg: dict, new_ipv4: str,
                            new_ipv6: str = "") -> bool:
    """A/AAAA → BIND_IP-адрес стека (companion: второй IP; standalone:
    основной IP). Паритет upsert/delete-логики bash."""
    token = cfg.get("cf_api_token") or ""
    if not token or token == "REUSE_EXISTING_CERT_TOKEN":
        _warn("CF_API_TOKEN не задан — A/AAAA записи не синхронизированы")
        return False
    domain = cfg["domain"]
    dot_host = cfg["dot_host"]
    zr = _cf_api(f"/zones?name={domain}&status=active", token)
    zone_id = ""
    for z in (zr.get("result") or []):
        zone_id = z.get("id", "")
        break
    if not zone_id:
        _err(f"Cloudflare-зона {domain} не найдена (проверьте токен)")
        return False

    def _upsert(rec_type: str, rec_name: str, content: str,
                create_if_missing: bool) -> None:
        sr = _cf_api(f"/zones/{zone_id}/dns_records?type={rec_type}"
                     f"&name={rec_name}", token)
        rec_id = ""
        for r in (sr.get("result") or []):
            rec_id = r.get("id", "")
            break
        payload = {"type": rec_type, "name": rec_name, "content": content,
                   "ttl": 120, "proxied": False}
        if rec_id:
            rr = _cf_api(f"/zones/{zone_id}/dns_records/{rec_id}", token,
                         method="PUT", payload=payload)
        elif create_if_missing:
            rr = _cf_api(f"/zones/{zone_id}/dns_records", token,
                         method="POST", payload=payload)
        else:
            return
        if rr.get("success"):
            _ok(f"CF {rec_type} {rec_name} → {content}")
        else:
            _warn(f"CF {rec_type} {rec_name}: {rr.get('errors')}")

    def _delete(rec_type: str, rec_name: str) -> None:
        sr = _cf_api(f"/zones/{zone_id}/dns_records?type={rec_type}"
                     f"&name={rec_name}", token)
        for r in (sr.get("result") or []):
            _cf_api(f"/zones/{zone_id}/dns_records/{r.get('id')}", token,
                    method="DELETE")
            _ok(f"CF {rec_type} {rec_name}: удалена устаревшая запись")

    _upsert("A", domain, new_ipv4, True)
    _upsert("A", f"*.{domain}", new_ipv4, True)
    _upsert("A", dot_host, new_ipv4, False)
    if new_ipv6:
        _upsert("AAAA", domain, new_ipv6, False)
        _upsert("AAAA", f"*.{domain}", new_ipv6, False)
        _upsert("AAAA", dot_host, new_ipv6, False)
    else:
        _delete("AAAA", domain)
        _delete("AAAA", f"*.{domain}")
        _delete("AAAA", dot_host)
    return True


def verify_tls_keys(cert: Path, key: Path, domain: str) -> bool:
    """Криптографическая проверка пары cert/key + SAN + срок (паритет bash
    verify-tls-keys.sh: pubkey DER SHA-256, SAN строго 2, >24ч до конца)."""
    if not cert.exists() or not key.exists():
        return False

    def _run(*args: str) -> str:
        return subprocess.run(args, capture_output=True, text=True,
                              check=False).stdout

    cert_pub = _run("sh", "-c",
                    f"openssl x509 -in {cert} -pubkey -noout 2>/dev/null"
                    f" | openssl pkey -pubin -outform DER 2>/dev/null"
                    f" | sha256sum")
    key_pub = _run("sh", "-c",
                   f"openssl pkey -in {key} -pubout -outform DER 2>/dev/null"
                   f" | sha256sum")
    ch = cert_pub.split()[0] if cert_pub else ""
    kh = key_pub.split()[0] if key_pub else ""
    if not ch or ch != kh:
        return False
    r = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout",
                        "-checkend", "86400"], capture_output=True, check=False)
    if r.returncode != 0:
        return False
    san = _run("openssl", "x509", "-in", str(cert), "-noout",
               "-ext", "subjectAltName")
    if (f"DNS:{domain}" not in san or f"DNS:*.{domain}" not in san
            or san.count("DNS:") != 2):
        return False
    return True


def issue_wildcard_certificate(cfg: dict) -> bool:
    """Wildcard LE-сертификат через acme.sh (DNS-01 dns_cf). Переиспользует
    валидный существующий; ставит acme.sh при отсутствии (паритет bash)."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    fullchain = CERT_DIR / "fullchain.pem"
    privkey = CERT_DIR / "privkey.pem"
    domain = cfg["domain"]

    if verify_tls_keys(fullchain, privkey, domain):
        _ok(f"Сертификат валиден: {CERT_DIR}")
        return True

    acme_dir = Path("/root/.acme.sh")
    acme = acme_dir / "acme.sh"
    if not acme.exists():
        _info("Установка acme.sh…")
        with tempfile.TemporaryDirectory(prefix="acme-") as td:
            tdp = Path(td)
            try:
                req = urllib.request.Request(
                    "https://github.com/acmesh-official/acme.sh/archive/"
                    "refs/heads/master.tar.gz")
                with urllib.request.urlopen(req, timeout=60) as resp, \
                        open(tdp / "acme.tar.gz", "wb") as f:
                    shutil.copyfileobj(resp, f)
                with tarfile.open(tdp / "acme.tar.gz") as tf:
                    tf.extractall(tdp)
                src_dir = next(d for d in tdp.iterdir() if d.is_dir())
                subprocess.run(
                    [str(src_dir / "acme.sh"), "--install",
                     "--home", str(acme_dir),
                     "--accountemail", cfg.get("acme_email") or
                     f"admin@{domain}", "--nocron"],
                    capture_output=True, check=False)
            except Exception as e:
                _err(f"Не удалось установить acme.sh: {e}")
                return False

    env = dict(os.environ)
    env["CF_Token"] = cfg["cf_api_token"]
    log_cert = LOG_DIR / "certificate.log"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _info(f"Выпуск wildcard-сертификата {domain} + *.{domain} (DNS-01)…")
    r = subprocess.run(
        [str(acme), "--home", str(acme_dir), "--issue", "--dns", "dns_cf",
         "-d", domain, "-d", f"*.{domain}", "--keylength", "ec-256"],
        env=env, capture_output=True, text=True, check=False)
    with open(log_cert, "a") as f:
        f.write(r.stdout + "\n" + r.stderr + "\n")
    if r.returncode != 0:
        _err("acme.sh не выпустил сертификат (см. "
             f"{log_cert}); проверьте CF_API_TOKEN/зону")
        return False

    with tempfile.TemporaryDirectory(prefix="cert-stage-") as td:
        stage = Path(td)
        r = subprocess.run(
            [str(acme), "--home", str(acme_dir), "--install-cert",
             "-d", domain, "--ecc",
             "--fullchain-file", str(stage / "fullchain.pem"),
             "--key-file", str(stage / "privkey.pem")],
            capture_output=True, check=False)
        if r.returncode != 0 or not verify_tls_keys(
                stage / "fullchain.pem", stage / "privkey.pem", domain):
            _err("Свежевыпущенный сертификат не прошёл верификацию")
            return False
        for name, mode in (("fullchain.pem", 0o644), ("privkey.pem", 0o640)):
            src = stage / name
            dst = CERT_DIR / name
            shutil.copy2(src, dst)
            os.chmod(dst, mode)
            try:
                subprocess.run(["chown", f"root:{GRP_SSL}", str(dst)],
                               check=False)
            except Exception:
                pass
    _ok(f"Wildcard-сертификат {domain} установлен: {CERT_DIR}")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  SYSTEMD-ЮНИТЫ (полный неймспейс smartdns-*)
# ══════════════════════════════════════════════════════════════════════════

def _chimera_root() -> str:
    """Корень установки Chimera (для PYTHONPATH таймеров geo-обновлений)."""
    return str(Path(__file__).resolve().parents[1])


def _unit_xray() -> str:
    return f"""[Unit]
Description=SmartDNS Xray Transparent SNI Proxy
After=network-online.target {UNIT_FW}
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User={USER_XRAY}
Group={USER_XRAY}
ExecStartPre={XRAY_BIN} run -test -confdir {XRAY_CONF_DIR}
ExecStart={XRAY_BIN} run -confdir {XRAY_CONF_DIR}
Restart=on-failure
RestartSec=3s
TimeoutStartSec=20s
TimeoutStopSec=15s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths={XRAY_LOG_DIR}
ReadOnlyPaths={XRAY_CONF_DIR} {XRAY_RULES_DIR}

[Install]
WantedBy=multi-user.target
"""


def _unit_engine(cfg: dict) -> str:
    if cfg.get("engine") == "oxidns":
        return f"""[Unit]
Description=SmartDNS OxiDNS Engine
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User={USER_OXIDNS}
Group={USER_OXIDNS}
SupplementaryGroups={USER_XRAY}
WorkingDirectory=/var/lib/smartdns-oxidns
ExecStartPre={OXIDNS_BIN} check -c {OXIDNS_CONF_DIR}/config.yaml -d /var/lib/smartdns-oxidns
ExecStart={OXIDNS_BIN} start -c {OXIDNS_CONF_DIR}/config.yaml -d /var/lib/smartdns-oxidns
Restart=on-failure
RestartSec=3s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/smartdns-oxidns
ReadOnlyPaths={OXIDNS_CONF_DIR} {ASSETS_DIR}

[Install]
WantedBy=multi-user.target
"""
    return f"""[Unit]
Description=SmartDNS AdGuardHome Engine
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User={USER_AGH}
Group={USER_AGH}
SupplementaryGroups={USER_XRAY}
WorkingDirectory=/var/lib/smartdns-adguardhome
ExecStart={AGH_BIN} -c {AGH_CONF_DIR}/AdGuardHome.yaml -w /var/lib/smartdns-adguardhome --no-check-update
Restart=on-failure
RestartSec=3s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={AGH_CONF_DIR} /var/lib/smartdns-adguardhome
ReadOnlyPaths={ASSETS_DIR}

[Install]
WantedBy=multi-user.target
"""


def _unit_firewall() -> str:
    return f"""[Unit]
Description=SmartDNS ipset and Netfilter Rules Manager
After=network-online.target ufw.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={BIN_DIR}/smartdns-firewall-apply.py
ExecStop=/bin/sh -c 'ipset save > {IPSET_SAVE_FILE}'

[Install]
WantedBy=multi-user.target
"""


def _unit_watchers() -> str:
    common = """[Service]
Type=simple
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
"""
    return (
        f"""[Unit]
Description=SmartDNS DoH Authorization ipset Watcher
After=nginx.service {UNIT_FW}
Requires={UNIT_FW}
StartLimitIntervalSec=120
StartLimitBurst=5

{common}ExecStart={BIN_DIR}/smartdns-doh-watcher.py

[Install]
WantedBy=multi-user.target
""",
        f"""[Unit]
Description=SmartDNS DoT Authorization ipset Watcher
After={UNIT_XRAY} nginx.service {UNIT_FW}
Requires={UNIT_FW}
StartLimitIntervalSec=120
StartLimitBurst=5

{common}ExecStart={BIN_DIR}/smartdns-dot-watcher.py

[Install]
WantedBy=multi-user.target
""")


def _unit_xray_reload() -> "tuple[str, str]":
    safe_reload = f"""#!/usr/bin/env python3
# {NGINX_MARKER} — validated reload: xray -test гейт, откат last-good.
import json, shutil, subprocess, time
from pathlib import Path
RULES = Path({str(XRAY_RULES_DIR)!r}) / "10-smartdns-routing.json"
BACKUP = Path({str(STATE_DIR)!r}) / "10-smartdns-routing.json.lastgood"
CONF = Path({str(XRAY_CONF_DIR)!r})
LOG = Path({str(LOG_DIR)!r}) / "xray.log"
XRAY = Path({str(XRAY_BIN)!r})
def log(msg):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(f"{{time.strftime('%Y-%m-%dT%H:%M:%S')}} [XRAY-RELOAD] {{msg}}\\n")
test = subprocess.run([str(XRAY), "run", "-test", "-confdir", str(CONF)],
                      capture_output=True)
if test.returncode == 0:
    if RULES.exists():
        shutil.copy2(RULES, BACKUP)
    subprocess.run(["systemctl", "restart", {UNIT_XRAY!r}])
    log("Проверка пройдена, Xray перезагружен")
else:
    log("ОШИБКА проверки конфигурации! Восстановление last-good.")
    if BACKUP.exists():
        shutil.copy2(BACKUP, RULES)
    raise SystemExit(1)
"""
    path_unit = f"""[Unit]
Description=Monitor {XRAY_RULES_DIR}/10-smartdns-routing.json for changes

[Path]
PathChanged={XRAY_RULES_DIR}/10-smartdns-routing.json
Unit={UNIT_RELOAD_SVC}

[Install]
WantedBy=multi-user.target
"""
    svc_unit = f"""[Unit]
Description=Validated SmartDNS Xray Configuration Reload
After={UNIT_XRAY}

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {BIN_DIR}/smartdns-xray-safe-reload.py
"""
    return path_unit, svc_unit, safe_reload


def _unit_geo_timers() -> "tuple[str, str, str, str]":
    root = _chimera_root()
    base = (f"Environment=PYTHONPATH={root}\n"
            f"WorkingDirectory={root}\n")
    geosite_svc = f"""[Unit]
Description=Update geosite.dat for SmartDNS
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
{base}ExecStart=/usr/bin/python3 -m chimera.modules.smartdns_stack update-geosite
"""
    geosite_tmr = """[Unit]
Description=Daily geosite.dat update at 04:00

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""
    geohide_svc = f"""[Unit]
Description=Update GeoHideDNS domains and SmartDNS routing rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
{base}ExecStart=/usr/bin/python3 -m chimera.modules.smartdns_stack update-geohide
"""
    geohide_tmr = """[Unit]
Description=Daily GeoHideDNS update at 04:05

[Timer]
OnCalendar=*-*-* 04:05:00
Persistent=true

[Install]
WantedBy=timers.target
"""
    return geosite_svc, geosite_tmr, geohide_svc, geohide_tmr


def write_systemd_units(cfg: dict) -> bool:
    """Пишет все юниты + safe-reload-скрипт; daemon-reload; enable+start."""
    unit_dir = Path("/etc/systemd/system")
    engine_unit = _engine_unit(cfg)

    def _write_unit(name: str, content: str) -> None:
        p = unit_dir / name
        p.write_text(content)
        os.chmod(p, 0o644)

    _write_unit(UNIT_XRAY, _unit_xray())
    _write_unit(engine_unit, _unit_engine(cfg))
    _write_unit(UNIT_FW, _unit_firewall())
    w_doh, w_dot = _unit_watchers()
    _write_unit(UNIT_DOH_WATCH, w_doh)
    _write_unit(UNIT_DOT_WATCH, w_dot)
    path_u, svc_u, safe_reload = _unit_xray_reload()
    _write_unit(UNIT_RELOAD_PATH, path_u)
    _write_unit(UNIT_RELOAD_SVC, svc_u)
    reload_script = BIN_DIR / "smartdns-xray-safe-reload.py"
    reload_script.write_text(safe_reload)
    os.chmod(reload_script, 0o755)
    gsvc, gtmr, hsvc, htmr = _unit_geo_timers()
    _write_unit(UNIT_GEOSITE_SVC, gsvc)
    _write_unit(UNIT_GEOSITE_TMR, gtmr)
    _write_unit(UNIT_GEOHIDE_SVC, hsvc)
    _write_unit(UNIT_GEOHIDE_TMR, htmr)

    subprocess.run(["systemctl", "daemon-reload"], check=False)
    _ok("systemd-юниты smartdns-* записаны")
    return True


def enable_and_start(cfg: dict) -> bool:
    """enable --now всех юнитов; порядок старта как в bash (fw → движок →
    nginx reload уже сделан → xray → ватчеры → таймеры)."""
    engine_unit = _engine_unit(cfg)
    for unit in (UNIT_FW, engine_unit):
        subprocess.run(["systemctl", "enable", "--now", unit],
                       capture_output=True, check=False)
    subprocess.run(["systemctl", "restart", UNIT_XRAY],
                   capture_output=True, check=False)
    subprocess.run(["systemctl", "start", UNIT_RELOAD_PATH],
                   capture_output=True, check=False)
    for unit in (UNIT_DOH_WATCH, UNIT_DOT_WATCH,
                 UNIT_GEOSITE_TMR, UNIT_GEOHIDE_TMR):
        subprocess.run(["systemctl", "enable", "--now", unit],
                       capture_output=True, check=False)
    # Дождаться движка на 5353/udp (компиляция фильтров при первом старте).
    for _ in range(15):
        r = subprocess.run(["ss", "-ulnp"], capture_output=True, text=True,
                           check=False)
        if ":5353 " in (r.stdout or ""):
            break
        time.sleep(1)
    _ok("Сервисы smartdns-* запущены")
    return True


def _restart_unit(unit: str, restart: bool = True) -> None:
    subprocess.run(["systemctl", "restart" if restart else "reload-or-restart",
                    unit], capture_output=True, check=False)


def stop_and_disable(cfg: dict) -> None:
    """Останавливает и дизейблит все юниты стека (uninstall)."""
    engine_unit = _engine_unit(cfg) if cfg else UNIT_OXIDNS
    for unit in [UNIT_XRAY, UNIT_DOH_WATCH, UNIT_DOT_WATCH, UNIT_RELOAD_PATH,
                 UNIT_GEOSITE_TMR, UNIT_GEOHIDE_TMR, engine_unit, UNIT_FW,
                 UNIT_RELOAD_SVC, UNIT_GEOSITE_SVC, UNIT_GEOHIDE_SVC]:
        subprocess.run(["systemctl", "disable", "--now", unit],
                       capture_output=True, check=False)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "reset-failed"], capture_output=True,
                   check=False)


def remove_units() -> None:
    """Удаляет файлы юнитов (после stop_and_disable)."""
    unit_dir = Path("/etc/systemd/system")
    for name in ALL_UNITS:
        (unit_dir / name).unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False)


# ══════════════════════════════════════════════════════════════════════════
#  ВЕРИФИКАЦИЯ БЭКЕНДА (dig-пробы; паритет verify_dns_backend_isolated)
# ══════════════════════════════════════════════════════════════════════════

def _dig(args: list, timeout: int = 4) -> str:
    try:
        r = subprocess.run(["dig", f"+time={timeout}", "+tries=1", *args],
                           capture_output=True, text=True, check=False,
                           timeout=timeout + 4)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def verify_dns_backend(cfg: dict) -> "tuple[bool, list[str]]":
    """Живые пробы: апстрим-резолв + кэш + спуфинг GeoHide + NODATA AAAA.
    Возвращает (ok, отчёт-строки)."""
    report = []
    engine_unit = _engine_unit(cfg)
    r = subprocess.run(["systemctl", "is-active", engine_unit],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        return False, [f"движок {engine_unit} не активен"]
    report.append(f"движок {engine_unit}: active")

    def _short_a(name: str) -> str:
        out = _dig(["@127.0.0.1", "-p", str(PORT_ENGINE), name, "A", "+short"])
        for line in out.splitlines():
            if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line.strip()):
                return line.strip()
        return ""

    upstream = _short_a("example.com")
    if not upstream or upstream == cfg["server_ipv4"]:
        return False, report + [f"апстрим-резолв example.com → "
                                f"'{upstream}' (ожидался внешний IP)"]
    cached = _short_a("example.com")
    if cached != upstream:
        return False, report + ["кэш-проба не совпала с апстримом"]
    report.append(f"апстрим+кэш: example.com → {upstream}")

    spoofed = ""
    for i in range(15):
        spoofed = _short_a(f"probe-{i}.generativelanguage.googleapis.com")
        if spoofed == cfg["server_ipv4"]:
            break
        time.sleep(1)
    spoofed = _short_a("generativelanguage.googleapis.com")
    if spoofed != cfg["server_ipv4"]:
        return False, report + [
            f"спуфинг GeoHide: generativelanguage → '{spoofed}', "
            f"ожидался {cfg['server_ipv4']} (фильтры могли не скомпилироваться)"]
    report.append(f"спуфинг GeoHide: → {cfg['server_ipv4']}")

    aaaa = _dig(["@127.0.0.1", "-p", str(PORT_ENGINE),
                 "generativelanguage.googleapis.com", "AAAA"])
    if "status: NOERROR" not in aaaa or "ANSWER: 0" not in aaaa:
        return False, report + ["AAAA NODATA-проба не прошла"]
    report.append("AAAA NODATA: ok")
    return True, report


# ══════════════════════════════════════════════════════════════════════════
#  CLI (systemd-таймеры geo-обновлений)
# ══════════════════════════════════════════════════════════════════════════

def _cli() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("update-geosite",
                                                "update-geohide"):
        print("Использование: python3 -m chimera.modules.smartdns_stack "
              "update-geosite|update-geohide")
        return 2
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from chimera.modules.smartdns import load_settings
    cfg = load_settings()
    if not cfg:
        print("[ERR] settings.json не найден — сначала установка")
        return 1
    ok = (update_geosite(cfg) if sys.argv[1] == "update-geosite"
          else update_geohide(cfg))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
