"""
chimera/modules/openflux.py
───────────────────────────────────────────────────────────────────────────────
OpenFlux — carrier-channel туннель: трафик клиента доходит до exit-ноды
через ЛЕГИТИМНЫЕ РУ-сервисы (Яндекс.Документы / Волга / MAX / Cups.online).

Зачем это Химере:
  Все остальные транспорта флота (VLESS/REALITY, mieru, hy2, b4) так или
  иначе тянут международку от клиента. OpenFlux — единственный класс
  решений, где клиентский leg ЦЕЛИКОМ домашний:
    юзер → disk.yandex.ru (живёт всегда) → комната документа → exit VPS → мир
  Канал для «кинематографического» сценария: международку порезали,
  иностранные IP выпилены — а Яша отвечает.

Архитектура upstream (github.com/p1neappleXpress/OpenFlux, GPL-3.0+):
  Клиент (SOCKS5 :1080)
    → gVisor userspace TCP/IP-стек (TCP/IPv4-only)
    → Transport: байтовая труба, 1 IP-пакет = 1 сообщение (lz4 сверху)
    → несущая: Яндекс.Документы (курсорные сообщения) | Волга (relay-API,
      батчи 20пкт/4МБ) | MAX (WebRTC DataChannel) | Cups.online (Centrifugo)
  Exit-нода (эта VPS):
    proxy-режим (по умолчанию) — gVisor-терминация + net.Dial:
      БЕЗ root, БЕЗ raw-сокетов, БЕЗ iptables. Инбаундов НЕТ — процесс
      сам исходяще подключается к Яндексу.
    raw-режим (опция) — raw-сокеты + SNAT, Linux+root, +правило дропа RST.

Секретность:
  URL документа = общий секрет (док публичный, любой с URL попадает в
  комнату) → модуль ВСЕГДА включает e2e-шифрование AES-256-GCM
  (--encryption-key-file, directional keys + anti-replay). Ключ на
  установке генерируется, хранится в /etc/openflux/transport.key.

Проверенная связка (мануал юзера «OpenFlux через Yandex», 10/10):
  Windows → SOCKS5 127.0.0.1:1080 → OpenFlux client → Yandex Docs edit-URL
  → Ubuntu 24 VPS (proxy mode) → Internet.
  Commit upstream: 461905369bd8f44ad2aacff240540d6a01d38c4d — пин по
  умолчанию (verified), «свежий main» — опция установки.

Интеграция в клиентские конфиги:
  OpenFlux-клиент поднимает ЛОКАЛЬНЫЙ SOCKS5 на устройстве юзера →
  в mihomo/Party/FlClash добавляется узел type: socks5 → 127.0.0.1:1080
  («🛟 Гарантия») последним звеном fallback-цепочки. Модуль экспортирует
  готовый фрагмент + команды запуска для Windows/Linux/macOS.
  Мобильные: готовые приложения OpenFluxAndroid (APK) / iOS (TestFlight).

Что модуль делает:
  • Ставит Go ≥1.26.4 (snap → tarball через download_manager: go.dev
    + 3 азиатских зеркала, /root-фолбэк WinSCP, min_size-контроль)
  • Тянет исходники OpenFlux тарболлом по sha через download_manager
    (codeload → 3 gh-proxy; git для установки больше не нужен,
    ls-remote — только чтобы узнать sha свежего main)
  • Пин verified-commit (или свежий main по выбору)
  • Генерирует e2e-ключ, пишет /etc/openflux/openflux.env (600)
  • systemd-сервис openflux: proxy-режим под непривилегированным юзером
    (raw — опция: root + scoped RST-drop + автоСLEANUP через ExecStopPost)
  • Bridge-режим: клиент OpenFlux НА ЭТОЙ VPS — SOCKS5-сервер
    (по умолчанию 127.0.0.1:1080) для цепочек Xray/mihomo на сервере.
    Порт живёт в port_registry: активация = проверка занятости +
    регистрация + UFW (для публичного bind), деактивация/удаление =
    закрытие + разрегистрация (требование юзера, см. _bridge_port_open)
  • Ротация ключа и смена doc-URL (ротация канала) без переустановки
  • Экспорт клиентского бандла: команды запуска + mihomo-фрагмент
  • Обновление исходников (re-fetch tarball + rebuild + restart)
  • Любой интерактивный промпт отменяем: Ctrl+C ИЛИ Esc(+Enter) →
    _ask() → _Cancelled → назад в меню установки (урок юзера: раньше
    Ctrl+C на URL-промпте молча превращался в «пустая ссылка»)

Порты (всё через port_registry):
  • exit-нода — ИСХОДЯЩИЙ канал (WSS/HTTPS к носителю), инбаундов
    нет: не регистрирует и не открывает ничего.
  • bridge — SOCKS5 bind:port (default 127.0.0.1:1080). Loopback-bind
    в UFW не нуждается (как b4_web/dnscrypt), но регистрируется в
    реестре для conflict-detection; 0.0.0.0-bind — ещё и UFW-правило.

Что модуль НЕ трогает:
  • Xray config.json и VLESS-inbound
  • state.json инстоллера и прочие сателлиты
  • iptables (proxy-режим правил не требует вовсе)

Точка входа из _core.py:
    from chimera.modules.openflux import do_openflux_menu
    do_openflux_menu()

CLI (для скриптов):
    python3 -m chimera.modules.openflux <install|status|logs|restart|
                                          export|rotate-key|set-url|update|
                                          uninstall> [--transport ...]
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import argparse
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state, proto_ask,
)

_Cancelled = ProtoCancelled

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════

def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[31m', GREEN='\033[32m', YELLOW='\033[33m',
            CYAN='\033[36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[97m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD',
                            'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════

_REPO_URL        = "https://github.com/p1neappleXpress/OpenFlux.git"
# Verified-коммит из мануала юзера (§14: «В тесте commit был …», 10/10 curl).
# Дефолт установки; «свежий main» — опция (upstream живой, API Яндекса
# меняется — свежий main может быть и лучше, и хуже; пин = воспроизводимость).
_PINNED_COMMIT   = "461905369bd8f44ad2aacff240540d6a01d38c4d"

_SRC_DIR         = Path("/opt/openflux/src")           # git-clone
_INSTALL_DIR     = Path("/opt/openflux")               # дерево установки
_BIN             = Path("/opt/openflux/universal-bypass-tool")
_ENV_DIR         = Path("/etc/openflux")
_ENV_FILE        = Path("/etc/openflux/openflux.env")
_KEY_FILE        = Path("/etc/openflux/transport.key")
_BUNDLE_FILE     = Path("/etc/openflux/client-bundle.txt")
_SERVICE_FILE    = Path("/etc/systemd/system/openflux.service")
_SERVICE_NAME    = "openflux"
_SERVICE_USER    = "openflux"
_MODULE_STATE    = Path("/var/lib/xray-installer/openflux.json")

# Транспорты: ключ → (метка, нужен ли doc-URL на exit-ноде, стабильность)
#   yandex     — Документы, курсорные сообщения; проверен мануалом (10/10)
#   vyandex    — Волга-таблички, relay-API + батчи; экспериментальный, быстрый
#   cupsonline — комнаты live-coding; exit сам создаёт комнаты (URL не нужен),
#                сессионный секрет = base64-список комнат из stdout/journal
#   oneme      — MAX/WebRTC; НЕ предлагаем в меню (риск аккаунта, см. README
#                upstream), но CLI-флагом разрешаем
_TRANSPORTS = {
    "yandex":     ("Яндекс.Документы (курсорные сообщения)", True,  "verified"),
    "vyandex":    ("Яндекс.Волга (relay-API, батчи 4 МБ)",   True,  "experimental"),
    "cupsonline": ("Cups.online (комнаты live-coding)",       False, "experimental"),
    "oneme":      ("MAX-мессенджер (WebRTC DataChannel)",     True,  "risky"),
}
_MENU_TRANSPORTS = ("yandex", "vyandex", "cupsonline")   # oneme — только CLI

# Go: go.mod upstream требует 1.26.4 (спека и зеркала — openflux_packages)
_GO_MIN = (1, 26, 4)
_GOPROXY = "https://proxy.golang.org,https://goproxy.io,direct"

# Разрешение sha свежего main (best-effort): git ls-remote по тем же
# зеркалам-префиксам, что и раньше для клона. Для УСТАНОВКИ git больше
# не нужен — исходники идут тарболлом через download_manager.
_LS_REMOTE_URLS = [
    _REPO_URL,
    "https://gh-proxy.com/" + _REPO_URL,
    "https://ghproxy.net/" + _REPO_URL,
    "https://gh.llkk.cc/" + _REPO_URL,
]

# ── Bridge (клиент OpenFlux на этой VPS) ─────────────────────────────
_BRIDGE_SERVICE_FILE = Path("/etc/systemd/system/openflux-bridge.service")
_BRIDGE_SERVICE_NAME = "openflux-bridge"
_BRIDGE_ENV_FILE     = Path("/etc/openflux/openflux-bridge.env")
_DEFAULT_BRIDGE_BIND = "127.0.0.1"   # loopback: UFW не трогаем, только реестр
_DEFAULT_BRIDGE_PORT = 1080          # канонический SOCKS5

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (конвенция проекта, см. mieru.py)
# ══════════════════════════════════════════════════════════════════════════════


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad = _BOX_W - _wlen(title); lpad = pad // 2; rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text); cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1: cut = i; break
        text = text[:cut] + "…"; w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

def _box_log_line(line: str, indent: str = "  ") -> None:
    avail_1 = _BOX_W - _wlen(indent)
    cont_indent = indent + "↳ "
    avail_2 = _BOX_W - _wlen(cont_indent)
    plain = line
    if _wlen(plain) <= avail_1:
        _box_row(f"{indent}{DIM}{plain}{NC}")
        return
    first_part = plain[:avail_1]
    rest = plain[avail_1:]
    if _wlen(rest) > avail_2:
        rest = rest[:max(0, avail_2 - 1)] + "…"
    _box_row(f"{indent}{DIM}{first_part}{NC}")
    _box_row(f"{cont_indent}{DIM}{rest}{NC}")

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

# ══════════════════════════════════════════════════════════════════════════════
#  ВВОД С ОТМЕНОЙ (Ctrl+C / Esc)
# ══════════════════════════════════════════════════════════════════════════════
#  Урок юзера: на URL-промпте Ctrl+C молча превращался в «пустая ссылка»
#  — proto_ask без c=True возвращает default="" вместо отмены, и выйти
#  из мастера было НЕВОЗМОЖНО. С этих пор любой интерактивный промпт
#  модуля идёт через _ask: Ctrl+C ИЛИ Esc(+Enter) → _Cancelled →
#  возврат в меню установки.

# CSI (стрелки/Home/End/bracketed-paste), OSC (заголовок окна), SS3,
# одиночный Esc (группа опциональна — голый \x1b тоже матчится)
_ESC_SEQ_RE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|O[ -~])?")


def _strip_esc(s: str) -> tuple[str, bool]:
    """Убирает escape-мусор из строки ввода; ``(_, True)`` = был Esc.

    Терминал в cooked-режиме кладёт ESC-последовательности прямо в
    буфер строки: стрелки, Home/End, обёртки bracketed paste
    (\\x1b[200~...\\x1b[201~), OSC. Если юзер жал стрелки перед вставкой
    ссылки — она не должна ломаться. Остаточные одиночные Esc (после
    CSI/OSC-разбора) вычищаются заменой: голый Esc перед печатным
    текстом = случайное нажатие, текст сохраняем; только Esc без
    текста = намеренная отмена (см. _ask)."""
    had = "\x1b" in s
    if not had:
        return s, False
    s = _ESC_SEQ_RE.sub("", s)
    s = s.replace("\x1b", "")
    return s, had


def _ask(prompt: str, default: str = "") -> str:
    """Интерактивный ввод с отменой: Ctrl+C ИЛИ Esc(+Enter) → _Cancelled.

    Отличия от proto_ask:
      • всегда c=True — Ctrl+C = отмена (не «пустая строка»);
      • Esc: cooked-терминал кладёт \\x1b в буфер, Enter подтверждает —
        строка из «голого» Esc (+возможно стрелки) = отмена. Подсказка
        об этом печатается в самих промптах;
      • escape-мусор (стрелки, bracketed paste) вычищается — вставленная
        ссылка не ломается.
    Пустой ввод → default (семантика proto_ask сохранена)."""
    raw = proto_ask(prompt, default="", c=True)
    cleaned, had_esc = _strip_esc(raw)
    if had_esc and not cleaned.strip():
        raise _Cancelled()
    return cleaned.strip() or default

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: list, capture: bool = False, check: bool = False,
         cwd: Optional[str] = None,
         env_extra: Optional[dict] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if cwd:
        kw["cwd"] = cwd
    if env_extra:
        env = dict(os.environ)
        env.update(env_extra)
        kw["env"] = env
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    return "203.0.113.10"


def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")


def _is_installed() -> bool:
    return _BIN.exists() and _SERVICE_FILE.exists()


def _svc_active() -> bool:
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    return (r.stdout or "").strip() == "active"

# ══════════════════════════════════════════════════════════════════════════════
#  ЧИСТЫЕ ФУНКЦИИ (тестируются unit-тестами без сервера)
# ══════════════════════════════════════════════════════════════════════════════

def _validate_doc_url(url: str, transport: str = "yandex") -> tuple[bool, str]:
    """Валидация носителя для exit-ноды.

    yandex/vyandex: годится ТОЛЬКО полная edit-ссылка Яндекс.Документов
      https://disk.yandex.ru/edit/d/...?...&sk=...
      ОБЯЗАТЕЛЬНЫ оба признака: «/edit/d/» в пути И «sk=» в параметрах
      (ключ сессии, обычно последний в хвосте). Без sk= Яндекс отдаёт
      логин-редирект → upstream падает с «config not found».
      Короткая /i/... НЕ годится (мануал §«Важно»: она не открывает
      collaborative-комнату) — отдельная диагностика, чтобы юзер не
      гадал, почему «curl виснет».
    cupsonline: exit-ноде URL не нужен (комнаты создаёт сам), любое
      значение игнорируется — валидно всё.
    oneme: URL не используется (токен/uid), валидно всё.
    """
    u = (url or "").strip()
    if transport in ("cupsonline", "oneme"):
        return True, ""
    if not u:
        return False, "пустая ссылка"
    if not u.startswith("https://"):
        return False, "ссылка должна начинаться с https://"
    if "/i/" in u:
        return False, ("это КОРОТКАЯ ссылка (/i/...) — нужна edit-ссылка "
                       "https://disk.yandex.ru/edit/d/...")
    if "disk.yandex.ru/edit/" not in u and "disk.yandex.ru/edit#" not in u:
        return False, ("не похоже на edit-ссылку Яндекс.Документов "
                       "(ожидается disk.yandex.ru/edit/d/...)")
    if "sk=" not in u:
        return False, ("в ссылке нет «sk=» — ключ сессии обязателен. "
                       "Нужна ПОЛНАЯ ссылка с хвостом ?...&sk=... "
                       "(документ → «Поделиться» → копировать целиком)")
    return True, ""


def _parse_go_version(s: str) -> Optional[tuple]:
    """'go version go1.26.4 linux/amd64' → (1, 26, 4); иначе None."""
    m = re.search(r"go(\d+)\.(\d+)(?:\.(\d+))?", s or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _go_meets(s: str, minimum: tuple = _GO_MIN) -> bool:
    v = _parse_go_version(s)
    if v is None:
        return False
    return v >= minimum


def _gen_transport_key() -> str:
    """Секрет для --encryption-key-file (AES-256-GCM обёртка OpenFlux).

    32 случайных байта → base64 (44 символа). Upstream требует ≥16
    символов; scrypt(32768) внутри сам выведет AES-ключ из секрета."""
    import base64
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _render_env_file(doc_url: str, transport: str) -> str:
    """systemd EnvironmentFile: URL и транспорт. Ключ — ОТДЕЛЬНЫМ файлом
    (права 640 root:openflux), в env его не дублируем.
    oneme: токен/uid — опциональные заготовки под ручное редактирование
    (транспорт не из меню, только CLI-энтузиасты)."""
    u = (doc_url or "").strip()
    if " " in u or "'" in u or '"' in u:
        u = f'"{u}"'
    out = (
        "# OpenFlux exit-node (chimera/modules/openflux.py)\n"
        "# ФАЙЛ СЕКРЕТНЫЙ: doc-URL = ключ входа в комнату документа.\n"
        f"OPENFLUX_URL={u}\n"
        f"OPENFLUX_TRANSPORT={transport}\n"
    )
    if transport == "oneme":
        out += (
            "# MAX-транспорт (CLI-only): заполните вручную и перезапустите\n"
            "# сервис — без них oneme не поднимется.\n"
            "OPENFLUX_MAX_TOKEN=\n"
            "OPENFLUX_MAX_UID=\n"
        )
    return out


def _render_systemd_unit(transport: str, raw_mode: bool = False,
                         local_ip: str = "") -> str:
    """systemd-юнит exit-ноды.

    proxy-режим (по умолчанию): User=openflux, NoNewPrivileges, НИКАКИХ
    iptables — gVisor-терминация + net.Dial не требуют root (README
    upstream: «Без root, без raw-сокетов, без iptables»).

    raw-режим (опция «максимальная совместимость/скорость»): root,
    --mode raw + --local-ip, scoped RST-drop только с egress-IP (не
    хост-wide! — автор upstream сам рекомендует scoped-правило),
    ExecStopPost снимает правило — после stop/service-остановки мусора
    в iptables не остаётся."""
    common = (
        "[Unit]\n"
        "Description=OpenFlux Exit Node (carrier channel)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
    )
    if not raw_mode:
        oneme_tail = ""
        if transport == "oneme":
            oneme_tail = (" --maxToken ${OPENFLUX_MAX_TOKEN}"
                          " --maxUid ${OPENFLUX_MAX_UID}")
        return (
            common +
            f"User={_SERVICE_USER}\n"
            "Group=" + _SERVICE_USER + "\n"
            "EnvironmentFile=" + str(_ENV_FILE) + "\n"
            f"ExecStart={_BIN} --exit-node --transport {transport} "
            f"--url ${{OPENFLUX_URL}} "
            f"--encryption-key-file { _KEY_FILE }{oneme_tail}\n"
            "Restart=always\n"
            "RestartSec=5\n"
            "NoNewPrivileges=true\n"
            "ProtectSystem=strict\n"
            "ReadWritePaths=-/var/log\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
    ip = local_ip or _get_server_ip()
    oneme_tail = ""
    if transport == "oneme":
        oneme_tail = " --maxToken ${OPENFLUX_MAX_TOKEN} --maxUid ${OPENFLUX_MAX_UID}"
    return (
        common +
        "EnvironmentFile=" + str(_ENV_FILE) + "\n"
        f"ExecStart={_BIN} --exit-node --transport {transport} "
        f"--url ${{OPENFLUX_URL}} --mode raw --local-ip {ip} "
        f"--encryption-key-file { _KEY_FILE }{oneme_tail}\n"
        f"ExecStartPost=/usr/sbin/iptables -A OUTPUT -p tcp "
        f"--tcp-flags RST RST -s {ip} -j DROP\n"
        f"ExecStopPost=/usr/sbin/iptables -D OUTPUT -p tcp "
        f"--tcp-flags RST RST -s {ip} -j DROP || true\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _render_mihomo_fragment() -> str:
    """Фрагмент proxies для КЛИЕНТСКОГО mihomo-конфига юзера (Party/
    FlClash/Verge): узел-цепочка через ЛОКАЛЬНЫЙ OpenFlux-клиент.

    dialer-proxy/udp не нужны: это листовой socks5 на 127.0.0.1.
    Ссылки наружу не содержат — фрагмент одинаков для всех юзеров."""
    return (
        "  # 🛟 OpenFlux — канал «последней надежды» через Яндекс.Документы.\n"
        "  # Требует запущенный OpenFlux-клиент на этом устройстве\n"
        "  # (см. бандл от сервера). Без него узел мёртв — потому и в конце\n"
        "  # fallback-цепочки, а не в основном выборе.\n"
        "  - name: \"🛟 OpenFlux\"\n"
        "    type: socks5\n"
        "    server: 127.0.0.1\n"
        "    port: 1080\n"
        "    udp: false\n"
    )


def _render_bridge_env_file(doc_url: str, transport: str) -> str:
    """EnvironmentFile bridge-сервиса. URL/транспорт — те же, что у
    exit-ноды (одна комната документа = один канал); ключ тоже общий
    (e2e симметричен). oneme — заготовки токенов, как у exit."""
    u = (doc_url or "").strip()
    if " " in u or "'" in u or '"' in u:
        u = f'"{u}"'
    out = (
        "# OpenFlux bridge (клиент на ЭТОЙ VPS, chimera/modules/openflux.py)\n"
        "# Тот же doc-URL/транспорт/ключ, что у exit-ноды — одна комната.\n"
        f"OPENFLUX_URL={u}\n"
        f"OPENFLUX_TRANSPORT={transport}\n"
    )
    if transport == "oneme":
        out += (
            "# MAX-транспорт (CLI-only): заполните вручную и перезапустите.\n"
            "OPENFLUX_MAX_TOKEN=\n"
            "OPENFLUX_MAX_UID=\n"
        )
    return out


def _render_bridge_unit(bind: str, port: int, transport: str) -> str:
    """systemd-юнит bridge-сервиса: OpenFlux-КЛИЕНТ на этой VPS.

    --socks5 {bind}:{port} — локальный SOCKS5-сервер для цепочек
    Xray/mihomo на самом сервере (VPS-гибрид / узел «🛟 Гарантия»).
    Клиентский режим не требует root: тот же unprivileged-юзер, что и
    у exit-ноды; никаких iptables/raw. ВАЖНО: дефолт апстрима ':1080'
    слушает ВСЕ интерфейсы — мы всегда указываем bind явно."""
    oneme_tail = ""
    if transport == "oneme":
        oneme_tail = (" --maxToken ${OPENFLUX_MAX_TOKEN}"
                      " --maxUid ${OPENFLUX_MAX_UID}")
    return (
        "[Unit]\n"
        "Description=OpenFlux Bridge (client SOCKS5 on this VPS)\n"
        "After=network-online.target openflux.service\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={_SERVICE_USER}\n"
        "Group=" + _SERVICE_USER + "\n"
        f"EnvironmentFile={_BRIDGE_ENV_FILE}\n"
        f"ExecStart={_BIN} --client --transport {transport} "
        f"--url ${{OPENFLUX_URL}} "
        f"--socks5 {bind}:{port} "
        f"--encryption-key-file { _KEY_FILE }{oneme_tail}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _render_client_bundle(doc_url: str, transport: str, key: str,
                          server_ip: str) -> str:
    """Текстовый клиентский бандл: команды запуска обоих концов +
    mihomo-фрагмент. Пишется в /etc/openflux/client-bundle.txt (600) и
    печатается в export-меню ПОЗАДИ рамок (урок длинные ссылки
    рвут бордюры — печатаем их отдельными строками вне боксов)."""
    u = doc_url or "<YANDEX_DOCS_EDIT_URL>"
    return f"""\
════════ OpenFlux client bundle (сгенерировано Chimera) ════════
Носитель : {transport}
Сервер   : {server_ip} (exit-node, режим из /etc/openflux)
E2E-шифр : AES-256-GCM (обе стороны — один ключ)

── 1. Windows (PowerShell) ─────────────────────────────────────
git clone https://github.com/p1neappleXpress/OpenFlux.git "$env:USERPROFILE\\OpenFlux"
cd "$env:USERPROFILE\\OpenFlux"
go mod tidy
go build -o openflux.exe .
# положите ключ в файл transport.key (содержимое — см. ниже):
notepad transport.key
$URL = '{u}'
.\\openflux.exe --client --transport {transport} --url $URL --socks5 127.0.0.1:1080 --encryption-key-file transport.key

── 2. Linux / macOS ────────────────────────────────────────────
git clone https://github.com/p1neappleXpress/OpenFlux.git ~/OpenFlux
cd ~/OpenFlux && go mod tidy && go build -o openflux .
printf '%s\\n' '{key}' > transport.key
URL='{u}'
./openflux --client --transport {transport} --url "$URL" --socks5 127.0.0.1:1080 --encryption-key-file transport.key

── 3. Мобильные ────────────────────────────────────────────────
Android: github.com/p1neappleXpress/OpenFluxAndroid (APK)
iOS:     TestFlight — testflight.apple.com/join/BwnAcdus

── 4. Проверка ─────────────────────────────────────────────────
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
→ должно вернуть {server_ip}

── 5. Встраивание в mihomo (Party/FlClash/Verge) ───────────────
В proxies: (фрагмент ниже)
{_render_mihomo_fragment()}И добавить в fallback-группу ПОСЛЕДНИМ звеном, например:
  - "🛟 OpenFlux"
Если в конфиге есть QUIC-блок (REJECT udp/443) — он не мешает:
OpenFlux-туннель сам TCP-only, QUIC внутри него и так не ходит.

── 6. Ключ e2e (секрет; тот же на клиенте и сервере) ───────────
{key}

── ВАЖНО ───────────────────────────────────────────────────────
• doc-URL = СЕКРЕТ: любой, кто его знает, попадает в комнату
  документа. e2e-ключ защищает ТРАФИК, но не факт присутствия.
• Рекомендация upstream: отдельный (не основной) Яндекс-аккаунт.
• Внутри туннеля только TCP/IPv4 — браузинг и мессенджеры да,
  QUIC/голос — нет.
• Яндекс может поменять API Документов — тогда каналу нужен
  апдейт исходников (меню → Обновить).
═══════════════════════════════════════════════════════════════
"""

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА: GO
# ══════════════════════════════════════════════════════════════════════════════

def _current_go() -> str:
    """Вывод `go version` (путь /usr/local/go/bin тоже щупаем — tarball-
    установка не всегда в PATH).'' — Go нет."""
    for go in ("go", "/usr/local/go/bin/go", "/usr/lib/go/bin/go"):
        r = _run([go, "version"], capture=True)
        if r.returncode == 0 and r.stdout:
            return r.stdout.strip()
    return ""


def _ensure_go() -> Optional[str]:
    """Go ≥1.26.4 (go.mod upstream). Цепочка:
    1) уже стоит и свежий → ок;
    2) snap install go --classic (мануал юзера §2.2 — проверенный путь
       на Ubuntu 24; snap-канал из РФ доступен);
    3) ОБЩИЙ GO_TOOLCHAIN_SPEC через download_manager (как
       wdtt/webdav_tunnel/olcrtc): go.dev → golang.google.cn → aliyun
       → tencent, /root-фолбэк WinSCP, post_install сам делает
       симлинки в /usr/local/bin. Пин go1.26.4 = воспроизводимость.
    Возвращает строку `go version` или None (фейл)."""
    cur = _current_go()
    if _go_meets(cur):
        return cur
    if cur:
        print(f"  {YELLOW}⚠{NC}  Найден устаревший Go: {cur}")
    print(f"  {CYAN}→{NC}  Ставлю Go через snap (проверенный путь, мануал §2.2)...")
    r = _run(["snap", "install", "go", "--classic"], capture=True)
    if r.returncode != 0:
        print(f"  {YELLOW}⚠{NC}  snap не сработал ({(r.stderr or '').strip()[:60]})"
              f" — качаю тулчейн через download_manager")
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        arch = "amd64" if _is_amd64() else "arm64"
        ok = fetch_package(
            GO_TOOLCHAIN_SPEC,
            progress_label="Go",
            version=f"go{_GO_MIN[0]}.{_GO_MIN[1]}.{_GO_MIN[2]}", arch=arch,
        )
        if not ok:
            print(f"  {RED}✗{NC}  download_manager не смог доставить Go-тулчейн")
            return None
    cur = _current_go()
    if _go_meets(cur):
        return cur
    print(f"  {RED}✗{NC}  Go так и не достиг {_GO_MIN}: {cur or 'не найден'}")
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА: ИСХОДНИКИ + СБОРКА
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_main_sha() -> str:
    """sha HEAD ветки main через `git ls-remote` (best-effort, зеркала
    те же). Пустая строка = не удалось (git отсутствует / все зеркала
    молчат) — вызывающий код падает на tarball refs/heads/main."""
    if not shutil.which("git"):
        return ""
    for url in _LS_REMOTE_URLS:
        r = _run(["git", "ls-remote", url, "HEAD"], capture=True)
        if r.returncode == 0 and r.stdout:
            head = (r.stdout or "").split()[0]
            if re.fullmatch(r"[0-9a-f]{40}", head):
                return head
    return ""


def _fetch_sources(use_main: bool = False) -> Optional[str]:
    """Исходники тарболлом через download_manager. Возвращает
    commit-sha (или 'main' для fallback-ветки) или None.

    Пин-режим: tarball по точному 40-символьному sha — иммутабелен,
    кеш зеркала не может подменить контент; codeload → 3 gh-proxy.
    main-режим: сначала ls-remote (sha свежего HEAD) → tarball по sha;
    если ls-remote не дал sha — tarball refs/heads/main (зеркало может
    отдать кеш-отставание, предупреждаем) и commit записывается как
    'main'. git для УСТАНОВКИ не нужен — только tar."""
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.openflux_packages import OPENFLUX_SRC_SPEC

    stale_warn = False
    if use_main:
        ref = _resolve_main_sha()
        if ref:
            print(f"  {CYAN}→{NC}  main → {ref[:12]} (ls-remote)")
        else:
            ref = "refs/heads/main"
            stale_warn = True
    else:
        ref = _PINNED_COMMIT

    ok = fetch_package(OPENFLUX_SRC_SPEC, progress_label="OpenFlux",
                       ref=ref)
    if not ok:
        return None
    if stale_warn:
        print(f"  {YELLOW}⚠{NC}  sha main не разрешён — tarball ветки;"
              f" зеркало может отдать кеш-отставание")
    return ref if ref != "refs/heads/main" else "main"


def _build_binary() -> bool:
    """go mod tidy + go build. GOPROXY с goproxy.io-фоллбэком (РУ-
    устойчивость), GOTOOLCHAIN=auto (если snap дал более старый Go —
    тулчейн дотянутся сам)."""
    go = shutil.which("go") or "/usr/local/go/bin/go"
    env = {
        "GOPROXY": _GOPROXY,
        "GOTOOLCHAIN": "auto",
        "PATH": f"/usr/local/go/bin:{os.environ.get('PATH', '')}",
        "HOME": os.environ.get("HOME", "/root"),
    }
    print(f"  {CYAN}→{NC}  go mod tidy (может тянуть модули; gvisor большой)...")
    r = _run([go, "mod", "tidy"], cwd=str(_SRC_DIR), capture=True,
             env_extra=env)
    if r.returncode != 0:
        print(f"  {RED}✗{NC}  go mod tidy: {(r.stderr or '')[-200:]}")
        return False
    print(f"  {CYAN}→{NC}  go build (первая сборка ~1-3 мин)...")
    r = _run([go, "build", "-o", str(_BIN), "."], cwd=str(_SRC_DIR),
             capture=True, env_extra=env)
    if r.returncode != 0 or not _BIN.exists():
        print(f"  {RED}✗{NC}  go build: {(r.stderr or '')[-200:]}")
        return False
    _BIN.chmod(0o755)
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА: ЮЗЕР / КЛЮЧ / СЕРВИС
# ══════════════════════════════════════════════════════════════════════════════

def _ensure_openflux_user() -> None:
    """Непривилегированный системный юзер под proxy-режим (как mita у
    mieru). raw-режим сервисом сам переключается на root — юзер не мешает."""
    r = _run(["id", _SERVICE_USER], capture=True)
    if r.returncode == 0:
        return
    _run(["useradd", "--system", "--no-create-home",
          "--shell", "/usr/sbin/nologin", _SERVICE_USER])


def _write_key_file(key: str) -> None:
    _ENV_DIR.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_text(key.strip() + "\n", encoding="utf-8")
    os.chmod(_KEY_FILE, 0o640)
    try:
        import pwd
        _run(["chown", f"root:{_SERVICE_USER}", str(_KEY_FILE)])
    except Exception:
        pass


def _write_env(doc_url: str, transport: str) -> None:
    _ENV_DIR.mkdir(parents=True, exist_ok=True)
    _ENV_FILE.write_text(_render_env_file(doc_url, transport),
                         encoding="utf-8")
    _ENV_FILE.chmod(0o600)


def _install_service(transport: str, raw_mode: bool = False,
                     local_ip: str = "") -> None:
    _SERVICE_FILE.write_text(
        _render_systemd_unit(transport, raw_mode=raw_mode,
                             local_ip=local_ip), encoding="utf-8")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])


def _health_check() -> tuple[bool, str]:
    """active + в journal видно фрейм exit-ноды. 'Martian packet' и
    WS-reconnect — НЕ считаем фейлом (мануал: martian — не критично)."""
    if not _svc_active():
        r = _run(["journalctl", "-u", _SERVICE_NAME, "-n", "15",
                  "--no-pager"], capture=True)
        return False, (r.stdout or "").strip()
    r = _run(["journalctl", "-u", _SERVICE_NAME, "-n", "40", "--no-pager"],
             capture=True)
    out = r.stdout or ""
    good = ("Running as EXIT NODE" in out or "EXIT NODE" in out)
    return True, ("exit-кадр в журнале" if good else
                  "active, exit-кадр ещё не появился (ждите коннекта)")


# ══════════════════════════════════════════════════════════════════════════════
#  ПОРТЫ BRIDGE: всё через port_registry
#  активация  = port_is_free → port_register → ufw_open (публичный bind)
#  деактивация/удаление = ufw_close → port_unregister
#  exit-нода инбаундов не имеет — для неё порт-цикл пуст (by design)
# ══════════════════════════════════════════════════════════════════════════════

def _is_loopback_bind(bind: str) -> bool:
    return (bind or "").strip() in ("127.0.0.1", "::1", "localhost",
                                    "ip6-localhost", "ip6-loopback")


def _bridge_port_open(bind: str, port: int) -> tuple[bool, str]:
    """Проверка занятости + регистрация + открытие UFW для bridge-порта.

    Возвращает (ok, msg). msg при провале содержит список конфликтов
    (кто занял: реестр / ss-слушатель / чужое UFW-правило) — вызывающий
    код показывает его юзеру и предлагает другой порт.

    Loopback-bind: UFW не трогаем (loopback не фильтруется), но в
    реестр регистрируем — conflict-detect должен видеть занятость.
    Публичный bind: + ufw_open_port (идемпотентно)."""
    try:
        from chimera.modules.port_registry import (
            port_is_free, port_register, ufw_open_port, SERVICE_OPENFLUX_BRIDGE,
        )
    except Exception:
        # fallback-ветка (конвенция mieru): port_registry недоступен —
        # legacy-ufw вручную, только для публичного bind
        if not _is_loopback_bind(bind) and shutil.which("ufw"):
            _run(["ufw", "allow", f"{port}/tcp", "comment",
                  "chimera-openflux_bridge"], capture=True)
        return True, "порт занят без реестра (legacy-ufw)"

    is_free, conflicts = port_is_free(port, "tcp",
                                      exclude_service=SERVICE_OPENFLUX_BRIDGE)
    if not is_free:
        return False, "; ".join(conflicts)

    ok, msg = port_register(SERVICE_OPENFLUX_BRIDGE, port, "tcp",
                            comment="OpenFlux bridge SOCKS5")
    if not ok:
        return False, msg

    if not _is_loopback_bind(bind):
        ufw_ok, ufw_msg = ufw_open_port(port, "tcp", SERVICE_OPENFLUX_BRIDGE,
                                        comment="OpenFlux bridge SOCKS5")
        if not ufw_ok:
            # порт зарегистрирован, но UFW не открылся — говорим честно,
            # не считаем фейлом установки (loopback-цепочки работают)
            return True, f"{msg}; UFW: {ufw_msg}"
    return True, msg


def _bridge_port_close(port: int) -> None:
    """Деактивация/удаление bridge: UFW-правило снять, порт раз-
    регистрировать. Идемпотентно (нет правила/записи — молча ок)."""
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_OPENFLUX_BRIDGE,
        )
    except Exception:
        if shutil.which("ufw"):
            _run(["ufw", "delete", "allow", f"{port}/tcp"], capture=True)
        return
    ufw_close_port(port, "tcp", SERVICE_OPENFLUX_BRIDGE)
    port_unregister(SERVICE_OPENFLUX_BRIDGE, port, "tcp")


def _bridge_port_show_conflicts(port: int) -> list[str]:
    """Человекочитаемый список конфликтов для показа в меню."""
    try:
        return _port_is_free_wrapper(port)[1]
    except Exception:
        return []


def _port_is_free_wrapper(port: int) -> tuple[bool, list[str]]:
    """port_is_free для bridge-порта (тонкая обёртка для тестируемости)."""
    from chimera.modules.port_registry import (
        port_is_free, SERVICE_OPENFLUX_BRIDGE,
    )
    return port_is_free(port, "tcp", exclude_service=SERVICE_OPENFLUX_BRIDGE)


def _bridge_svc_active() -> bool:
    r = _run(["systemctl", "is-active", _BRIDGE_SERVICE_NAME], capture=True)
    return (r.stdout or "").strip() == "active"


def _bridge_probe_listener(bind: str, port: int,
                           timeout: float = 3.0) -> bool:
    """TCP-коннект до bridge-SOCKS5: слушатель реально поднялся?
    Публичный bind тоже щупаем через 127.0.0.1 (0.0.0.0 слушает всё)."""
    try:
        with socket.create_connection(("127.0.0.1", port),
                                      timeout=timeout):
            return True
    except OSError:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНЫЙ УСТАНОВОЧНЫЙ ФЛОУ
# ══════════════════════════════════════════════════════════════════════════════

def _ask_transport(cli_transport: Optional[str] = None) -> Optional[str]:
    """Меню выбора носителя. oneme в меню НЕ показываем (README upstream:
    риск лимитации MAX-аккаунта) — только через CLI-флаг."""
    if cli_transport:
        if cli_transport not in _TRANSPORTS:
            print(f"  {RED}✗{NC}  неизвестный транспорт: {cli_transport}")
            return None
        return cli_transport
    print()
    print(f"  {CYAN}Носитель канала (что видит провайдер):{NC}")
    for i, key in enumerate(_MENU_TRANSPORTS, 1):
        label, _, st = _TRANSPORTS[key]
        mark = {"verified": f"{GREEN}verified{NC}",
                "experimental": f"{YELLOW}эксперимент{NC}"}[st]
        print(f"   {DIM}[{NC}{WHITE}{BOLD}{i}{NC}{DIM}]{NC} {key:11} — {label}  {mark}")
    while True:
        try:
            raw = _ask(f"{CYAN}Выбор [1={_MENU_TRANSPORTS[0]}]: {NC}",
                       default="1")
        except _Cancelled:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(_MENU_TRANSPORTS):
            return _MENU_TRANSPORTS[int(raw) - 1]
        if raw in _TRANSPORTS:
            return raw
        print(f"  {YELLOW}⚠{NC}  введите 1-{len(_MENU_TRANSPORTS)}"
              f" или имя транспорта")


def _ask_doc_url(transport: str) -> Optional[str]:
    """edit-ссылка доков: строгий формат-блок (edit/d/ + sk=) +
    валидация + отмена (Ctrl+C / Esc+Enter) назад в меню установки.
    Пустой ввод на yandex/vyandex — отказ (URL обязателен)."""
    need_url = _TRANSPORTS[transport][1]
    if not need_url:
        return ""
    print()
    print(f"  {CYAN}Edit-ссылка Яндекс.Документа — носитель канала{NC}")
    print()
    print(f"  {YELLOW}⚠{NC}  Нужен {BOLD}ИМЕННО такой формат{NC} — это важно:")
    print(f"     в ссылке ДОЛЖНЫ быть «/edit/d/» и «sk=» (ключ сессии,")
    print(f"     стоит в конце хвоста ?...&sk=...). Без них Яндекс не")
    print(f"     открывает collaborative-комнату — канал не поднимется.")
    print()
    print(f"  {DIM}Формат целиком (это ОДНА строка; для показа разбита на 2):{NC}")
    print(f"    {WHITE}https://disk.yandex.ru/edit/d/ID_ДОКУМЕНТА{NC}")
    print(f"    {WHITE}?ПАРАМЕТРЫ&sk=КЛЮЧ_СЕССИИ{NC}")
    print()
    print(f"  {DIM}Пример (реальные длины частей — вставляйте свою ссылку{NC}")
    print(f"  {DIM}целиком, одной строкой):{NC}")
    print(f"    {DIM}https://disk.yandex.ru/edit/d/5f8a3b2c1d9e4f7a8b9c0d1e2f3a4b5c{NC}")
    print(f"    {DIM}?rtp=1&app=word&sk=u76b8a9c0d1e2f3a4b5c6d7e8f9a0b1c2{NC}")
    print()
    print(f"  {RED}✗{NC}  НЕ короткая /i/... — она НЕ открывает комнату")
    print(f"  {RED}✗{NC}  НЕ обрезанная ссылка без хвоста ?...&sk=...")
    print(f"  {DIM}Где взять: открыть документ → «Поделиться» → скопировать{NC}")
    print(f"  {DIM}ПОЛНУЮ ссылку (с /edit/d/ и хвостом &sk=...).{NC}")
    print()
    print(f"  {DIM}Ссылка = СЕКРЕТ (док публичный). Заведите отдельный документ{NC}")
    print(f"  {DIM}и отдельный Яндекс-аккаунт (рекомендация upstream).{NC}")
    print(f"  {DIM}Отмена: Ctrl+C или Esc затем Enter — назад в меню{NC}")
    while True:
        try:
            url = _ask(f"{CYAN}URL: {NC}")
        except _Cancelled:
            return None
        ok, why = _validate_doc_url(url, transport)
        if ok:
            return url
        print(f"  {RED}✗{NC}  {why}")
        if "/i/" in url:
            print(f"  {DIM}Откройте документ → «Поделиться» → полная ссылка"
                  f" на редактирование, скопируйте её (с /edit/d/).{NC}")


def _run_install(cli_transport: Optional[str] = None,
                 use_main: bool = False, raw_mode: bool = False,
                 cli_url: Optional[str] = None) -> None:
    """Полный установочный флоу. Идемпотентен: переустановка поверх
    живой ноды сохраняет doc-URL/ключ из state (если юзер не сменил)."""
    _box_top("OPENFLUX  •  УСТАНОВКА EXIT-НОДЫ")
    _box_row()
    _box_info("Канал через легитимные РУ-сервисы: клиент → Яндекс → эта VPS → мир")
    _box_row()

    old = proto_load_state(_MODULE_STATE)

    # 1. Транспорт
    transport = _ask_transport(cli_transport)
    if transport is None:
        _box_err("Транспорт не выбран — отмена")
        _box_bot(); _pause(); return

    # 2. Doc-URL (CLI-флаг бьёт интерактив; cups/oneme URL не нужен)
    if cli_url is not None:
        ok, why = _validate_doc_url(cli_url, transport)
        if not ok:
            _box_err(f"--url: {why}")
            _box_bot(); _pause(); return
        doc_url = cli_url.strip()
    else:
        doc_url = _ask_doc_url(transport)
    if doc_url is None:
        _box_err("URL не получен — отмена")
        _box_bot(); _pause(); return
    if not doc_url and old.get("doc_url") and \
            old.get("transport") == transport:
        doc_url = old["doc_url"]
        _box_info("Взят URL из прошлой установки (state)")

    # 3. Свежий main vs пин
    if not use_main and not cli_transport:
        try:
            pick = _ask(
                f"{CYAN}Версия [1=verified {_PINNED_COMMIT[:7]} / 2=main]: {NC}",
                default="1")
        except _Cancelled:
            _box_err("Отмена — назад в меню")
            _box_bot(); _pause(); return
        use_main = pick == "2"
    if use_main:
        _box_warn("main-ветка: свежие фиксы, но без гарантии мануала")

    _box_sep()

    # 4. Go
    _box_info("Тулчейн: Go ≥ 1.26.4")
    gover = _ensure_go()
    if gover is None:
        _box_err("Go не установлен — ставьте: snap install go --classic")
        _box_bot(); _pause(); return
    _box_ok(f"Go: {gover.split(' go')[-1].strip()}")
    _box_row()

    # 5. Исходники (tarball через download_manager)
    _box_info("Исходники OpenFlux (download_manager: codeload → gh-proxy)")
    commit = _fetch_sources(use_main=use_main)
    if commit is None:
        _box_err("Не удалось скачать исходники (зеркала и /root провалились)")
        _box_info("Подсказка с URL для ручной загрузки — выше;"
                  " положите tarball в /root/ и повторите")
        _box_bot(); _pause(); return
    _box_ok(f"Исходники: {commit[:12]}" + (" (verified-пин)"
            if not use_main else " (main)"))
    _box_row()

    # 6. Сборка
    _box_info("Сборка universal-bypass-tool")
    if not _build_binary():
        _box_bot(); _pause(); return
    _box_ok("Бинарник собран")
    _box_row()

    # 7. Юзер + ключ + env
    _ensure_openflux_user()
    key = old.get("transport_key") if old.get("transport_key") else \
        _gen_transport_key()
    _write_key_file(key)
    _write_env(doc_url, transport)
    _box_ok("E2E-ключ AES-256-GCM: /etc/openflux/transport.key")
    _box_row()

    # 8. Сервис
    local_ip = ""
    if raw_mode:
        try:
            local_ip = _ask(f"{CYAN}Egress IP для raw-режима "
                            f"[{_get_server_ip()}]: {NC}",
                            default=_get_server_ip())
        except _Cancelled:
            _box_err("Отмена — назад в меню")
            _box_bot(); _pause(); return
    _install_service(transport, raw_mode=raw_mode, local_ip=local_ip)
    _run(["systemctl", "restart", _SERVICE_NAME])
    time.sleep(4)

    ok, detail = _health_check()
    if ok:
        _box_ok("Сервис активен")
        for ln in (detail or "").splitlines()[:3]:
            if ln.strip():
                _box_log_line(ln.strip()[:100])
    else:
        _box_warn("Сервис стартует с задержкой — журнал:")
        for ln in (detail or "").splitlines()[-6:]:
            if ln.strip():
                _box_log_line(ln.strip()[:100])

    # 9. State + бандл
    proto_save_state(_MODULE_STATE, {
        "transport": transport,
        "doc_url": doc_url,
        "transport_key": key,
        "commit": commit,
        "pinned": not use_main,
        "raw_mode": raw_mode,
        "local_ip": local_ip,
        "installed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        # bridge-поля: наследуются при переустановке
        "bridge_active": bool(old.get("bridge_active")),
        "bridge_bind": old.get("bridge_bind", _DEFAULT_BRIDGE_BIND),
        "bridge_port": old.get("bridge_port"),
    }, name="openflux.json")

    server_ip = _get_server_ip()
    _BUNDLE_FILE.write_text(
        _render_client_bundle(doc_url, transport, key, server_ip),
        encoding="utf-8")
    _BUNDLE_FILE.chmod(0o600)

    _box_sep()
    _box_ok("Клиентский бандл: /etc/openflux/client-bundle.txt")
    _box_info("Экспорт в меню → [2] Клиентские конфиги")
    if transport == "cupsonline":
        _box_info("Cups: комнаты создаёт exit — секрет сессии в journalctl")
    _box_row()
    _box_info("Проверка канала (с клиента):")
    _box_log_line("curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org")
    _box_bot()
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  ЭКСПОРТ КЛИЕНТСКИХ КОНФИГОВ
# ══════════════════════════════════════════════════════════════════════════════

def _export_client_configs() -> None:
    """Печать клиентского бандла. Урок длинные строки (URL с &sk=)
    ПОЗАДИ рамок — бордюры не рвутся, копирование одним куском."""
    st = proto_load_state(_MODULE_STATE)
    doc_url = st.get("doc_url", "")
    transport = st.get("transport", "yandex")
    key = st.get("transport_key", "")
    if not doc_url or not key:
        print(f"  {RED}✗{NC}  Нет state/ключа — сначала установка")
        _pause(); return

    server_ip = _get_server_ip()
    bundle = _render_client_bundle(doc_url, transport, key, server_ip)
    _BUNDLE_FILE.write_text(bundle, encoding="utf-8")
    _BUNDLE_FILE.chmod(0o600)

    _box_top("OPENFLUX  •  КЛИЕНТСКИЕ КОНФИГИ")
    _box_row()
    _box_kv("Носитель:", transport)
    _box_kv("Бандл:", "/etc/openflux/client-bundle.txt")
    _box_row()
    _box_info("Ниже — команды для запуска клиента (вне рамок,")
    _box_info("чтобы URL и ключ копировались целиком):")
    _box_bot()
    print()
    print(bundle)
    print(f"  {DIM}Бандл также сохранён: {_BUNDLE_FILE} (chmod 600){NC}")
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  BRIDGE-РЕЖИМ: клиент OpenFlux НА ЭТОЙ VPS (SOCKS5 для цепочек)
# ══════════════════════════════════════════════════════════════════════════════

def _ask_bridge_bind(cli_bind: Optional[str] = None) -> Optional[str]:
    """bind SOCKS5: loopback (по умолчанию) или все интерфейсы."""
    if cli_bind:
        bind = cli_bind.strip()
        if bind not in ("127.0.0.1", "0.0.0.0", "::1", "::", "localhost"):
            print(f"  {RED}✗{NC}  --bind: ожидается 127.0.0.1 | 0.0.0.0")
            return None
        return bind
    print()
    print(f"  {CYAN}Где слушать SOCKS5 (bind):{NC}")
    print(f"   {DIM}[{NC}{WHITE}{BOLD}1{NC}{DIM}]{NC} 127.0.0.1 — только эта VPS "
          f"(рекомендуется: цепочки Xray/mihomo локально)")
    print(f"   {DIM}[{NC}{WHITE}{BOLD}2{NC}{DIM}]{NC} 0.0.0.0 — все интерфейсы"
          f" (откроет UFW; SOCKS5 БЕЗ аутентификации!)")
    try:
        pick = _ask(f"{CYAN}Выбор [1]: {NC}", default="1")
    except _Cancelled:
        return None
    return "0.0.0.0" if pick == "2" else _DEFAULT_BRIDGE_BIND


def _ask_bridge_port(cli_port: Optional[int] = None) -> Optional[int]:
    """Порт SOCKS5 с валидацией. None = отмена/ошибка."""
    if cli_port is not None:
        if not (isinstance(cli_port, int) and 1 <= cli_port <= 65535):
            print(f"  {RED}✗{NC}  --port: число 1-65535")
            return None
        return cli_port
    while True:
        try:
            raw = _ask(
                f"{CYAN}SOCKS5 порт [{_DEFAULT_BRIDGE_PORT}]: {NC}",
                default=str(_DEFAULT_BRIDGE_PORT))
        except _Cancelled:
            return None
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            return int(raw)
        print(f"  {YELLOW}⚠{NC}  порт — число 1-65535")


def _render_bridge_mihomo_fragment(port: int) -> str:
    """Фрагмент proxies для mihomo/Хray-цепочек НА ЭТОМ сервере: узел
    через bridge (локальный SOCKS5). Наружу секретов не несёт."""
    return (
        "  # 🛟 OpenFlux bridge — carrier-канал с этой VPS\n"
        "  # (порт зарегистрирован в port_registry как openflux_bridge)\n"
        "  - name: \"🛟 OpenFlux (bridge)\"\n"
        "    type: socks5\n"
        "    server: 127.0.0.1\n"
        f"    port: {port}\n"
        "    udp: false\n"
    )


def _bridge_setup(cli_bind: Optional[str] = None,
                  cli_port: Optional[int] = None) -> None:
    """Настройка + запуск bridge: port-цикл (проверка → регистрация
    → UFW), юнит, state. Конфликт порта → предложение другого."""
    st = proto_load_state(_MODULE_STATE)
    if not st.get("doc_url") or not _BIN.exists():
        _box_top("OPENFLUX  •  BRIDGE")
        _box_row()
        _box_err("Сначала установите exit-ноду (пункт 1)")
        _box_bot(); _pause(); return

    transport = st.get("transport", "yandex")
    _box_top("OPENFLUX  •  BRIDGE (SOCKS5 на этой VPS)")
    _box_row()
    _box_info("Клиент OpenFlux здесь: канал для цепочек Xray/mihomo")
    _box_info("на самом сервере (VPS-гибрид / узел «🛟 Гарантия»)")
    _box_row()

    bind = _ask_bridge_bind(cli_bind)
    if bind is None:
        _box_err("bind не выбран — отмена"); _box_bot(); _pause(); return

    # Порт + цикл конфликтов (требование занятость ПРОВЕРЯЕТСЯ)
    port = _ask_bridge_port(cli_port)
    if port is None:
        _box_err("Порт не задан — отмена"); _box_bot(); _pause(); return
    while True:
        ok, msg = _bridge_port_open(bind, port)
        if ok:
            _box_ok(f"Порт {port}/tcp: {msg}"
                    + ("; UFW открыт" if not _is_loopback_bind(bind)
                       and "UFW" not in msg else ""))
            break
        _box_err(f"Порт {port}/tcp ЗАНЯТ: {msg}")
        if cli_port is not None:
            _box_info("CLI-режим: смените порт флагом --port")
            _box_bot(); _pause(); return
        try:
            raw = _ask(f"{CYAN}Другой порт (Enter — отмена): {NC}",
                       default="")
        except _Cancelled:
            raw = ""
        if not raw or not raw.isdigit():
            _box_err("Отмена"); _box_bot(); _pause(); return
        port = int(raw)

    # env + unit + старт
    _ENV_DIR.mkdir(parents=True, exist_ok=True)
    _BRIDGE_ENV_FILE.write_text(
        _render_bridge_env_file(st["doc_url"], transport), encoding="utf-8")
    _BRIDGE_ENV_FILE.chmod(0o600)
    _ensure_openflux_user()
    _BRIDGE_SERVICE_FILE.write_text(
        _render_bridge_unit(bind, port, transport), encoding="utf-8")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "--now", _BRIDGE_SERVICE_NAME])
    time.sleep(3)

    if _bridge_svc_active() and _bridge_probe_listener(bind, port):
        _box_ok(f"Bridge активен: SOCKS5 {bind}:{port}")
    else:
        _box_warn("Bridge стартует с задержкой — см. статус/журнал")

    st["bridge_active"] = True
    st["bridge_bind"] = bind
    st["bridge_port"] = port
    proto_save_state(_MODULE_STATE, st, name="openflux.json")

    _box_sep()
    _box_info("Фрагмент для mihomo/Xray на этом сервере (вне рамок):")
    _box_bot()
    print()
    print(_render_bridge_mihomo_fragment(port), end="")
    print(f"  {DIM}curl --socks5-hostname 127.0.0.1:{port} https://api.ipify.org{NC}")
    print()
    _pause()


def _bridge_activate() -> None:
    """Повторная активация после деактивации: порт мог занять другой
    сервис, пока bridge стоял выключенным — проверяем заново."""
    st = proto_load_state(_MODULE_STATE)
    port = st.get("bridge_port")
    if not port:
        print(f"  {RED}✗{NC}  Bridge не настроен — пункт «Bridge» в меню")
        _pause(); return
    bind = st.get("bridge_bind", _DEFAULT_BRIDGE_BIND)
    ok, msg = _bridge_port_open(bind, port)
    if not ok:
        print(f"  {RED}✗{NC}  Порт {port}/tcp занят: {msg}")
        print(f"  {YELLOW}→{NC}  Перенастройте bridge с другим портом (меню)")
        _pause(); return
    _run(["systemctl", "enable", "--now", _BRIDGE_SERVICE_NAME])
    time.sleep(2)
    if _bridge_svc_active() and _bridge_probe_listener(bind, port):
        print(f"  {GREEN}✓{NC}  Bridge активен: {bind}:{port} ({msg})")
    else:
        print(f"  {YELLOW}⚠{NC}  Bridge стартует с задержкой — см. статус")
    st["bridge_active"] = True
    proto_save_state(_MODULE_STATE, st, name="openflux.json")
    _pause()


def _bridge_deactivate() -> None:
    """Деактивация bridge (требование порты ЗАКРЫВАЮТСЯ):
    stop/disable + UFW-правило снять + разрегистрация из реестра."""
    st = proto_load_state(_MODULE_STATE)
    port = st.get("bridge_port")
    if not port:
        print(f"  {RED}✗{NC}  Bridge не настроен")
        _pause(); return
    _run(["systemctl", "stop", _BRIDGE_SERVICE_NAME])
    _run(["systemctl", "disable", _BRIDGE_SERVICE_NAME])
    _bridge_port_close(port)
    st["bridge_active"] = False
    proto_save_state(_MODULE_STATE, st, name="openflux.json")
    print(f"  {GREEN}✓{NC}  Bridge остановлен: порт {port}/tcp закрыт"
          f" и разрегистрирован")
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  АКТИВАЦИЯ / ДЕАКТИВАЦИЯ ВСЕГО МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════

def _activate_services() -> None:
    """Запуск: exit (инбаундов нет — только исходящий WSS) + bridge
    (если настроен: проверка порта → регистрация → UFW)."""
    if not _is_installed():
        print(f"  {RED}✗{NC}  Не установлен"); _pause(); return
    _box_top("OPENFLUX  •  АКТИВАЦИЯ")
    _box_row()
    _run(["systemctl", "enable", "--now", _SERVICE_NAME])
    _box_ok("exit-нода запущена (исходящий канал, инбаундов нет)")
    st = proto_load_state(_MODULE_STATE)
    if st.get("bridge_port"):
        bind = st.get("bridge_bind", _DEFAULT_BRIDGE_BIND)
        port = st["bridge_port"]
        ok, msg = _bridge_port_open(bind, port)
        if ok:
            _run(["systemctl", "enable", "--now", _BRIDGE_SERVICE_NAME])
            _box_ok(f"bridge запущен: {bind}:{port} ({msg})")
            st["bridge_active"] = True
            proto_save_state(_MODULE_STATE, st, name="openflux.json")
        else:
            _box_err(f"bridge: порт {port}/tcp занят: {msg}")
            _box_info("Перенастройте bridge с другим портом")
    _box_bot(); _pause()


def _deactivate_services() -> None:
    """Остановка: bridge-порт закрывается и разрегистрируется, у exit
    ExecStopPost сам снимает scoped RST-rule raw-режима."""
    if not _is_installed():
        print(f"  {RED}✗{NC}  Не установлен"); _pause(); return
    _box_top("OPENFLUX  •  ДЕАКТИВАЦИЯ")
    _box_row()
    st = proto_load_state(_MODULE_STATE)
    if st.get("bridge_port"):
        _run(["systemctl", "stop", _BRIDGE_SERVICE_NAME])
        _run(["systemctl", "disable", _BRIDGE_SERVICE_NAME])
        _bridge_port_close(st["bridge_port"])
        _box_ok(f"bridge остановлен: порт {st['bridge_port']}/tcp закрыт"
                f" (UFW + реестр)")
        st["bridge_active"] = False
        proto_save_state(_MODULE_STATE, st, name="openflux.json")
    _run(["systemctl", "stop", _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    _box_ok("exit-нода остановлена (инбаундов не было; raw-RST снят"
            " через ExecStopPost)")
    _box_bot(); _pause()




def _rotate_key() -> None:
    st = proto_load_state(_MODULE_STATE)
    if not st:
        print(f"  {RED}✗{NC}  Не установлен"); _pause(); return
    new = _gen_transport_key()
    _write_key_file(new)
    st["transport_key"] = new
    proto_save_state(_MODULE_STATE, st, name="openflux.json")
    _run(["systemctl", "restart", _SERVICE_NAME])
    if st.get("bridge_active"):
        _run(["systemctl", "restart", _BRIDGE_SERVICE_NAME])
    _box_top("OPENFLUX  •  РОТАЦИЯ E2E-КЛЮЧА")
    _box_ok("Новый ключ записан, сервисы перезапущены")
    _box_warn("ВСЕ клиенты (и bridge) должны получить новый ключ")
    _box_bot(); _pause()


def _set_url() -> None:
    """Смена doc-URL = смена комнаты = ротация канала целиком
    (старый док можно удалить/закрыть). Bridge едет в ту же комнату —
    его env обновляется вместе с exit-нодой."""
    st = proto_load_state(_MODULE_STATE)
    if not st:
        print(f"  {RED}✗{NC}  Не установлен"); _pause(); return
    transport = st.get("transport", "yandex")
    url = _ask_doc_url(transport)
    if not url:
        print(f"  {DIM}отмена (Ctrl+C/Esc — без изменений){NC}")
        _pause()
        return
    _write_env(url, transport)
    st["doc_url"] = url
    if st.get("bridge_port"):
        _ENV_DIR.mkdir(parents=True, exist_ok=True)
        _BRIDGE_ENV_FILE.write_text(
            _render_bridge_env_file(url, transport), encoding="utf-8")
        _BRIDGE_ENV_FILE.chmod(0o600)
        if st.get("bridge_active"):
            _run(["systemctl", "restart", _BRIDGE_SERVICE_NAME])
    proto_save_state(_MODULE_STATE, st, name="openflux.json")
    _run(["systemctl", "restart", _SERVICE_NAME])
    _box_ok("URL сменён, сервисы перезапущены")
    _box_info("Клиенты (и bridge, если был) тоже переходят на новый URL")
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ ИСХОДНИКОВ
# ══════════════════════════════════════════════════════════════════════════════

def _update_sources() -> None:
    """Re-fetch tarball (тот же пин или main, как было) + rebuild +
    restart. State (URL/ключ/bridge) переживает обновление."""
    st = proto_load_state(_MODULE_STATE)
    if not st:
        print(f"  {RED}✗{NC}  Не установлен"); _pause(); return
    use_main = not st.get("pinned", True)
    _box_top("OPENFLUX  •  ОБНОВЛЕНИЕ ИСХОДНИКОВ")
    _box_info("download_manager re-fetch + rebuild + restart"
              " (URL/ключ/bridge сохраняются)")
    _box_row()
    commit = _fetch_sources(use_main=use_main)
    if commit is None:
        _box_err("Не удалось скачать исходники (зеркала и /root провалились)")
        _box_bot(); _pause(); return
    _box_ok(f"Исходники: {commit[:12]}")
    if not _build_binary():
        _box_bot(); _pause(); return
    _box_ok("Пересобрано")
    _run(["systemctl", "restart", _SERVICE_NAME])
    if st.get("bridge_active"):
        _run(["systemctl", "restart", _BRIDGE_SERVICE_NAME])
        _box_ok("bridge перезапущен")
    time.sleep(4)
    ok, _ = _health_check()
    _box_ok("Сервис активен" if ok else "Сервис перезапускается")
    st["commit"] = commit
    proto_save_state(_MODULE_STATE, st, name="openflux.json")
    _box_bot(); _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / ЛОГИ / СТОП-СТАРТ / УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════

def _show_status() -> None:
    st = proto_load_state(_MODULE_STATE)
    _box_top("OPENFLUX  •  СТАТУС")
    _box_row()
    if not _is_installed():
        _box_kv("Статус:", f"{YELLOW}● не установлен{NC}")
        _box_bot(); _pause(); return
    active = _svc_active()
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if active else f"{RED}● остановлен{NC}")
    _box_kv("Носитель:", str(st.get("transport", "—")))
    _box_kv("Режим:", "raw (root, RST-drop)" if st.get("raw_mode")
            else "proxy (unprivileged)")
    _box_kv("Инбаунды:", "нет — исходящий carrier-канал (port_registry)")
    _box_kv("Коммит:", str(st.get("commit", "—"))[:12] +
            (" пин" if st.get("pinned", True) else " main"))
    _box_kv("E2E-шифр:", f"{GREEN}вкл{NC} (AES-256-GCM)")
    _box_kv("Установлен:", str(st.get("installed_at", "—")))
    # bridge
    bport = st.get("bridge_port")
    if bport:
        bbind = st.get("bridge_bind", _DEFAULT_BRIDGE_BIND)
        if st.get("bridge_active"):
            listen = "слушает" if _bridge_probe_listener(bbind, bport) \
                else "поднимается"
            _box_kv("Bridge:", f"{GREEN}● активен{NC} {bbind}:{bport} ({listen})")
        else:
            _box_kv("Bridge:", f"{YELLOW}● настроен, остановлен{NC} "
                    f"({bbind}:{bport}; порт закрыт)")
    else:
        _box_kv("Bridge:", "не настроен (меню → Bridge)")
    _box_row(); _box_sep()
    _box_info("Последние строки журнала:")
    r = _run(["journalctl", "-u", _SERVICE_NAME, "-n", "12",
              "--no-pager"], capture=True)
    for ln in (r.stdout or "").splitlines():
        if ln.strip():
            _box_log_line(ln.strip()[:110])
    _box_bot(); _pause()


def _show_logs() -> None:
    if not _is_installed():
        print(f"  {RED}✗{NC}  Не установлен"); _pause(); return
    print(f"{DIM}journalctl -u {_SERVICE_NAME} -f — Ctrl+C для выхода{NC}\n")
    subprocess.run(["journalctl", "-u", _SERVICE_NAME, "-f", "--no-pager"])


def _restart_service() -> None:
    if not _is_installed():
        print(f"  {RED}✗{NC}  Не установлен"); _pause(); return
    _run(["systemctl", "restart", _SERVICE_NAME])
    time.sleep(3)
    ok, _ = _health_check()
    print(f"  {'✓' if ok else '⚠'}  openflux "
          f"{'перезапущен' if ok else 'перезапускается (см. статус)'}")
    time.sleep(1)


def _uninstall() -> None:
    try:
        if _ask(f"{RED}Точно удалить OpenFlux? "
                f"Введите YES: {NC}") != "YES":
            print("  отмена"); return
    except _Cancelled:
        print(f"  {DIM}отмена (Ctrl+C/Esc){NC}"); return
    st = proto_load_state(_MODULE_STATE)
    # bridge первым: stop + порт закрыть/разрегистрировать
    if st.get("bridge_port"):
        _run(["systemctl", "stop", _BRIDGE_SERVICE_NAME])
        _run(["systemctl", "disable", _BRIDGE_SERVICE_NAME])
        _bridge_port_close(st["bridge_port"])
        _BRIDGE_SERVICE_FILE.unlink(missing_ok=True)
        _BRIDGE_ENV_FILE.unlink(missing_ok=True)
        print(f"  {GREEN}✓{NC}  bridge: порт {st['bridge_port']}/tcp закрыт"
              f" (UFW + реестр), юнит убран")
    _run(["systemctl", "stop", _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    # raw-режим: снять возможный scoped RST-drop (мусор не оставляем)
    ip = st.get("local_ip") or ""
    if st.get("raw_mode") and ip:
        _run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags",
              "RST", "RST", "-s", ip, "-j", "DROP"])
    _SERVICE_FILE.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"])
    shutil.rmtree(_INSTALL_DIR, ignore_errors=True)
    shutil.rmtree(_ENV_DIR, ignore_errors=True)
    _MODULE_STATE.unlink(missing_ok=True)
    _run(["userdel", _SERVICE_USER])
    print(f"  {GREEN}✓{NC}  OpenFlux удалён (бинарник, env, ключ, state,"
          f" юзер; порты закрыты и разрегистрированы)")


# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════

def _show_guide() -> None:
    _box_top("OPENFLUX  •  ГАЙД")
    _box_row()
    _box_row(f"  {BOLD}Идея{NC}: клиентский трафик до exit-ноды едет внутри")
    _box_row(f"  легитимного РУ-сервиса. Провайдер видит: юзер работает")
    _box_row(f"  с Яндекс.Документами. Блокнуть, не поломав Яндекс, — трудно.")
    _box_row()
    _box_row(f"  {CYAN}Клиент{NC} (Windows/Linux/мобильный)")
    _box_row(f"    ↓ SOCKS5 127.0.0.1:1080 → gVisor TCP/IP-стек")
    _box_row(f"  {CYAN}Носитель{NC} (Яндекс.Документы / Волга / Cups)")
    _box_row(f"    ↓ WSS/HTTPS — обычный «домашний» трафик")
    _box_row(f"  {CYAN}Exit{NC} (эта VPS, proxy-режим, без root)")
    _box_row(f"    ↓ net.Dial")
    _box_row(f"  {CYAN}Интернет{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}Секретность{NC}")
    _box_row(f"  • doc-URL = ключ комнаты: док публичный по ссылке.")
    _box_row(f"    → e2e AES-256-GCM всегда вкл; ключ на обеих сторонах.")
    _box_row(f"    → отдельный Яндекс-аккаунт и «пустой» док под канал.")
    _box_row(f"  • Ротация: смена URL (новая комната) или ключа — из меню.")
    _box_row()
    _box_row(f"  {BOLD}Ограничения{NC}")
    _box_row(f"  • Только TCP/IPv4 внутри туннеля: браузинг/мессенджеры да,")
    _box_row(f"    QUIC/голос — нет (QUIC-блок в mihomo не мешает).")
    _box_row(f"  • Скорость зависит от носителя: курсорные сообщения —")
    _box_row(f"    медленно; Волга (батчи 4 МБ) — быстрее, но эксперимент.")
    _box_row(f"  • API Яндекса меняется — тогда «Обновить исходники».")
    _box_row()
    _box_row(f"  {BOLD}Роль во флоте{NC}")
    _box_row(f"  • Это НЕ замена VLESS/mieru — это канал «последней надежды»")
    _box_row(f"    на случай тотального зарезания международки/ино-IP.")
    _box_row(f"    В mihomo — узел «🛟 OpenFlux» последним в fallback.")
    _box_sep()
    _box_row(f"  {BOLD}Bridge — клиент на этой VPS{NC}")
    _box_row(f"  • OpenFlux-клиент поднимает SOCKS5 прямо на сервере:")
    _box_row(f"    цепочки Xray/mihomo на этой VPS могут ходить в carrier-")
    _box_row(f"    канал локально (127.0.0.1:1080) — VPS-гибрид без клиентов.")
    _box_row(f"  • ПОРТЫ — всё через port_registry: активация проверяет")
    _box_row(f"    занятость (реестр + ss-слушатели + чужие UFW-правила),")
    _box_row(f"    регистрирует порт, при 0.0.0.0 открывает UFW;")
    _box_row(f"    деактивация/удаление закрывают и разрегистрируют.")
    _box_row(f"  • Exit-нода инбаундов не имеет — её порт-цикл пуст.")
    _box_row(f"  • 0.0.0.0 = SOCKS5 без аутентификации наружу — только если")
    _box_row(f"    понимаете риск; по умолчанию loopback.")
    _box_bot()
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════

def do_openflux_menu() -> None:
    """Точка входа из _core.py (пункт 17 главного меню)."""
    while True:
        os.system("clear")
        installed = _is_installed()
        state = proto_load_state(_MODULE_STATE)
        active = _svc_active()

        svc_str = (f"{GREEN}● активен{NC}" if active else
                   f"{RED}● остановлен{NC}" if installed else
                   f"{YELLOW}● не установлен{NC}")

        _box_top("OPENFLUX  •  канал через Яндекс.Документы")
        _box_row()
        _box_kv("Статус:", svc_str)
        if installed:
            _box_kv("Носитель:", str(state.get("transport", "—")))
            _box_kv("Режим:", "raw" if state.get("raw_mode") else "proxy")
            _box_kv("E2E-шифр:", f"{GREEN}AES-256-GCM{NC}")
            commit = str(state.get("commit", "—"))
            _box_kv("Версия:", commit[:12] +
                    (f" {DIM}пин{NC}" if state.get("pinned", True)
                     else f" {DIM}main{NC}"))
            bport = state.get("bridge_port")
            if bport:
                if state.get("bridge_active"):
                    _box_kv("Bridge:", f"{GREEN}● активен{NC} "
                            f"{state.get('bridge_bind', _DEFAULT_BRIDGE_BIND)}:"
                            f"{bport}")
                else:
                    _box_kv("Bridge:", f"{YELLOW}● настроен, остановлен{NC}")
        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить exit-ноду")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "📤  Клиентские конфиги (бандл)")
            _box_item("3", "🌉  Bridge: SOCKS5 на этой VPS (настроить)")
            _box_item("4", "▶️   Активировать (запустить всё)")
            _box_item("5", "⏹   Деактивировать (остановить, порты закрыть)")
            _box_item("6", "📊  Статус / журнал")
            _box_item("7", "🔑  Ротация e2e-ключа")
            _box_item("8", "🔗  Сменить doc-URL (ротация комнаты)")
            _box_item("9", "⬆️  Обновить исходники (re-fetch+rebuild)")
            _box_sep()
            _box_item("0", f"{RED}🗑️   Удалить OpenFlux{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает, секретность, ограничения")
        _box_sep()
        _box_item("Q", "← Назад в главное меню")
        _box_bot()
        print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}").strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()
        elif ch == "2" and installed:
            _export_client_configs()
        elif ch == "3" and installed:
            _bridge_setup()
        elif ch == "4" and installed:
            _activate_services()
        elif ch == "5" and installed:
            _deactivate_services()
        elif ch == "6" and installed:
            _show_status()
        elif ch == "7" and installed:
            _rotate_key()
        elif ch == "8" and installed:
            _set_url()
        elif ch == "9" and installed:
            _update_sources()
        elif ch == "0" and installed:
            _uninstall()
        elif ch == "g":
            _show_guide()
        elif ch == "q":
            break


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(
        prog="openflux",
        description="OpenFlux exit-node + bridge management (Chimera satellite #6)")
    p.add_argument("action", choices=[
        "install", "status", "logs", "restart", "export", "rotate-key",
        "set-url", "update", "uninstall", "menu",
        "bridge-on", "bridge-off", "activate", "deactivate"])
    p.add_argument("--transport", default=None,
                   choices=list(_TRANSPORTS),
                   help="носитель: yandex (default) | vyandex | cupsonline | oneme")
    p.add_argument("--main", action="store_true",
                   help="install/update: свежий main вместо verified-пина")
    p.add_argument("--raw", action="store_true",
                   help="install: raw-режим (root, RST-drop) вместо proxy")
    p.add_argument("--url", default=None,
                   help="install/set-url: doc-URL без интерактива")
    p.add_argument("--bind", default=None,
                   help="bridge-on: 127.0.0.1 (default) | 0.0.0.0")
    p.add_argument("--port", type=int, default=None,
                   help="bridge-on: SOCKS5-порт (default 1080; проверяется"
                        " занятость через port_registry)")
    args = p.parse_args(argv)

    if args.action == "menu":
        do_openflux_menu()
        return 0
    if args.action == "install":
        _run_install(cli_transport=args.transport, use_main=args.main,
                     raw_mode=args.raw, cli_url=args.url)
        return 0
    if args.action == "status":
        _show_status()
        return 0
    if args.action == "logs":
        _show_logs()
        return 0
    if args.action == "restart":
        _restart_service()
        return 0
    if args.action == "export":
        _export_client_configs()
        return 0
    if args.action == "rotate-key":
        _rotate_key()
        return 0
    if args.action == "set-url":
        _set_url()
        return 0
    if args.action == "update":
        _update_sources()
        return 0
    if args.action == "uninstall":
        _uninstall()
        return 0
    if args.action == "bridge-on":
        _bridge_setup(cli_bind=args.bind, cli_port=args.port)
        return 0
    if args.action == "bridge-off":
        _bridge_deactivate()
        return 0
    if args.action == "activate":
        _activate_services()
        return 0
    if args.action == "deactivate":
        _deactivate_services()
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
