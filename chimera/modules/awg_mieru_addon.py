#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
awg_mieru_addon.py — надстройка «AWG 3.1 поверх Mieru» (UDP-мост SOCKS5).

Идея: внешний клиент подключается к Entry-ноде по Mieru (mita, TCP+mTLS,
без TLS ClientHello вообще — нечему «маячить» MLKEM768/SNI/JA3), а полезная
нагрузка — датаграммы AmneziaWG 3.1 — едут внутри mieru-сессии через SOCKS5
UDP ASSOCIATE и прибывают на штатный awg0 Entry-ноды. Дальше работает
обычный AWG-каскад (RU вход → зарубежные выходы) без единого изменения.

Схема (клиент):

    [Клиент]
      AWG-клиент (awg-client.conf, Endpoint = 127.0.0.1:<gw_port>, MTU 1100)
        │ UDP (стандартные датаграммы AWG 3.1, локально)
        ▼
      mieru-udp-gw.py — UDP→SOCKS5(UDP ASSOCIATE) мост (этот репозиторий,
        только stdlib; цель зашита: <entry>:<awg_port>)
        │ SOCKS5 UDP ASSOCIATE
        ▼
      mieru-клиент (mieru-client.json, socks5Port 127.0.0.1:25199)
        │ TCP :2012, mTLS + padding, НЕТ TLS-отпечатка на проводе
    [Entry RU]
      mita (уже развёрнут standalone-Mieru) → UDP → awg0 (:45915/udp)
        → обычный AWG-каскад → выходы

Почему это работает: сервер WireGuard/AWG отвечает пиру по адресу последней
валидной датаграммы (endpoint roaming — штатное поведение). mita держит
UDP-сокет на время ассоциации → awg0 видит «пира с адресом mita» и спокойно
работает. NAT-маппинг живёт, пока жива mieru-сессия; PersistentKeepalive=25
в клиентском конфиге держит её тонкой.

Живая валидация (02.11.2026, vds13195): mita 3.38.0 принимает UDP ASSOCIATE
и релеит датаграммы вплоть до 127.0.0.1 и до собственного публичного IP
(порт awg0) — TCP CONNECT и UDP echo подтверждены end-to-end. Схема
клиентского mieru-профиля (profileName / user{name,password} /
servers[].portBindings[{port,protocol}] / socks5Port) сверена оракулом
`mieru replace config` на реальном бинарнике.

Что НЕ меняет аддон на сервере:
  • awg0, AWG-каскад, mita, порты, firewall — ноль изменений;
  • добавляются только: пир в awg- state (обычный awg_peer_add) и mita-юзер
    awg_<имя> (обычная регенерация server.json через mieru._build_server_config).

Компромиссы (честно, см. README в бандле):
  • TCP-over-TCP для TCP-нагрузки внутри туннеля (браузение — терпимо,
    торренты — плохо); UDP-нагрузка страдает меньше;
  • MTU клиента занижен до 1100 (mieru MTU 1400 − padding − заголовки,
    консервативно как AWG31_MTU в wpp_awg);
  • +1 уровень шифрования и мультиплексирование сессий mieru.

Использование (CLI, сервер):
    sudo python3 awg_mieru_addon.py --status
    sudo python3 awg_mieru_addon.py --issue alice
    sudo python3 awg_mieru_addon.py --issue alice --gw-port 51820 --entry 1.2.3.4
    sudo python3 awg_mieru_addon.py --regen alice
    sudo python3 awg_mieru_addon.py --revoke alice
    sudo python3 awg_mieru_addon.py --list
    sudo python3 awg_mieru_addon.py --rollback-all

TUI: меню управления пирами AWG → пункт [M] (do_awg_mieru_menu).

Не требует pip — только стандартная библиотека Python (как hybrid_addon).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from datetime import datetime
from pathlib import Path

# Прямой запуск файла (sudo python3 awg_mieru_addon.py --status): sys.path[0]
# указывает на chimera/modules/, пакета chimera рядом нет → ленивые импорты
# chimera.modules.* падали («No module named 'chimera'», фикс после смоука на
# vds13195 02.11). Кладём корень репо в sys.path. При штатном импорте как
# chimera.modules.awg_mieru_addon (TUI через main.py) __package__ задан — no-op.
if not __package__:
    _REPO_ROOT = str(Path(__file__).resolve().parents[2])
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════

_STATE_FILE   = Path("/var/lib/xray-installer/awg_mieru.json")
_BUNDLE_DIR   = Path("/root/awg-mieru")
_STATE_SCHEMA = 1

# Клиентские дефолты (живут на машине КЛИЕНТА, не сервера):
#   gw_port    — где мост слушает UDP для AWG (Endpoint клиента);
#   socks_port — где mieru-клиент поднимает SOCKS5 (socks5Port профиля).
# 25199/25181 не конфликтуют с каскадными портами нод.
_DEFAULT_GW_PORT    = 51820
_DEFAULT_SOCKS_PORT = 25199
# MTU клиента: mieru MTU 1400 − padding (до 128) − UDP/IP заголовки →
# консервативно 1100 (то же значение, что AWG31_MTU в wpp_awg: «kept below
# the IPv6 minimum path MTU even in the worst generated profile»).
_CLIENT_MTU = 1100

_RE_CLIENT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")

# ══════════════════════════════════════════════════════════════════════════════
#  СТИЛЬ ВЫВОДА (копия алгоритмов box_renderer, как в hybrid_addon / mieru —
#  самостоятельный CLI не тянет chimera-пакет на верхнем уровне импорта)
# ══════════════════════════════════════════════════════════════════════════════

def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED="\033[31m", GREEN="\033[32m", YELLOW="\033[33m",
            CYAN="\033[36m", BOLD="\033[1m", DIM="\033[2m", NC="\033[0m",
        )
    return {k: "" for k in ("RED", "GREEN", "YELLOW", "CYAN", "BOLD", "DIM", "NC")}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C["RED"], _C["GREEN"], _C["YELLOW"], _C["CYAN"], _C["BOLD"], _C["DIM"], _C["NC"],
)

_BOX_W = 66


def _plain(s: str) -> str:
    """Убирает ANSI-коды для корректного расчёта ширины."""
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _wcslen(s: str) -> int:
    n = 0
    for ch in s:
        if unicodedata.east_asian_width(ch) in ("W", "F"):
            n += 2
        elif unicodedata.combining(ch):
            continue
        else:
            n += 1
    return n


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _wcslen(text))


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        _box_row(f"{BOLD}{title}{NC}")


def _box_row(text: str = "") -> None:
    p = _plain(text)
    overflow = _wcslen(p) - _BOX_W
    if overflow > 0:
        cut = len(p) - overflow
        while cut > 0 and _wcslen(p[:cut]) > _BOX_W:
            cut -= 1
        text = text[:cut]
        p = p[:cut]
    print(f"{CYAN}║{_pad(text, _BOX_W)}║{NC}")


def _box_bottom() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")


def _box_item(key: str, label: str) -> None:
    _box_row(f"  [{key}] {label}")


def _box_kv(key: str, val: str, kw: int = 24) -> None:
    _box_row(f"  {_pad(key, kw)}{val}")


def box_header(title: str) -> None:
    print()
    _box_top(title)
    _box_row()


def c_cyan(msg: str) -> None:
    print(f"{CYAN}{msg}{NC}")


def c_green(msg: str) -> None:
    print(f"{GREEN}{msg}{NC}")


def c_red(msg: str) -> None:
    print(f"{RED}{msg}{NC}")


def c_yellow(msg: str) -> None:
    print(f"{YELLOW}{msg}{NC}")


def die(msg: str, code: int = 1) -> None:
    _box_bottom()
    c_red(msg)
    sys.exit(code)


def confirm(prompt: str) -> bool:
    try:
        return input(f"{YELLOW}{prompt} [y/N]:{NC} ").strip().lower() in ("y", "yes", "д", "да")
    except (EOFError, KeyboardInterrupt):
        return False


def _log(level: str, msg: str) -> None:
    """Лог в /var/log/chimera.log (если каталог есть), тихо иначе."""
    try:
        d = Path("/var/log")
        if d.is_dir():
            with open(d / "chimera.log", "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat(timespec='seconds')} "
                        f"[awg_mieru_addon] {level}: {msg}\n")
    except Exception:
        pass


def require_root() -> None:
    if os.geteuid() != 0:
        print(f"{RED}Запусти от root (sudo).{NC}")
        sys.exit(1)


def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


# ══════════════════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════════════════

def state_load() -> dict:
    if not _STATE_FILE.exists():
        return {"schema": _STATE_SCHEMA, "clients": []}
    try:
        d = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"schema": _STATE_SCHEMA, "clients": []}
    d.setdefault("schema", _STATE_SCHEMA)
    d.setdefault("clients", [])
    return d


def state_save(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    _STATE_FILE.chmod(0o600)


def client_find(state: dict, name: str) -> dict | None:
    for c in state.get("clients", []):
        if c.get("name") == name:
            return c
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  ЛЕНИВЫЕ ИМПОРТЫ CHIMERA (нулевая стоимость при standalone-запуске)
# ══════════════════════════════════════════════════════════════════════════════

def _mieru_mod():
    from chimera.modules import mieru
    return mieru


def _awg_api():
    """(awg_peer_add, awg_peer_remove, peer_find, state_load) из awg_peers/awg_state."""
    from chimera.modules.awg_peers import awg_peer_add, awg_peer_remove
    from chimera.modules.awg_state import awgs_state_load, awgs_state_peer_find
    return awg_peer_add, awg_peer_remove, awgs_state_peer_find, awgs_state_load


# ══════════════════════════════════════════════════════════════════════════════
#  MITA-ЮЗЕРЫ (reuse примитивов mieru.py — регенерация server.json + рестарт)
# ══════════════════════════════════════════════════════════════════════════════

def _mita_regenerate(mieru_mod, state: dict) -> bool:
    """Перегенерировать /etc/mita/server.json из mieru-state и перезапустить mita.
    Зеркалит ensure_user_full/_delete_user из mieru.py (те же примитивы)."""
    users = state.get("users", [])
    tp_name = state.get("traffic_preset", "basic")
    tp_config = mieru_mod._MIERU_TRAFFIC_PRESETS.get(tp_name, {}).get("config")
    cfg = mieru_mod._build_server_config(
        users,
        state.get("port_start", mieru_mod._DEFAULT_PORT_START),
        state.get("port_end",   mieru_mod._DEFAULT_PORT_END),
        state.get("protocol",   mieru_mod._DEFAULT_PROTOCOL),
        traffic_pattern=tp_config,
    )
    err = mieru_mod._apply_server_config(cfg)
    if err:
        c_red(f"mita: не удалось применить server.json: {err}")
        return False
    run(["systemctl", "reload-or-restart", mieru_mod._SERVICE_NAME])
    return True


def mita_user_add(username: str) -> str | None:
    """Создать mita-юзера (идемпотентно). Возвращает пароль (существующий или новый)."""
    m = _mieru_mod()
    state = m.proto_load_state(m._MODULE_STATE)
    users = state.get("users", [])
    for u in users:
        if u.get("username") == username:
            return u.get("password", "")
    password = m.proto_gen_password()
    users.append({"username": username, "password": password})
    state["users"] = users
    m.proto_save_state(m._MODULE_STATE, state)
    if not _mita_regenerate(m, state):
        return None
    return password


def mita_user_remove(username: str) -> bool:
    m = _mieru_mod()
    state = m.proto_load_state(m._MODULE_STATE)
    users = [u for u in state.get("users", []) if u.get("username") != username]
    if len(users) == len(state.get("users", [])):
        return True  # не было — идемпотентность
    state["users"] = users
    m.proto_save_state(m._MODULE_STATE, state)
    return _mita_regenerate(m, state)


# ══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ КОМПОНЕНТОВ БАНДЛА
# ══════════════════════════════════════════════════════════════════════════════

def _patch_awg_client_conf(conf_text: str, gw_port: int) -> str:
    """Endpoint → локальный мост, MTU → 1100. Остальное (I1-I5, 3.1-директивы,
    ключи, AllowedIPs, keepalive) — как выдал awgs_qr_build_client_conf."""
    conf_text = re.sub(r"(?m)^Endpoint\s*=.*$",
                       f"Endpoint = 127.0.0.1:{gw_port}", conf_text)
    conf_text = re.sub(r"(?m)^MTU\s*=.*$", f"MTU = {_CLIENT_MTU}", conf_text)
    header = (
        "# AWG 3.1 через mieru-обёртку (Chimera awg_mieru_addon).\n"
        "# Endpoint указывает на ЛОКАЛЬНЫЙ UDP-мост mieru-udp-gw.py —\n"
        "# сначала подними mieru-клиент и мост, потом awg-quick up.\n"
        "# MTU занижен до 1100: внутри mieru (MTU 1400 − padding − заголовки).\n"
    )
    return header + conf_text


def _build_mieru_profile(profile_name: str, username: str, password: str,
                         entry_addr: str, mita_port: int,
                         socks_port: int) -> dict:
    """Клиентский конфиг mieru. Схема сверена живым оракулом `mieru replace
    config` (vds13195, mieru 3.38.0, 02.11.2026) и end-to-end PoC TCP+UDP."""
    return {
        "activeProfile": profile_name,
        "profiles": [{
            "profileName": profile_name,
            "user": {"name": username, "password": password},
            "servers": [{
                "ipAddress": entry_addr,
                "portBindings": [{"port": mita_port, "protocol": "TCP"}],
            }],
        }],
        "socks5Port": socks_port,
        "loggingLevel": "INFO",
    }


# ── UDP→SOCKS5 мост (пишется в бандл как есть; только stdlib) ─────────────────

MIERU_UDP_GW_PY = r'''#!/usr/bin/env python3
"""mieru-udp-gw — UDP→SOCKS5(UDP ASSOCIATE) мост: AWG поверх mieru.

Слушает UDP (Endpoint AWG-клиента = 127.0.0.1:<listen>), каждую сессию
клиента оборачивает в SOCKS5 UDP ASSOCIATE на mieru-клиенте и доставляет
датаграммы на реальный <target> (Entry: порт awg0). Ответы возвращаются
обратно клиенту. Только стандартная библиотека Python 3.8+.

Запуск: python3 mieru-udp-gw.py --listen 127.0.0.1:51820 \
        --socks 127.0.0.1:25199 --target 203.0.113.10:45915
"""
import argparse
import selectors
import socket
import struct
import sys
import time


def parse_addr(s):
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"bad address {s!r}, want host:port")
    return host, int(port)


def socks5_associate(socks_addr):
    """UDP ASSOCIATE через mieru SOCKS5 (без авторизации на локальном хосте).
    Возвращает (tcp-канал управления, (relay_ip, relay_port))."""
    s = socket.create_connection(socks_addr, timeout=15)
    s.settimeout(15)
    s.sendall(b"\x05\x01\x00")                       # greeting: no auth
    r = s.recv(2)
    if r != b"\x05\x00":
        raise OSError(f"SOCKS5 greeting failed: {r!r}")
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")   # UDP ASSOCIATE
    hdr = b""
    while len(hdr) < 10:
        chunk = s.recv(10 - len(hdr))
        if not chunk:
            raise OSError("SOCKS5 associate: connection closed")
        hdr += chunk
    if hdr[1] != 0:
        raise OSError(f"SOCKS5 UDP ASSOCIATE rejected: rep={hdr[1]}")
    atyp = hdr[3]
    if atyp == 0x01:
        ip = socket.inet_ntoa(hdr[4:8])
        port = struct.unpack(">H", hdr[8:10])[0]
    else:
        raise OSError(f"SOCKS5 UDP ASSOCIATE: unexpected ATYP={atyp}")
    if ip in ("0.0.0.0", "::"):
        ip = socks_addr[0]
    s.settimeout(None)
    return s, (ip, port)


def unwrap_udp(datagram):
    """Снять SOCKS5 UDP-заголовок (RSV FRAG ATYP ADDR PORT). None — мусор."""
    if len(datagram) < 4 or datagram[0:2] != b"\x00\x00":
        return None
    frag = datagram[2]
    atyp = datagram[3]
    i = 4
    if atyp == 0x01:
        if len(datagram) < 10:
            return None
        i = 8
    elif atyp == 0x03:
        dl = datagram[4] if len(datagram) > 4 else 0
        i = 5 + dl
    elif atyp == 0x04:
        if len(datagram) < 22:
            return None
        i = 20
    else:
        return None
    if len(datagram) < i + 2 or frag != 0:
        return None
    return datagram[i + 2:]


class Session:
    """Одна ассоциация: клиентский addr → (TCP control, UDP relay socket)."""

    __slots__ = ("client_addr", "dst", "ctrl", "relay", "udp", "last")

    def __init__(self, client_addr, dst, socks_addr):
        self.client_addr = client_addr
        self.dst = dst
        self.ctrl, self.relay = socks5_associate(socks_addr)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.last = time.monotonic()

    def wrap(self, payload):
        return (b"\x00\x00\x00\x01" + socket.inet_aton(self.dst[0])
                + struct.pack(">H", self.dst[1]) + payload)

    def send(self, payload):
        self.udp.sendto(self.wrap(payload), self.relay)

    def close(self):
        for s in (self.ctrl, self.udp):
            try:
                s.close()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", default="127.0.0.1:51820",
                    help="UDP-адрес для AWG-клиента (default: 127.0.0.1:51820)")
    ap.add_argument("--socks", default="127.0.0.1:25199",
                    help="SOCKS5 mieru-клиента (default: 127.0.0.1:25199)")
    ap.add_argument("--target", required=True,
                    help="реальный Endpoint AWG host:port (Entry-нода)")
    ap.add_argument("--idle", type=int, default=180,
                    help="таймаут неактивной сессии, сек (default: 180)")
    args = ap.parse_args()

    listen_addr = parse_addr(args.listen)
    socks_addr = parse_addr(args.socks)
    dst = parse_addr(args.target)

    listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen.bind(listen_addr)

    sel = selectors.DefaultSelector()
    sel.register(listen, selectors.EVENT_READ, None)
    sessions = {}    # client_addr -> Session
    by_fd = {}       # udp fileno -> client_addr

    print(f"[mieru-udp-gw] {listen_addr[0]}:{listen_addr[1]} -> "
          f"socks5://{socks_addr[0]}:{socks_addr[1]} -> "
          f"{dst[0]}:{dst[1]}", flush=True)

    while True:
        for key, _ in sel.select(timeout=30):
            if key.fileobj is listen:
                payload, caddr = listen.recvfrom(65535)
                sess = sessions.get(caddr)
                if sess is None:
                    try:
                        sess = Session(caddr, dst, socks_addr)
                    except OSError as e:
                        print(f"[mieru-udp-gw] associate {caddr[0]}:{caddr[1]} "
                              f"FAIL: {e}", file=sys.stderr, flush=True)
                        continue
                    sessions[caddr] = sess
                    by_fd[sess.udp.fileno()] = caddr
                    sel.register(sess.udp, selectors.EVENT_READ, sess)
                    print(f"[mieru-udp-gw] session {caddr[0]}:{caddr[1]} -> "
                          f"relay {sess.relay[0]}:{sess.relay[1]}", flush=True)
                sess.last = time.monotonic()
                try:
                    sess.send(payload)
                except OSError as e:
                    print(f"[mieru-udp-gw] send {caddr}: {e}",
                          file=sys.stderr, flush=True)
            else:
                sess = key.data
                datagram, _ = sess.udp.recvfrom(65535)
                payload = unwrap_udp(datagram)
                if payload is None:
                    continue
                sess.last = time.monotonic()
                try:
                    listen.sendto(payload, sess.client_addr)
                except OSError:
                    pass

        # GC неактивных сессий (AWG keepalive=25с держит живые тёплыми)
        now = time.monotonic()
        for caddr, sess in list(sessions.items()):
            if now - sess.last > args.idle:
                sel.unregister(sess.udp)
                sess.close()
                del sessions[caddr]
                by_fd.pop(sess.udp.fileno(), None)
                print(f"[mieru-udp-gw] session {caddr[0]}:{caddr[1]} idle, "
                      f"closed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[mieru-udp-gw] stopped", file=sys.stderr)
'''

# ── README бандла ─────────────────────────────────────────────────────────────

def _build_readme(name: str, entry: str, mita_port: int, awg_port: int,
                  gw_port: int, socks_port: int) -> str:
    return f"""AWG 3.1 ЧЕРЕЗ MIERU — клиентский комплект «{name}»
════════════════════════════════════════════════════════════════

ЗАЧЕМ
  Сегмент «клиент → Entry» едет внутри mieru: TCP+mTLS+padding, БЕЗ TLS
  ClientHello — на проводе нет SNI/JA3/MLKEM768, нечего фрагментировать и
  нечему «маячить». UDP-квоты/шейпинг к этой ноге неприменимы (нога — TCP).
  AWG 3.1 (I1-I5, HeaderProtectionKey, padding, trailers) сохранён как есть.

СТЕК (порядок запуска важен)

  1. mieru-клиент     mieru-client.json   (socks5 на 127.0.0.1:{socks_port})
  2. UDP-мост         mieru-udp-gw.py     (127.0.0.1:{gw_port} → {entry}:{awg_port})
  3. AWG-клиент       awg-client.conf     (Endpoint = 127.0.0.1:{gw_port}, MTU 1100)

ФАЙЛЫ
  awg-client.conf    — конфиг AWG 3.1 (Endpoint уже ведёт на локальный мост)
  mieru-client.json  — профиль mieru (import/replace config)
  mieru-udp-gw.py    — мост UDP→SOCKS5 UDP ASSOCIATE (только Python 3.8+)
  start-linux.sh     — запуск всех трёх слоёв (Linux)
  start-windows.bat  — mieru + мост (Windows; AWG — импорт awg-client.conf
                       в Amnezia/любой AWG-клиент)

LINUX
  # 1) mieru (один раз):   mieru replace config mieru-client.json
  #    запуск:             mieru start
  # 2) мост:               python3 mieru-udp-gw.py --listen 127.0.0.1:{gw_port} \\
                            --socks 127.0.0.1:{socks_port} --target {entry}:{awg_port}
  # 3) туннель:            sudo awg-quick up ./awg-client.conf
  # остановка:             sudo awg-quick down ./awg-client.conf; mieru stop

WINDOWS
  1) mieru: установить приложение (github.com/enfein/mieru/releases), импортировать
     mieru-client.json (или CLI: mieru.exe replace config mieru-client.json;
     mieru.exe start)
  2) мост: python mieru-udp-gw.py --listen 127.0.0.1:{gw_port} ^
              --socks 127.0.0.1:{socks_port} --target {entry}:{awg_port}
  3) AWG: импортировать awg-client.conf (Amnezia / awg-quick под WSL)
  Или просто start-windows.bat (шаги 1-2).

НОРМАЛЬНО ЛИ, ЧТО МОСТ МОЛЧИТ
  Да. При подключении AWG печатает "session ... -> relay ..." на каждую
  клиентскую сессию. PersistentKeepalive=25 держит NAT тёплым.

КОМПРОМИССЫ (знать обязательно)
  • TCP-over-TCP: TCP-нагрузка ВНУТРИ туннеля едет в TCP-сессии mieru.
    Браузение — терпимо; торренты/массовые параллельные загрузки — плохо.
  • MTU 1100 (внутри mieru MTU 1400 минус padding/заголовки).
  • Синхронизация времени ±30 с (требование mieru).

ОТКАТ
  Вернуть Endpoint на {entry}:{awg_port} и MTU на 1280 в awg-client.conf —
  и это снова обычный AWG-конфиг, мост и mieru больше не нужны.
"""


def _build_start_linux(name: str, entry: str, awg_port: int,
                       gw_port: int, socks_port: int) -> str:
    return f"""#!/usr/bin/env bash
# AWG 3.1 через mieru — автозапуск стека «{name}» (Linux).
set -e
cd "$(dirname "$0")"

if ! mieru status >/dev/null 2>&1; then
    mieru replace config mieru-client.json
    mieru start
    sleep 2
fi

if ! pgrep -f mieru-udp-gw.py >/dev/null 2>&1; then
    nohup python3 mieru-udp-gw.py \\
        --listen 127.0.0.1:{gw_port} \\
        --socks 127.0.0.1:{socks_port} \\
        --target {entry}:{awg_port} > udp-gw.log 2>&1 &
    sleep 1
fi

sudo awg-quick up ./awg-client.conf
echo "OK: туннель «{name}» поднят (mieru -> мост -> AWG)."
"""


def _build_start_windows(name: str, entry: str, awg_port: int,
                         gw_port: int, socks_port: int) -> str:
    return f"""@echo off
rem AWG 3.1 через mieru — запуск mieru + моста («{name}»).
rem AWG-клиент: импортируй awg-client.conf в Amnezia (Endpoint уже = мост).

cd /d "%~dp0"

mieru status >nul 2>&1
if errorlevel 1 (
    mieru replace config mieru-client.json
    mieru start
    timeout /t 2 /nobreak >nul
)

tasklist /FI "IMAGENAME eq python.exe" | find /I "python.exe" >nul || (
    start "mieru-udp-gw" /MIN python mieru-udp-gw.py --listen 127.0.0.1:{gw_port} --socks 127.0.0.1:{socks_port} --target {entry}:{awg_port}
)

echo Мост запущен (127.0.0.1:{gw_port} -> {entry}:{awg_port} через mieru).
echo Теперь подключи AWG: конфиг awg-client.conf (Endpoint уже указывает на мост).
pause
"""


# ══════════════════════════════════════════════════════════════════════════════
#  ВЫДАЧА / ОТЗЫВ / РЕГЕН
# ══════════════════════════════════════════════════════════════════════════════

def _detect_entry_addr() -> str:
    """Адрес Entry для клиентского mieru-профиля. Приоритет: домен из
    настроек mieru (если задан), иначе публичный IP."""
    try:
        m = _mieru_mod()
        addr = m._effective_client_addr()
        if addr:
            return addr
    except Exception:
        pass
    try:
        r = run(["ip", "-4", "route", "get", "1.1.1.1"])
        m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", r.stdout or "")
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def prerequisites() -> dict:
    """Проверка подсистем: AWG standalone + Mieru (mita)."""
    info = {"awg": False, "mieru": False, "awg_port": 0, "mita_port": 0,
            "entry": "", "protocol_version": "", "mtu": 0, "error": ""}
    try:
        from chimera.modules.awg_state import awgs_state_is_installed, awgs_state_load
        if not awgs_state_is_installed():
            info["error"] = "AWG standalone не установлен (awg-quick@awg0)"
            return info
        st = awgs_state_load()
        info["awg"] = True
        info["awg_port"] = int(st.get("port", 0) or 0)
        info["protocol_version"] = st.get("protocol_version", "2.0")
        info["mtu"] = int(st.get("mtu", 1280) or 1280)
    except Exception as e:
        info["error"] = f"AWG state: {e}"
        return info
    try:
        m = _mieru_mod()
        if not m._is_installed():
            info["error"] += " Mieru (mita) не установлен"
            return info
        mstate = m.proto_load_state(m._MODULE_STATE)
        info["mieru"] = True
        info["mita_port"] = int(mstate.get("port_start", m._DEFAULT_PORT_START))
    except Exception as e:
        info["error"] += f" Mieru state: {e}"
        return info
    info["entry"] = _detect_entry_addr()
    return info


def _emit_bundle(rec: dict, peer: dict, awg_server_state: dict,
                 mita_username: str, mita_password: str) -> Path:
    """Собрать каталог /root/awg-mieru/<name>/ со всем комплектом."""
    name = rec["name"]
    bdir = _BUNDLE_DIR / name
    bdir.mkdir(parents=True, exist_ok=True)
    try:
        bdir.chmod(0o700)
    except OSError:
        pass

    # 1) AWG-конфиг: штатная сборка awgs_qr_build_client_conf + патч
    from chimera.modules.awg_qr import awgs_qr_build_client_conf
    conf_text = awgs_qr_build_client_conf(peer, awg_server_state)
    conf_text = _patch_awg_client_conf(conf_text, rec["gw_port"])
    p = bdir / "awg-client.conf"
    p.write_text(conf_text, encoding="utf-8")
    p.chmod(0o600)

    # 2) mieru-профиль (схема сверена живым оракулом mieru replace config)
    profile = _build_mieru_profile(
        f"awg-{name}", mita_username, mita_password,
        rec["entry_addr"], rec["mita_port"], rec["socks_port"])
    p = bdir / "mieru-client.json"
    p.write_text(json.dumps(profile, ensure_ascii=False, indent=2),
                 encoding="utf-8")
    p.chmod(0o600)

    # 3) мост
    p = bdir / "mieru-udp-gw.py"
    p.write_text(MIERU_UDP_GW_PY, encoding="utf-8")
    p.chmod(0o755)

    # 4) старт-скрипты + README
    p = bdir / "start-linux.sh"
    p.write_text(_build_start_linux(name, rec["entry_addr"], rec["awg_port"],
                                    rec["gw_port"], rec["socks_port"]),
                 encoding="utf-8")
    p.chmod(0o755)
    p = bdir / "start-windows.bat"
    p.write_text(_build_start_windows(name, rec["entry_addr"], rec["awg_port"],
                                      rec["gw_port"], rec["socks_port"]),
                 encoding="utf-8")
    p = bdir / "README.txt"
    p.write_text(_build_readme(name, rec["entry_addr"], rec["mita_port"],
                               rec["awg_port"], rec["gw_port"], rec["socks_port"]),
                 encoding="utf-8")
    return bdir


def issue_client(name: str, gw_port: int | None = None,
                 entry_addr: str | None = None,
                 socks_port: int = _DEFAULT_SOCKS_PORT) -> dict | None:
    """Полный цикл выдачи: AWG-пир + mita-юзер + бандл + state."""
    if not _RE_CLIENT_NAME.match(name or ""):
        c_red(f"Имя '{name}' невалидно: [A-Za-z][A-Za-z0-9_-]{{0,31}}.")
        return None

    pre = prerequisites()
    if not (pre["awg"] and pre["mieru"]):
        c_red(f"Предпосылки не выполнены: {pre['error'] or 'AWG/Mieru не готовы'}")
        return None
    entry = (entry_addr or "").strip() or pre["entry"]
    if not entry:
        c_red("Не удалось определить адрес Entry (IP/домен) — укажи --entry.")
        return None

    state = state_load()
    if client_find(state, name):
        c_red(f"Клиент '{name}' уже выдан (см. --list / --regen).")
        return None

    awg_peer_add, _awg_peer_remove, peer_find, awgs_state_load = _awg_api()

    # 1) mita-юзер awg_<name> (до пира — если mita упадёт, AWG не трогаем)
    mita_username = f"awg_{name}"
    mita_password = mita_user_add(mita_username)
    if not mita_password:
        c_red("Не удалось создать mita-юзера — выдача прервана, AWG не тронут.")
        return None

    # 2) AWG-пир
    if not awg_peer_add(name=name, expires="", psk=False, apply=True,
                        save_state=True, show_qr=False, owner_email=""):
        c_red("awg_peer_add не удался — откатываю mita-юзера.")
        mita_user_remove(mita_username)
        return None
    peer = peer_find(name)
    if not peer:
        c_red(f"Пир '{name}' не найден в awg-state после добавления (аномалия).")
        return None
    awg_server_state = awgs_state_load()

    # 3) запись + бандл
    used_gw = set(int(c.get("gw_port", 0)) for c in state["clients"])
    if gw_port is None:
        gw_port = _DEFAULT_GW_PORT
        while gw_port in used_gw:
            gw_port += 1
    rec = {
        "name": name,
        "mita_username": mita_username,
        "gw_port": gw_port,
        "socks_port": socks_port,
        "entry_addr": entry,
        "awg_port": pre["awg_port"],
        "mita_port": pre["mita_port"],
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    bdir = _emit_bundle(rec, peer, awg_server_state, mita_username, mita_password)

    state["clients"].append(rec)
    state_save(state)
    _log("SUCCESS", f"выдан клиент '{name}' (mita={mita_username}, gw={gw_port})")
    rec["bundle_dir"] = str(bdir)
    return rec


def regen_client(name: str, entry_addr: str | None = None) -> bool:
    """Пересобрать бандл из существующего state (смена IP Entry и т.п.)."""
    state = state_load()
    rec = client_find(state, name)
    if not rec:
        c_red(f"Клиент '{name}' не найден в state аддона.")
        return False
    pre = prerequisites()
    if not (pre["awg"] and pre["mieru"]):
        c_red(f"Предпосылки не выполнены: {pre['error']}")
        return False
    if entry_addr:
        rec["entry_addr"] = entry_addr.strip()
    rec["awg_port"] = pre["awg_port"] or rec["awg_port"]
    rec["mita_port"] = pre["mita_port"] or rec["mita_port"]

    _add, _rm, peer_find, awgs_state_load = _awg_api()
    peer = peer_find(name)
    if not peer:
        c_red(f"AWG-пир '{name}' не найден (удалён вручную?) — сначала --issue.")
        return False

    m = _mieru_mod()
    mstate = m.proto_load_state(m._MODULE_STATE)
    pwd = ""
    for u in mstate.get("users", []):
        if u.get("username") == rec["mita_username"]:
            pwd = u.get("password", "")
            break
    if not pwd:
        c_red(f"mita-юзер {rec['mita_username']} не найден — сначала --issue.")
        return False

    bdir = _emit_bundle(rec, peer, awgs_state_load(), rec["mita_username"], pwd)
    state_save(state)
    c_green(f"Бандл «{name}» пересобран: {bdir}")
    return True


def revoke_client(name: str) -> bool:
    """Отзыв: AWG-пир + mita-юзер + бандл + запись state."""
    state = state_load()
    rec = client_find(state, name)
    if not rec:
        c_red(f"Клиент '{name}' не найден в state аддона.")
        return False
    _add, awg_peer_remove, _find, _load = _awg_api()
    ok = True
    if not awg_peer_remove(name, apply=True, save_state=True):
        ok = False
        c_yellow(f"AWG-пир '{name}' не удалён (уже отсутствует?)")
    if not mita_user_remove(rec["mita_username"]):
        ok = False
        c_yellow(f"mita-юзер {rec['mita_username']} не удалён")
    bdir = _BUNDLE_DIR / name
    if bdir.exists():
        shutil.rmtree(bdir, ignore_errors=True)
    state["clients"] = [c for c in state["clients"] if c.get("name") != name]
    state_save(state)
    _log("SUCCESS" if ok else "WARNING", f"отозван клиент '{name}'")
    if ok:
        c_green(f"Клиент '{name}' отозван (пир, mita-юзер, бандл).")
    return ok


def rollback_all() -> None:
    state = state_load()
    clients = [c.get("name", "") for c in state.get("clients", [])]
    if not clients:
        c_cyan("Выданных клиентов нет — откатывать нечего.")
        return
    c_yellow(f"Будут отозваны все клиенты аддона: {', '.join(clients)}")
    if not confirm("Продолжить?"):
        c_cyan("Отменено.")
        return
    for name in clients:
        revoke_client(name)
    state_save({"schema": _STATE_SCHEMA, "clients": []})
    c_green("Rollback завершён: state аддона пуст.")


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / СПИСОК
# ══════════════════════════════════════════════════════════════════════════════

def show_status() -> None:
    pre = prerequisites()
    box_header("AWG × MIERU ADDON — СТАТУС")
    _box_kv("AWG standalone:", "OK" if pre["awg"] else "НЕТ", kw=20)
    if pre["awg"]:
        _box_kv("awg0 порт:", f"{pre['awg_port']}/udp", kw=20)
        _box_kv("протокол:", pre["protocol_version"], kw=20)
    _box_kv("Mieru (mita):", "OK" if pre["mieru"] else "НЕТ", kw=20)
    if pre["mieru"]:
        _box_kv("mita порт:", f"{pre['mita_port']}/tcp", kw=20)
    _box_kv("Entry (адрес):", pre["entry"] or "?", kw=20)
    state = state_load()
    _box_kv("Клиентов выдано:", str(len(state["clients"])), kw=20)
    if pre["error"]:
        _box_row()
        _box_row(f"  {RED}⚠ {pre['error']}{NC}")
    _box_row()
    _box_row(f"  {DIM}Сервер не требует изменений: mita уже релеит UDP до awg0.{NC}")
    _box_row(f"  {DIM}Живая валидация UDP ASSOCIATE → awg0-порт: 02.11.2026, vds13195.{NC}")
    _box_bottom()


def show_clients() -> None:
    state = state_load()
    box_header("AWG × MIERU — КЛИЕНТЫ")
    if not state["clients"]:
        _box_row(f"  {DIM}Пока никого (--issue NAME).{NC}")
    for c in state["clients"]:
        _box_row()
        _box_kv(f"{c['name']}:", f"gw={c['gw_port']} socks={c['socks_port']}", kw=18)
        _box_kv("", f"entry={c['entry_addr']} awg={c['awg_port']}", kw=18)
        _box_kv("", f"mita={c['mita_username']} @ {c['created_at']}", kw=18)
        _box_kv("", f"бандл: {_BUNDLE_DIR / c['name']}", kw=18)
    _box_bottom()


# ══════════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (вызывается из do_manage_awg_peers, пункт [M])
# ══════════════════════════════════════════════════════════════════════════════

def do_awg_mieru_menu() -> None:
    while True:
        os.system("clear")
        print()
        show_status()
        print()
        _box_top("AWG × MIERU — УПРАВЛЕНИЕ")
        _box_row()
        _box_item("1", "Выдать клиента (пир + mita-юзер + бандл)")
        _box_item("2", "Пересобрать бандл (смена IP/домена Entry)")
        _box_item("3", "Отозвать клиента")
        _box_item("4", "Список выданных")
        _box_item("Q", "Назад")
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == "1":
            try:
                name = input("Имя клиента ([A-Za-z][A-Za-z0-9_-]): ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if name:
                rec = issue_client(name)
                if rec:
                    c_green(f"Готово. Бандл: {rec['bundle_dir']}")
                    c_cyan("Передай клиенту КАТАЛОГ целиком (awg-client.conf + "
                           "mieru-client.json + mieru-udp-gw.py + start-* + README.txt).")
            input(f"{CYAN}Enter...{NC}")
        elif ch == "2":
            try:
                name = input("Имя клиента: ").strip()
                entry = input("Новый адрес Entry (пусто = как было): ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if name:
                regen_client(name, entry_addr=entry or None)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "3":
            try:
                name = input("Имя клиента для отзыва: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if name and confirm(f"Отозвать '{name}'?"):
                revoke_client(name)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "4":
            show_clients()
            input(f"{CYAN}Enter...{NC}")
        elif ch in ("q", ""):
            break


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWG 3.1 поверх Mieru (UDP-мост SOCKS5) — аддон Chimera")
    parser.add_argument("--status", action="store_true", help="статус подсистем")
    parser.add_argument("--issue", metavar="NAME", help="выдать клиента")
    parser.add_argument("--regen", metavar="NAME", help="пересобрать бандл клиента")
    parser.add_argument("--revoke", metavar="NAME", help="отозвать клиента")
    parser.add_argument("--list", action="store_true", help="список выданных")
    parser.add_argument("--rollback-all", action="store_true",
                        help="отозвать всех клиентов аддона")
    parser.add_argument("--gw-port", type=int, default=None,
                        help=f"UDP-порт моста на клиенте (default: {_DEFAULT_GW_PORT}+)")
    parser.add_argument("--socks-port", type=int, default=_DEFAULT_SOCKS_PORT,
                        help=f"socks5Port mieru-клиента (default: {_DEFAULT_SOCKS_PORT})")
    parser.add_argument("--entry", type=str, default=None,
                        help="адрес Entry (IP/домен) в mieru-профиле (default: автодетект)")
    args = parser.parse_args()

    require_root()

    if args.status:
        show_status()
        return
    if args.list:
        show_clients()
        return
    if args.rollback_all:
        rollback_all()
        return
    if args.issue:
        rec = issue_client(args.issue, gw_port=args.gw_port,
                           entry_addr=args.entry, socks_port=args.socks_port)
        if rec:
            box_header("AWG × MIERU — КЛИЕНТ ВЫДАН")
            _box_kv("Клиент:", rec["name"])
            _box_kv("Мост (клиент):", f"127.0.0.1:{rec['gw_port']}/udp", kw=22)
            _box_kv("mieru SOCKS5:", f"127.0.0.1:{rec['socks_port']}", kw=22)
            _box_kv("Entry:", f"{rec['entry_addr']}:{rec['awg_port']}/udp", kw=22)
            _box_kv("Бандл:", rec["bundle_dir"], kw=22)
            _box_row()
            _box_row(f"  {DIM}Передай клиенту каталог целиком; README внутри.{NC}")
            _box_bottom()
        else:
            sys.exit(1)
        return
    if args.regen:
        sys.exit(0 if regen_client(args.regen, entry_addr=args.entry) else 1)
    if args.revoke:
        sys.exit(0 if revoke_client(args.revoke) else 1)

    parser.print_help()


if __name__ == "__main__":
    main()
