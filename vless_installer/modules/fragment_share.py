"""
vless_installer/modules/fragment_share.py
───────────────────────────────────────────────────────────────────────────────
Временный HTTPS-сервер для доставки конфигов без scp (пункт 5).

Поднимает одноразовый HTTPS-сервер на случайном порту.
Генерирует QR-код со ссылкой — пользователь сканирует и скачивает
JSON-конфиг прямо на телефон без компьютера.

Особенности:
  • Самоподписанный TLS-сертификат (генерируется на лету через openssl)
  • Случайный порт в диапазоне 32000-45000
  • Токен в URL — конфиг доступен только по уникальной ссылке
  • Автоматическое завершение: после первого скачивания ИЛИ по таймауту
  • Таймаут по умолчанию: 10 минут
  • Открывает порт в firewall на время работы, закрывает после

ВАЖНО: серверный /etc/xray/config.json не затрагивается.

Публичное API:
    do_fragment_share_menu()  → Меню 2 → G (рядом с F)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import random
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [SHARE] [{level}] {_re.sub(chr(27)+'[0-9;]*m','',msg)}\n")
    except Exception:
        pass

def _info(msg): print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

# ── Импорты ────────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _get_box_width,
)

# ── Константы ─────────────────────────────────────────────────────────────
_STATE_FILE  = Path("/var/lib/xray-installer/state.json")
_FRAG_DIR    = Path("/var/lib/xray-installer/fragment_configs")
_PORT_RANGE  = (32000, 45000)
_TIMEOUT_SEC = 600  # 10 минут

# ── Получение внешнего IP ──────────────────────────────────────────────────
def _get_server_ip() -> str:
    """Возвращает публичный IP этого сервера."""
    import importlib
    try:
        core = importlib.import_module("vless_installer._core")
        return getattr(core, "get_server_ip")("4") or ""
    except Exception:
        pass
    # Fallback: локальный интерфейс
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""

# ── Генерация самоподписанного сертификата ────────────────────────────────
def _gen_self_signed_cert(tmp_dir: str, ip: str) -> tuple[str, str]:
    """
    Генерирует самоподписанный TLS-сертификат через openssl.
    Возвращает (cert_path, key_path).
    """
    cert = os.path.join(tmp_dir, "cert.pem")
    key  = os.path.join(tmp_dir, "key.pem")
    subj = f"/CN={ip}"
    san  = f"IP:{ip}" if ip else "IP:127.0.0.1"

    # openssl req + san через -addext (openssl >= 1.1.1)
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key, "-out", cert,
        "-days", "1", "-nodes", "-subj", subj,
        "-addext", f"subjectAltName={san}",
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=15)
    if r.returncode != 0:
        # Fallback без SAN (старый openssl)
        cmd2 = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key, "-out", cert,
            "-days", "1", "-nodes", "-subj", subj,
        ]
        subprocess.run(cmd2, capture_output=True, timeout=15, check=True)

    return cert, key

# ── HTTP-обработчик ───────────────────────────────────────────────────────
class _OneTimeHandler(BaseHTTPRequestHandler):
    """Отдаёт файл конфига ровно один раз по секретному токену."""
    token: str       = ""
    file_path: Path  = Path()
    file_name: str   = ""
    served: list     = []   # [True] после первой отдачи
    shutdown_event   = None

    def do_GET(self):
        if f"/{self.token}" not in self.path:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        try:
            data = self.file_path.read_bytes()
        except Exception:
            self.send_response(500)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{self.file_name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

        self.served.append(True)
        _log("INFO", f"Config downloaded: {self.file_name} from {self.client_address[0]}")
        # Сигнализируем об остановке
        if self.shutdown_event:
            self.shutdown_event.set()

    def log_message(self, fmt, *args):
        pass  # Подавляем стандартный лог


# ── Управление firewall ───────────────────────────────────────────────────
def _fw_open(port: int) -> None:
    for cmd in [
        ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
        ["ip6tables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
    ]:
        subprocess.run(cmd, capture_output=True)


def _fw_close(port: int) -> None:
    for cmd in [
        ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
        ["ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
    ]:
        subprocess.run(cmd, capture_output=True)


# ── Выбор свободного порта ────────────────────────────────────────────────
def _free_port() -> int:
    for _ in range(20):
        port = random.randint(*_PORT_RANGE)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return random.randint(*_PORT_RANGE)


# ── QR-код в терминале ────────────────────────────────────────────────────
def _show_qr_inline(url: str) -> None:
    """Показывает QR через qrencode если доступен."""
    try:
        r = subprocess.run(
            ["qrencode", "-t", "ANSIUTF8", "-m", "1", url],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            print(r.stdout)
            return
    except Exception:
        pass
    print(f"  {DIM}(qrencode не установлен — скопируйте ссылку){NC}\n")


# ── Список конфигов ───────────────────────────────────────────────────────
def _list_configs() -> list[Path]:
    if not _FRAG_DIR.exists():
        return []
    return sorted(_FRAG_DIR.glob("*.json"))


# ── Основная функция ──────────────────────────────────────────────────────
def _serve_config(config_path: Path, timeout: int = _TIMEOUT_SEC) -> None:
    """
    Поднимает временный HTTPS-сервер, показывает QR,
    ждёт скачивания или таймаута.
    """
    ip = _get_server_ip()
    if not ip:
        _warn("Не удалось определить IP сервера")
        return

    token = secrets.token_urlsafe(12)
    port  = _free_port()
    url   = f"https://{ip}:{port}/{token}/{config_path.name}"

    with tempfile.TemporaryDirectory(prefix="vless_share_") as tmp:
        # Генерируем сертификат
        try:
            cert, key = _gen_self_signed_cert(tmp, ip)
        except Exception as e:
            _warn(f"Не удалось создать TLS-сертификат: {e}")
            _warn("Убедитесь что установлен openssl")
            return

        # Настраиваем HTTP-обработчик
        shutdown_event = threading.Event()
        _OneTimeHandler.token          = token
        _OneTimeHandler.file_path      = config_path
        _OneTimeHandler.file_name      = config_path.name
        _OneTimeHandler.served         = []
        _OneTimeHandler.shutdown_event = shutdown_event

        # Запускаем сервер
        try:
            httpd = HTTPServer(("0.0.0.0", port), _OneTimeHandler)
            ctx   = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        except Exception as e:
            _warn(f"Не удалось запустить сервер: {e}")
            return

        _fw_open(port)
        _log("INFO", f"Share server started: port={port} file={config_path.name}")

        # Запускаем сервер в отдельном потоке
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        # Показываем QR и инструкцию
        os.system("clear")
        print()
        _box_top("📲  СКАЧАТЬ КОНФИГ НА ТЕЛЕФОН")
        _box_sep()
        _box_row(f"  Файл: {DIM}{config_path.name}{NC}")
        _box_row(f"  Порт: {DIM}{port}{NC}")
        _box_row(f"  Время: {DIM}{timeout // 60} мин{NC}")
        _box_sep()
        _box_row(f"  {YELLOW}Ссылка:{NC}")
        _box_row(f"  {DIM}{url}{NC}")
        _box_sep()
        _box_warn("Сертификат самоподписанный — нажмите «Принять» в браузере")
        _box_warn("Ссылка работает ОДИН РАЗ и гаснет после скачивания")
        _box_bottom()
        print()

        print(f"  {BOLD}Отсканируйте QR-код телефоном:{NC}")
        print()
        _show_qr_inline(url)

        # Ждём скачивания или таймаута
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                if shutdown_event.wait(timeout=1.0):
                    break
                remaining = int(deadline - time.time())
                print(f"\r  {DIM}Ожидание скачивания... осталось {remaining} сек  {NC}",
                      end="", flush=True)
        except KeyboardInterrupt:
            pass

        print()
        httpd.shutdown()
        _fw_close(port)

        if _OneTimeHandler.served:
            _ok("Конфиг успешно скачан!")
            _log("INFO", f"Share completed: {config_path.name}")
        else:
            _warn("Таймаут — конфиг не был скачан")
            _log("WARN", f"Share timeout: {config_path.name}")


# ── Меню ──────────────────────────────────────────────────────────────────
def do_fragment_share_menu() -> None:
    """
    Временный HTTPS-сервер для доставки конфигов без scp.
    Вызывается из _menu_users() в _core.py (пункт G).
    """
    os.system("clear")
    print()
    _box_top("📲  ПОДЕЛИТЬСЯ КОНФИГОМ (БЕЗ SCP)")
    _box_desc(
        "Поднимает временный HTTPS-сервер на 10 минут. "
        "Отсканируйте QR телефоном — конфиг скачается сам. "
        "После скачивания сервер гаснет автоматически."
    )
    _box_sep()
    _box_info("Требуется: openssl (обычно уже установлен)")
    _box_warn("Сертификат самоподписанный — браузер попросит подтвердить")
    _box_bottom()

    # Проверяем наличие конфигов
    configs = _list_configs()
    if not configs:
        print()
        _warn("Конфигов не найдено. Сначала сгенерируйте через F4.")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    # Показываем список конфигов
    print()
    _box_top("Выберите конфиг для раздачи")
    for i, cfg in enumerate(configs[:9], 1):
        size_kb = cfg.stat().st_size // 1024
        _box_item(str(i), f"{cfg.name}  {DIM}({size_kb} КБ){NC}")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except KeyboardInterrupt:
        return

    if ch.lower() == "q" or ch == "":
        return

    if not ch.isdigit() or not (1 <= int(ch) <= len(configs[:9])):
        _warn("Неверный выбор")
        time.sleep(1)
        return

    selected = configs[int(ch) - 1]
    _serve_config(selected)
    input(f"\n{BLUE}Нажмите Enter...{NC}")
