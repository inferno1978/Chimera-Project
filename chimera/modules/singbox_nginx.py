"""
chimera/modules/singbox_nginx.py
───────────────────────────────────────────────────────────────────────────────
SNI-dispatch через nginx stream{} + ssl_preread.

АРХИТЕКТУРА:
  По решению пользователя — НЕ HAProxy, НЕ sing-box как generic frontend.
  Reality должен сам видеть ClientHello, поэтому единственный путь —
  SNI-based TCP dispatch через nginx stream{} + ssl_preread.

  nginx stream{} живёт ВНЕ http{} — обычно в /etc/nginx/streams-enabled/*.conf
  или прямо в /etc/nginx/nginx.conf. Существующий http{} блок НЕ ТРОГАЕМ.

ПРИНЦИП:
  TCP:443 → nginx stream{} → ssl_preread_server_name →
    ├─ shadowtls.example.com  → 127.0.0.1:8443  (sing-box ShadowTLS)
    ├─ anytls.example.com    → 127.0.0.1:8444  (sing-box AnyTLS)
    └─ default (Reality SNI) → unix:/dev/shm/vless-reality.socket (Xray)

  UDP:443 → TUIC (sing-box), не пересекается с TCP:443

ОПАСНОСТЬ:
  При включении SNI-dispatch Reality должен переехать с :443 на backend.
  Это меняет существующую конфигурацию! Поэтому:
    1. SNI-dispatch — ОПЦИОНАЛЬНЫЙ режим (по умолчанию выключен)
    2. При включении — предупреждаем пользователя и предлагаем
       либо автоматический перевод Reality на backend, либо отказ
    3. При выключении — Reality возвращается на :443

ПОВЕДЕНИЕ:
  • enable_sni_dispatch(shadowtls_sni, anytls_sni) — включает SNI-dispatch
  • disable_sni_dispatch() — выключает, восстанавливает Reality на :443
  • sni_dispatch_status() — dict с текущим состоянием
  • _build_nginx_stream_conf() — генерирует nginx stream{} конфиг
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Optional

from chimera.modules.singbox_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run,
    DEFAULT_PORT_SHADOWTLS, DEFAULT_PORT_ANYTLS,
)
from chimera.modules.singbox_state import (
    singbox_state_load, singbox_state_save,
    singbox_state_get_sni_dispatch, singbox_state_set_sni_dispatch,
    singbox_state_update_sni_dispatch,
)


# ============================================================================
#  Пути nginx
# ============================================================================
NGINX_STREAMS_DIR    = Path("/etc/nginx/streams-enabled")
NGINX_STREAMS_AVAIL  = Path("/etc/nginx/streams-available")
NGINX_STREAM_CONF    = NGINX_STREAMS_DIR / "singbox-dispatch.conf"
NGINX_NGINX_CONF     = Path("/etc/nginx/nginx.conf")

# Возможный backend для Xray REALITY (либо unix-socket, либо loopback port)
_REALITY_UNIX_SOCKET_DEFAULT = "/dev/shm/vless-reality.socket"
_REALITY_LOOPBACK_PORT_DEFAULT = 8442  # если unix-socket недоступен


# ============================================================================
#  Проверка совместимости nginx
# ============================================================================
def _nginx_has_stream_support() -> bool:
    """Проверяет, что nginx собран с модулем stream."""
    try:
        r = _run(["nginx", "-V"], capture=True, quiet=True)
    except FileNotFoundError:
        return False
    if r.returncode != 0:
        return False
    output = (r.stderr or "") + (r.stdout or "")
    return "--with-stream" in output


def _nginx_has_ssl_preread() -> bool:
    """Проверяет, что nginx собран с ssl_preread (часть stream ssl модуля)."""
    try:
        r = _run(["nginx", "-V"], capture=True, quiet=True)
    except FileNotFoundError:
        return False
    if r.returncode != 0:
        return False
    output = (r.stderr or "") + (r.stdout or "")
    return "--with-stream_ssl_preread_module" in output or \
           "--with-stream_ssl_module" in output


def _nginx_config_has_stream_block() -> bool:
    """Проверяет, что в /etc/nginx/nginx.conf есть директива stream { ... }."""
    if not NGINX_NGINX_CONF.exists():
        return False
    try:
        text = NGINX_NGINX_CONF.read_text()
        return bool(re.search(r'^\s*stream\s*\{', text, re.MULTILINE))
    except Exception:
        return False


def _nginx_ensure_stream_include() -> bool:
    """Добавляет 'include /etc/nginx/streams-enabled/*.conf;' в stream{} блок.
    Если блока stream{} нет — создаёт его в nginx.conf.

    Возвращает True при успехе.
    """
    if not NGINX_NGINX_CONF.exists():
        error(f"{NGINX_NGINX_CONF} не найден")
        return False

    text = NGINX_NGINX_CONF.read_text()

    # Проверяем, есть ли уже include streams-enabled
    if "streams-enabled" in text:
        return True

    # Ищем блок stream { ... }
    stream_match = re.search(r'(\nstream\s*\{[^}]*\})', text)
    if stream_match:
        # Добавляем include внутрь существующего блока
        block = stream_match.group(1)
        new_block = block.rstrip("}")
        new_block += f"\n    include /etc/nginx/streams-enabled/*.conf;\n}}"
        text = text.replace(block, new_block, 1)
    else:
        # Создаём новый блок stream{} перед закрывающей }
        # Обычно в конце nginx.conf: }
        # Добавляем stream{} блок ДО последней }
        last_brace = text.rfind("}")
        if last_brace == -1:
            error("Не найден закрывающий } в nginx.conf — файл повреждён")
            return False
        stream_block = (
            "\nstream {\n"
            "    include /etc/nginx/streams-enabled/*.conf;\n"
            "}\n"
        )
        text = text[:last_brace] + stream_block + text[last_brace:]

    try:
        NGINX_NGINX_CONF.write_text(text)
        return True
    except Exception as e:
        error(f"Не удалось обновить {NGINX_NGINX_CONF}: {e}")
        return False


# ============================================================================
#  Генерация stream{} конфига
# ============================================================================
def _build_nginx_stream_conf(
    shadowtls_sni: str,
    anytls_sni: str,
    default_backend: str,
    shadowtls_port: int = DEFAULT_PORT_SHADOWTLS,
    anytls_port: int = DEFAULT_PORT_ANYTLS,
) -> str:
    """Генерирует nginx stream{} конфиг для SNI-dispatch.

    Структура:
        map $ssl_preread_server_name $singbox_backend {
            ~^shadowtls\\.example\\.com$  127.0.0.1:8443;
            ~^anytls\\.example\\.com$    127.0.0.1:8444;
            default                       <default_backend>;
        }

        server {
            listen 443;
            listen [::]:443;
            ssl_preread on;
            proxy_pass $singbox_backend;
            proxy_protocol on;  # опционально, передаёт реальный IP
        }
    """
    # Экранируем точки в доменах для regex
    sh_re = re.escape(shadowtls_sni) if shadowtls_sni else ""
    any_re = re.escape(anytls_sni) if anytls_sni else ""

    map_lines = []
    if sh_re:
        map_lines.append(f"    ~^{sh_re}$  127.0.0.1:{shadowtls_port};")
    if any_re:
        map_lines.append(f"    ~^{any_re}$  127.0.0.1:{anytls_port};")
    map_lines.append(f"    default  {default_backend};")

    return f"""# sing-box SNI-dispatch — generated by Chimera Project
# Включается/выключается через меню sing-box -> SNI-dispatch.
# НЕ редактировать вручную — файл перегенерируется.

map $ssl_preread_server_name $singbox_backend {{
{chr(10).join(map_lines)}
}}

server {{
    listen 443;
    listen [::]:443;
    ssl_preread on;
    proxy_pass $singbox_backend;
    proxy_protocol on;  # v4.23.5: передаёт реальный IP — fail2ban зависит от этого
    proxy_connect_timeout 5s;
    proxy_timeout 30s;
}}
"""


# ============================================================================
#  Публичный API
# ============================================================================
def enable_sni_dispatch(
    shadowtls_sni: str = "",
    anytls_sni: str = "",
    default_backend: str = "",
    interactive: bool = True,
) -> bool:
    """
    Включает SNI-dispatch через nginx stream{}.

    Args:
      shadowtls_sni:   SNI-домен для ShadowTLS (например "shadowtls.example.com")
      anytls_sni:      SNI-домен для AnyTLS
      default_backend: Куда направлять прочие SNI (Reality backend)
                       По умолчанию unix:/dev/shm/vless-reality.socket или 127.0.0.1:8442
      interactive:     Если True — задавать вопросы пользователю при конфликтах

    Returns:
      True при успехе, False при ошибке.
    """
    # 1. Проверки nginx
    if not _nginx_has_stream_support():
        error("nginx собран без --with-stream — SNI-dispatch невозможен")
        error("Пересоберите nginx с поддержкой stream module или установите nginx-extras")
        return False
    if not _nginx_has_ssl_preread():
        error("nginx собран без ssl_preread — SNI-dispatch невозможен")
        return False

    # 2. Определяем default_backend
    if not default_backend:
        # Unix-socket для Reality (предпочтительно) или loopback port
        default_backend = _REALITY_UNIX_SOCKET_DEFAULT

    # 3. Предупреждение о Reality-бэкенде
    if interactive:
        warn("ВНИМАНИЕ: SNI-dispatch требует, чтобы Xray REALITY слушал на backend,")
        warn(f"не на :443 напрямую. Backend: {default_backend}")
        warn("Если REALITY сейчас на :443 — нужно перенастроить на backend.")
        warn("Это меняет существующую конфигурацию Xray!")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            confirm = ""
        if confirm != "y":
            info("Отменено пользователем")
            return False

    # 4. Создаём директории
    NGINX_STREAMS_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_STREAMS_AVAIL.mkdir(parents=True, exist_ok=True)

    # 5. Обновляем nginx.conf (include streams-enabled)
    if not _nginx_ensure_stream_include():
        return False

    # 6. Генерируем stream-конфиг
    state = singbox_state_load()
    shadowtls_port = state.get("inbounds", {}).get("shadowtls", {}).get(
        "listen_port", DEFAULT_PORT_SHADOWTLS)
    anytls_port = state.get("inbounds", {}).get("anytls", {}).get(
        "listen_port", DEFAULT_PORT_ANYTLS)

    conf_text = _build_nginx_stream_conf(
        shadowtls_sni=shadowtls_sni,
        anytls_sni=anytls_sni,
        default_backend=default_backend,
        shadowtls_port=shadowtls_port,
        anytls_port=anytls_port,
    )

    # Записываем в streams-available и symlink в streams-enabled
    avail_path = NGINX_STREAMS_AVAIL / "singbox-dispatch.conf"
    avail_path.write_text(conf_text)

    if NGINX_STREAM_CONF.exists() or NGINX_STREAM_CONF.is_symlink():
        NGINX_STREAM_CONF.unlink()
    try:
        NGINX_STREAM_CONF.symlink_to(avail_path)
    except OSError:
        # Если symlink не удался — копируем
        shutil.copy(avail_path, NGINX_STREAM_CONF)

    # 7. nginx -t
    r = _run(["nginx", "-t"], capture=True, quiet=True)
    if r.returncode != 0:
        error("nginx -t провален после добавления SNI-dispatch:")
        error((r.stderr or "")[:400])
        # Откат
        if NGINX_STREAM_CONF.exists():
            NGINX_STREAM_CONF.unlink()
        return False

    # 8. Reload nginx
    r2 = _run(["systemctl", "reload", "nginx"], capture=True, quiet=True)
    if r2.returncode != 0:
        warn("nginx reload не удался — попробуйте systemctl restart nginx вручную")

    # 9. State update
    singbox_state_set_sni_dispatch({
        "enabled":            True,
        "nginx_stream_conf":  str(NGINX_STREAM_CONF),
        "shadowtls_sni":      shadowtls_sni,
        "anytls_sni":         anytls_sni,
        "default_backend":    default_backend,
        "shadowtls_port":     shadowtls_port,
        "anytls_port":        anytls_port,
    })

    success("SNI-dispatch включён (nginx stream{} + ssl_preread)")
    success(f"  ShadowTLS SNI:  {shadowtls_sni or '(не задан)'}")
    success(f"  AnyTLS SNI:     {anytls_sni or '(не задан)'}")
    success(f"  Default → Reality backend: {default_backend}")
    log_to_file("INFO", f"SNI-dispatch enabled: shadowtls={shadowtls_sni}, "
                        f"anytls={anytls_sni}, default={default_backend}")
    return True


def disable_sni_dispatch(interactive: bool = True) -> bool:
    """Выключает SNI-dispatch и удаляет stream{}-конфиг."""
    state = singbox_state_get_sni_dispatch()
    if not state.get("enabled"):
        info("SNI-dispatch уже выключен")
        return True

    if interactive:
        warn("При выключении SNI-dispatch Reality должен вернуться на :443 напрямую.")
        warn("Убедитесь, что Xray REALITY перенастроен обратно.")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            confirm = ""
        if confirm != "y":
            info("Отменено пользователем")
            return False

    # Удаляем symlink и файл
    if NGINX_STREAM_CONF.is_symlink() or NGINX_STREAM_CONF.exists():
        try:
            NGINX_STREAM_CONF.unlink()
        except Exception as e:
            warn(f"Не удалось удалить {NGINX_STREAM_CONF}: {e}")

    avail_path = NGINX_STREAMS_AVAIL / "singbox-dispatch.conf"
    if avail_path.exists():
        try:
            avail_path.unlink()
        except Exception:
            pass

    # nginx -t
    r = _run(["nginx", "-t"], capture=True, quiet=True)
    if r.returncode != 0:
        warn("nginx -t провален после удаления SNI-dispatch:")
        warn((r.stderr or "")[:300])
    else:
        _run(["systemctl", "reload", "nginx"], capture=True, quiet=True)

    # State
    singbox_state_update_sni_dispatch(enabled=False)
    success("SNI-dispatch выключен")
    log_to_file("INFO", "SNI-dispatch disabled")
    return True


def sni_dispatch_status() -> dict:
    """Возвращает dict с текущим статусом SNI-dispatch."""
    state = singbox_state_get_sni_dispatch()
    return {
        "enabled":            state.get("enabled", False),
        "nginx_stream_conf":  state.get("nginx_stream_conf", str(NGINX_STREAM_CONF)),
        "shadowtls_sni":      state.get("shadowtls_sni", ""),
        "anytls_sni":         state.get("anytls_sni", ""),
        "default_backend":    state.get("default_backend", ""),
        "config_file_exists": NGINX_STREAM_CONF.exists(),
        "nginx_stream_support":     _nginx_has_stream_support(),
        "nginx_ssl_preread":        _nginx_has_ssl_preread(),
        "nginx_stream_block":       _nginx_config_has_stream_block(),
    }


def validate_sni_dispatch_config() -> bool:
    """Проверяет, что конфиг SNI-dispatch валиден."""
    if not NGINX_STREAM_CONF.exists():
        return False
    r = _run(["nginx", "-t"], capture=True, quiet=True)
    return r.returncode == 0


# ============================================================================
#  v4.23.5: Auto-config — автоматическое определение параметров SNI-dispatch
# ============================================================================
# Архитектура (v4.23.5):
#
#  REALITY-инбаунд в config.json слушает на :443 напрямую (без SNI-dispatch).
#  При включении SNI-dispatch:
#    1. nginx stream{} перехватывает :443, диспетчеризует по SNI
#    2. REALITY-инбаунд должен переехать с :443 на backend (loopback:8442)
#    3. stream{} default → 127.0.0.1:8442 (с proxy_protocol on)
#    4. Xray REALITY inbound: listen=127.0.0.1:8442, sockopt.acceptProxyProtocol=true
#    5. realitySettings.dest (decoy-сокет) НЕ ТРОГАЕМ — это downstream Xray
#
#  Важно: realitySettings.dest (PARAM_SOCKET_PATH, decoy-сайт) — НЕ является
#  backend для SNI-dispatch. Это fallback для non-REALITY трафика внутри самого
#  Xray. SNI-dispatch направляет REALITY SNI на 127.0.0.1:8442, где Xray
#  слушает REALITY-инбаунд с acceptProxyProtocol.
#
#  Автоматический патч config.json Xray (перенос listen + acceptProxyProtocol) —
#  следующим шагом. В этом коммите: auto-detect параметров + генерация stream{}
#  + комментирование listen 443 в http{}. Ручной патч config.json — с явным
#  warn() пользователю.

import json as _json
from pathlib import Path as _Path
from datetime import datetime as _datetime

# Loopback порт для REALITY-инбаунда при SNI-dispatch
_REALITY_LOOPBACK_PORT = 8442

# Comment-tag для бэкапа http{} конфига
_NGINX_HTTP_BACKUP_SUFFIX = ".pre-sni-dispatch"


def _read_main_state() -> dict:
    """Читает основной state.json (/var/lib/xray-installer/state.json)."""
    try:
        p = _Path("/var/lib/xray-installer/state.json")
        if not p.exists():
            return {}
        return _json.loads(p.read_text())
    except Exception:
        return {}


def _detect_reality_backend() -> str:
    """Определяет backend для REALITY при SNI-dispatch.

    Читает state.json → protocol_mode, awg_exit_enabled.
    Если REALITY (не xHTTP, не AWG) — возвращает loopback адрес 127.0.0.1:8442.
    REALITY-инбаунд должен слушать на этом адресе с acceptProxyProtocol=true.

    НЕ использует state.json["socket"] (PARAM_SOCKET_PATH) — это decoy-сокет
    для realitySettings.dest, отдельная downstream-логика Xray.

    Returns:
      "127.0.0.1:8442" если REALITY режим.
      "" если xHTTP или AWG — auto-config неприменим.
    """
    state = _read_main_state()
    proto = state.get("protocol_mode", "reality")
    awg = state.get("awg_exit_enabled", False)

    if proto != "reality":
        # xhttp и xhttp_reality — SNI-dispatch неприменим: в чистом xHTTP
        # nginx http{} уже на :443; в xHTTP+REALITY Xray сам владеет :443
        # (REALITY TLS) — перехват SNI сломал бы xhttp-транспорт.
        return ""
    if awg:
        return ""  # AWG — Xray на :443 напрямую, конфликт

    return f"127.0.0.1:{_REALITY_LOOPBACK_PORT}"


def _detect_shadowtls_sni() -> str:
    """Auto-detect SNI для ShadowTLS из singbox_state.

    Читает singbox_state["inbounds"]["shadowtls"]["handshake"]["server"],
    если shadowtls enabled.
    """
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("shadowtls", {})
    if not ib.get("enabled"):
        return ""
    handshake = ib.get("handshake", {})
    return handshake.get("server", "")


def _detect_anytls_sni() -> str:
    """Auto-detect SNI для AnyTLS.

    v4.23.5: читает common_name из singbox_state (новые установки).
    Fallback для старых установок: парсит CN из cert_path через openssl.
    Если ни то ни другое — пустая строка (пользователь должен ввести вручную).
    """
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("anytls", {})
    if not ib.get("enabled"):
        return ""

    # 1. common_name из state (v4.23.5+)
    cn = ib.get("common_name", "")
    if cn:
        return cn

    # 2. Fallback: парсим CN из существующего сертификата
    cert_path = ib.get("cert_path", "")
    if cert_path and _Path(cert_path).exists():
        try:
            r = _run(["openssl", "x509", "-noout", "-subject", "-in", cert_path],
                     capture=True, quiet=True)
            if r.returncode == 0 and r.stdout:
                # Вывод: "subject=C=XX, CN=example.com" или "subject=/CN=example.com"
                subject = r.stdout.strip()
                # Извлекаем CN
                if "CN=" in subject:
                    cn_part = subject.split("CN=")[-1].split(",")[0].split("/")[0].strip()
                    if cn_part:
                        return cn_part
        except Exception:
            pass

    return ""


def _find_nginx_http_443_configs() -> list[_Path]:
    """Находит nginx http{} конфиги с активным listen 443.

    Ищет в /etc/nginx/sites-enabled/ и /etc/nginx/conf.d/.
    Возвращает список путей к файлам, содержащим незакомментированный listen 443.
    """
    result = []
    search_dirs = [_Path("/etc/nginx/sites-enabled"), _Path("/etc/nginx/conf.d")]
    for d in search_dirs:
        if not d.is_dir():
            continue
        for f in d.glob("*.conf"):
            try:
                text = f.read_text()
                for line in text.splitlines():
                    stripped = line.strip()
                    # Пропускаем закомментированные строки
                    if stripped.startswith("#"):
                        continue
                    # Ищем активный listen 443 (не в stream{}, не закомментированный)
                    if "listen" in stripped and "443" in stripped:
                        result.append(f)
                        break
            except Exception:
                pass
    return result


def _comment_out_listen_443(config_path: _Path) -> bool:
    """Комментирует строки `listen ... 443 ...` в http{} конфиге.

    Создаёт бэкап .pre-sni-dispatch перед изменением.
    Возвращает True при успехе.
    """
    try:
        text = config_path.read_text()
        # Бэкап
        backup_path = config_path.with_suffix(config_path.suffix + _NGINX_HTTP_BACKUP_SUFFIX)
        if not backup_path.exists():
            backup_path.write_text(text)
            info(f"Бэкап: {backup_path}")

        new_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if (not stripped.startswith("#")
                    and "listen" in stripped
                    and "443" in stripped
                    and "unix:" not in stripped):
                # Комментируем — добавляем # в начало (с сохранением отступа)
                indent = line[:len(line) - len(line.lstrip())]
                new_lines.append(f"{indent}# [SNI-DISPATCH] {stripped}")
            else:
                new_lines.append(line)

        config_path.write_text("\n".join(new_lines) + "\n")
        return True
    except Exception as e:
        error(f"Не удалось закомментировать listen 443 в {config_path}: {e}")
        return False


def _uncomment_listen_443(config_path: _Path) -> bool:
    """Раскомментирует строки `# [SNI-DISPATCH] listen ... 443 ...` в http{} конфиге.

    Возвращает True при успехе.
    """
    try:
        text = config_path.read_text()
        new_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("# [SNI-DISPATCH]"):
                # Раскомментируем
                indent = line[:len(line) - len(line.lstrip())]
                content = stripped.replace("# [SNI-DISPATCH] ", "")
                new_lines.append(f"{indent}{content}")
            else:
                new_lines.append(line)

        config_path.write_text("\n".join(new_lines) + "\n")
        return True
    except Exception as e:
        error(f"Не удалось раскомментировать listen 443 в {config_path}: {e}")
        return False


def auto_enable_sni_dispatch(
    reality_sni: str = "",
    interactive: bool = True,
) -> bool:
    """Автоматически включает SNI-dispatch с auto-detect параметров.

    v4.23.5–v4.23.8: Автоматизирует:
    1. Detect REALITY backend (loopback:8442, не decoy-сокет)
    2. Detect ShadowTLS SNI из singbox_state (handshake.server)
    3. Detect AnyTLS SNI из singbox_state (common_name или CN из cert)
    4. Комментирует listen 443 в http{} (с бэкапом)
    5. Генерирует stream{} конфиг с proxy_protocol on
    6. nginx -t → reload
    7. v4.23.8: apply_reality_sni_dispatch_patch() — перенос REALITY на
       loopback:8442 + acceptProxyProtocol=true (с бэкапом + xray -test).

    Args:
      reality_sni: SNI домен сервера REALITY (для default backend).
                   Если пусто — читается из state.json domain.
      interactive: Если True — подтверждение пользователя.

    Returns:
      True при успехе, False при ошибке.
    """
    # 1. Detect REALITY backend
    default_backend = _detect_reality_backend()
    if not default_backend:
        state = _read_main_state()
        proto = state.get("protocol_mode", "reality")
        awg = state.get("awg_exit_enabled", False)
        if proto == "xhttp":
            error("SNI-dispatch неприменим в xHTTP-режиме: nginx http{} уже на :443")
        elif proto == "xhttp_reality":
            error("SNI-dispatch неприменим в xHTTP+REALITY-режиме: "
                  "Xray владеет :443 (REALITY TLS + xhttp-транспорт)")
        elif awg:
            error("SNI-dispatch неприменим в AWG-режиме: Xray на :443 напрямую")
        else:
            error("Не удалось определить REALITY backend")
        return False

    # 2. Detect SNI для ShadowTLS
    shadowtls_sni = _detect_shadowtls_sni()
    if shadowtls_sni:
        info(f"ShadowTLS SNI auto-detected: {shadowtls_sni}")

    # 3. Detect SNI для AnyTLS
    anytls_sni = _detect_anytls_sni()
    if anytls_sni:
        info(f"AnyTLS SNI auto-detected: {anytls_sni}")
    else:
        # Проверим — AnyTLS включён но SNI не найден
        state = singbox_state_load()
        anytls_enabled = state.get("inbounds", {}).get("anytls", {}).get("enabled", False)
        if anytls_enabled:
            warn("AnyTLS SNI не определён автоматически — введите вручную")
            warn("(common_name не сохранён в state и CN не извлечён из cert)")

    # 4. REALITY SNI — из state.json domain
    if not reality_sni:
        main_state = _read_main_state()
        reality_sni = main_state.get("domain", "")

    # 5. Подтверждение
    if interactive:
        print()
        info(f"REALITY backend: {default_backend} (loopback, proxy_protocol)")
        info(f"ShadowTLS SNI:   {shadowtls_sni or '(не задан)'}")
        info(f"AnyTLS SNI:      {anytls_sni or '(не задан)'}")
        info(f"REALITY SNI:     {reality_sni or '(не задан)'}")
        print()
        warn("ВНИМАНИЕ: SNI-dispatch перехватит :443 в nginx stream{}.")
        warn("listen 443 в http{} будет закомментирован (с бэкапом).")
        warn(f"REALITY-инбаунд будет переведён на {default_backend}")
        warn("с sockopt.acceptProxyProtocol=true автоматически (v4.23.8).")
        warn("realitySettings.dest НЕ будет тронут (decoy-сокет остаётся).")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            confirm = ""
        if confirm != "y":
            info("Отменено пользователем")
            return False

    # 6. Комментируем listen 443 в http{}
    http_configs = _find_nginx_http_443_configs()
    if not http_configs:
        warn("Не найден http{} конфиг с listen 443 — возможно уже закомментирован")
    else:
        for cfg_path in http_configs:
            if not _comment_out_listen_443(cfg_path):
                error(f"Не удалось закомментировать listen 443 в {cfg_path}")
                return False
            info(f"listen 443 закомментирован в {cfg_path.name}")

    # 7. Включаем SNI-dispatch через существующую функцию
    #    proxy_protocol on — для передачи реального IP (fail2ban зависит от этого)
    ok = enable_sni_dispatch(
        shadowtls_sni=shadowtls_sni,
        anytls_sni=anytls_sni,
        default_backend=default_backend,
        interactive=False,  # уже подтвердили выше
    )
    if not ok:
        # Откат: раскомментируем listen 443
        for cfg_path in http_configs:
            _uncomment_listen_443(cfg_path)
        return False

    # 8. Дополняем state — сохраняем auto-config метаданные
    sd_state = singbox_state_get_sni_dispatch()
    sd_state["auto_configured"] = True
    sd_state["reality_sni"] = reality_sni
    sd_state["reality_backend"] = default_backend
    sd_state["http_configs_patched"] = [str(p) for p in http_configs]
    sd_state["auto_enabled_at"] = _datetime.now().isoformat()
    singbox_state_set_sni_dispatch(sd_state)

    success("SNI-dispatch auto-config включён")
    success(f"  REALITY backend: {default_backend} (proxy_protocol on)")
    if shadowtls_sni:
        success(f"  ShadowTLS SNI:   {shadowtls_sni}")
    if anytls_sni:
        success(f"  AnyTLS SNI:      {anytls_sni}")
    print()

    # v4.23.8: автоматический патч config.json Xray (перенос REALITY на
    # loopback:8442 + acceptProxyProtocol=true). До v4.23.8 здесь был
    # warn()-плейсхолдер "переведите вручную" — теперь патч применяется
    # автоматически, с бэкапом .pre-sni-dispatch и xray -test проверкой.
    if not apply_reality_sni_dispatch_patch():
        error("Не удалось применить патч config.json — откат SNI-dispatch")
        # Откат: удаляем stream{} конфиг и раскомментируем listen 443
        disable_sni_dispatch(interactive=False)
        for cfg_path in http_configs:
            _uncomment_listen_443(cfg_path)
        return False

    success(f"  config.json Xray пропатчен автоматически")
    success(f"  listen=127.0.0.1, port={_REALITY_LOOPBACK_PORT}, "
            f"acceptProxyProtocol=true")
    success("  (realitySettings.dest не тронут — decoy-сокет)")
    log_to_file("INFO", f"SNI-dispatch auto-enabled: backend={default_backend}, "
                        f"shadowtls_sni={shadowtls_sni}, anytls_sni={anytls_sni}")
    return True


def auto_disable_sni_dispatch(interactive: bool = True) -> bool:
    """Автоматически выключает SNI-dispatch и возвращает listen 443 в http{}.

    v4.23.5–v4.23.8:
    1. Удаляет stream{} конфиг (через существующую disable_sni_dispatch)
    2. Раскомментирует listen 443 в http{} конфигах
    3. nginx -t → reload
    4. v4.23.8: Откатывает патч config.json Xray (через
       revert_reality_sni_dispatch_patch) — REALITY возвращается на :443,
       acceptProxyProtocol убирается.

    Args:
      interactive: Если True — подтверждение пользователя.

    Returns:
      True при успехе, False при ошибке.
    """
    sd_state = singbox_state_get_sni_dispatch()
    if not sd_state.get("enabled"):
        info("SNI-dispatch уже выключен")
        return True

    if interactive:
        warn("При выключении SNI-dispatch:")
        warn("  1. stream{} конфиг будет удалён")
        warn("  2. listen 443 в http{} будет раскомментирован")
        warn("  3. REALITY-инбаунд вернётся на :443 напрямую автоматически (v4.23.8)")
        warn("     (sockopt.acceptProxyProtocol убран, listen :443)")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            confirm = ""
        if confirm != "y":
            info("Отменено пользователем")
            return False

    # 1. Удаляем stream{} конфиг
    ok = disable_sni_dispatch(interactive=False)
    if not ok:
        return False

    # 2. Раскомментируем listen 443 в http{}
    patched_paths = sd_state.get("http_configs_patched", [])
    if not patched_paths:
        # Fallback: ищем сами
        patched_paths = [str(p) for p in _find_nginx_http_443_configs()]

    for path_str in patched_paths:
        cfg_path = _Path(path_str)
        if cfg_path.exists():
            if _uncomment_listen_443(cfg_path):
                info(f"listen 443 раскомментирован в {cfg_path.name}")
            else:
                warn(f"Не удалось раскомментировать listen 443 в {cfg_path.name}")

    # 3. nginx -t → reload
    r = _run(["nginx", "-t"], capture=True, quiet=True)
    if r.returncode != 0:
        warn("nginx -t провален после раскомментирования:")
        warn((r.stderr or "")[:300])
    else:
        _run(["systemctl", "reload", "nginx"], capture=True, quiet=True)

    # 4. State update
    sd_state = singbox_state_get_sni_dispatch()
    sd_state["auto_configured"] = False
    sd_state.pop("reality_sni", None)
    sd_state.pop("reality_backend", None)
    sd_state.pop("http_configs_patched", None)
    sd_state.pop("auto_enabled_at", None)
    singbox_state_set_sni_dispatch(sd_state)

    success("SNI-dispatch auto-config выключен")
    success("  listen 443 возвращён в http{}")

    # v4.23.8: автоматический откат патча config.json Xray
    if not revert_reality_sni_dispatch_patch():
        warn("Не удалось откатить патч config.json — проверьте вручную")
        warn("REALITY-инбаунд должен вернуться на :443 напрямую")
    else:
        success("  config.json Xray откатан: REALITY на :443 напрямую")

    # Чистим original_listen/original_port из state
    sd_state = singbox_state_get_sni_dispatch()
    sd_state.pop("original_listen", None)
    sd_state.pop("original_port", None)
    singbox_state_set_sni_dispatch(sd_state)

    log_to_file("INFO", "SNI-dispatch auto-disabled, listen 443 restored")
    return True


# ============================================================================
#  v4.23.8: автоматический патч config.json Xray для SNI-dispatch
# ============================================================================
#  До v4.23.8 auto_enable_sni_dispatch() настраивал nginx stream{}, но НЕ
#  патчил config.json Xray — REALITY-инбаунд оставался на публичном :443,
#  создавая конфликт биндинга с nginx stream{}. Пользователь был вынужден
#  патчить вручную. Теперь патч применяется автоматически.
#
#  Патч:
#    "port":  SERVER_PORT (443) → 8442 (_REALITY_LOOPBACK_PORT)
#    "listen": "::"              → "127.0.0.1"
#    streamSettings.sockopt.acceptProxyProtocol: true (добавить)
#
#  НЕ ТРОГАЕТ:
#    - realitySettings.dest (decoy-сокет, отдельная downstream-логика Xray)
#    - другие инбаунды (ShadowTLS/AnyTLS/TUIC config — отдельный sing-box)
#    - применим ТОЛЬКО к REALITY-инбаунду, и ТОЛЬКО в REALITY-режиме
#      (xHTTP/AWG — патч явно отказывается применяться)
# ============================================================================

# Suffix для бэкапа config.json (по аналогии с .pre-sni-dispatch для nginx)
_XRAY_CONFIG_BACKUP_SUFFIX = ".pre-sni-dispatch"


def _xray_config_paths() -> list:
    """Возвращает существующие пути к config.json Xray (в порядке предпочтения).

    /etc/xray/config.json — канонический путь (CONFIG_DIR / "config.json").
    /usr/local/etc/xray/config.json — legacy/alt путь (симлинк для back-compat).
    """
    paths = [
        _Path("/etc/xray/config.json"),
        _Path("/usr/local/etc/xray/config.json"),
    ]
    return [p for p in paths if p.exists()]


def _find_reality_inbound(cfg: dict) -> Optional[dict]:
    """Находит REALITY-инбаунд в config.json Xray.

    Сначала по tag=="inbound-vless" (каноническое имя из xray_install.py:841).
    Fallback — первый inbound с streamSettings.security=="reality"
    (подстраховка, если tag когда-то переименуют).

    Возвращает None если REALITY-инбаунд не найден.
    """
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return None
    # 1. По каноническому tag
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        if ib.get("tag") == "inbound-vless":
            return ib
    # 2. Fallback по security=="reality"
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        ss = ib.get("streamSettings", {})
        if isinstance(ss, dict) and ss.get("security") == "reality":
            return ib
    return None


def _xray_test_config(cfg_path) -> tuple:
    """Запускает `xray -test -config <path>`. Возвращает (ok, output).

    Если xray binary недоступен — возвращает (True, "(xray not installed — skipped)").
    Это позволяет тестировать патч в песочницах без установленного Xray.
    """
    import shutil as _sh
    xray_bin = _sh.which("xray") or "/usr/local/bin/xray"
    if not _Path(xray_bin).exists():
        return True, "(xray binary not available — syntax check skipped)"
    r = _run([xray_bin, "-test", "-config", str(cfg_path)],
             capture=True, quiet=True, check=False)
    output = ((r.stdout or "") + (r.stderr or "")).strip()
    return r.returncode == 0, output


def apply_reality_sni_dispatch_patch(
    cfg_path=None,
    *,
    restart_xray: bool = True,
    skip_mode_check: bool = False,
) -> bool:
    """Патчит config.json Xray для SNI-dispatch (v4.23.8).

    Переносит REALITY-инбаунд с публичного :443 на loopback:8442 и добавляет
    streamSettings.sockopt.acceptProxyProtocol=true — чтобы nginx stream{}
    мог передавать реальный IP клиента через PROXY protocol (критично для
    fail2ban и логирования).

    Идемпотентен — безопасно вызывать многократно. Если конфиг уже пропатчен,
    повторный вызов не создаёт новый бэкап и не ломает структуру.

    НЕ ТРОГАЕТ:
      - realitySettings.dest (decoy-сокет, отдельная downstream-логика Xray)
      - другие инбаунды в config.json (только REALITY-инбаунд)
      - ShadowTLS/AnyTLS/TUIC config (это sing-box, не Xray)

    ГРАНИЦЫ ПРИМЕНИМОСТИ:
      - protocol_mode=="reality" + awg_exit_enabled==False — применим
      - protocol_mode=="xhttp" — ОТКАЗ (nginx http{} уже на :443)
      - awg_exit_enabled==True — ОТКАЗ (Xray на :443 напрямую)

    Args:
      cfg_path: путь к config.json. Если None — авто-поиск по стандартным путям.
      restart_xray: перезапустить xray после патча + active-check.
                    False — для reapply в _rebuild_and_restart_xray(),
                    где вызывающий код сам рестартует xray в конце.
      skip_mode_check: пропустить проверку protocol_mode (для reapply, где
                       проверка уже выполнена выше по стеку вызовов).

    Returns:
      True при успехе, False при ошибке (с откатом из бэкапа при необходимости).
    """
    # 1. Проверка protocol_mode (если не skip)
    if not skip_mode_check:
        backend = _detect_reality_backend()
        if not backend:
            state = _read_main_state()
            proto = state.get("protocol_mode", "reality")
            awg = state.get("awg_exit_enabled", False)
            if proto == "xhttp":
                error("SNI-dispatch patch неприменим в xHTTP-режиме "
                      "(nginx http{} уже на :443)")
            elif proto == "xhttp_reality":
                error("SNI-dispatch patch неприменим в xHTTP+REALITY-режиме "
                      "(Xray владеет :443, REALITY TLS + xhttp)")
            elif awg:
                error("SNI-dispatch patch неприменим в AWG-режиме "
                      "(Xray на :443 напрямую)")
            else:
                error("SNI-dispatch patch: не удалось определить REALITY backend")
            return False

    # 2. Находим config.json
    if cfg_path is None:
        candidates = _xray_config_paths()
        if not candidates:
            error("config.json Xray не найден — сначала выполните установку")
            return False
        cfg_path = candidates[0]
    elif not _Path(cfg_path).exists():
        error(f"config.json не найден: {cfg_path}")
        return False
    cfg_path = _Path(cfg_path)

    # 3. Читаем JSON
    try:
        cfg = _json.loads(cfg_path.read_text())
    except Exception as e:
        error(f"Не удалось прочитать {cfg_path}: {e}")
        return False
    if not isinstance(cfg, dict) or "inbounds" not in cfg:
        error(f"{cfg_path}: некорректная структура config.json")
        return False

    # 4. Находим REALITY-инбаунд
    inbound = _find_reality_inbound(cfg)
    if inbound is None:
        error("REALITY-инбаунд не найден в config.json — patch неприменим")
        return False

    # 5. Бэкап (только первый раз — идемпотентность)
    backup_path = cfg_path.with_suffix(cfg_path.suffix + _XRAY_CONFIG_BACKUP_SUFFIX)
    if not backup_path.exists():
        try:
            backup_path.write_text(cfg_path.read_text())
            info(f"Бэкап config.json: {backup_path}")
        except Exception as e:
            warn(f"Не удалось создать бэкап ({e}) — продолжаю без него")

    # 6. Запоминаем оригинальные значения в state (для revert без бэкапа)
    sd_state = singbox_state_get_sni_dispatch()
    if "original_listen" not in sd_state:
        sd_state["original_listen"] = inbound.get("listen", "::")
        sd_state["original_port"]   = inbound.get("port", 443)
        singbox_state_set_sni_dispatch(sd_state)

    # 7. Патчим — listen, port, acceptProxyProtocol
    #    Идемпотентность: установка значений поверх существующих безопасна.
    inbound["listen"] = "127.0.0.1"
    inbound["port"]   = _REALITY_LOOPBACK_PORT

    stream_settings = inbound.setdefault("streamSettings", {})
    if not isinstance(stream_settings, dict):
        stream_settings = {}
        inbound["streamSettings"] = stream_settings
    sockopt = stream_settings.setdefault("sockopt", {})
    if not isinstance(sockopt, dict):
        sockopt = {}
        stream_settings["sockopt"] = sockopt
    sockopt["acceptProxyProtocol"] = True

    # 8. realitySettings.dest НЕ ТРОГАЕМ — это decoy-сокет (PARAM_SOCKET_PATH),
    #    отдельная downstream-логика Xray для non-REALITY трафика.
    #    (Регресс-тест: test_reality_dest_untouched)

    # 9. Атомарная запись через .tmp → replace (по образцу singbox_state_save)
    try:
        tmp_path = cfg_path.with_suffix(cfg_path.suffix + ".tmp")
        tmp_path.write_text(_json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
        tmp_path.replace(cfg_path)
    except Exception as e:
        error(f"Не удалось записать {cfg_path}: {e}")
        return False

    info(f"config.json пропатчен: listen=127.0.0.1, port={_REALITY_LOOPBACK_PORT}, "
         f"acceptProxyProtocol=true")

    # 10. xray -test (если binary доступен — иначе skip с warn-уровнем)
    ok, output = _xray_test_config(cfg_path)
    if not ok:
        error(f"xray -test провален после патча:")
        error(output[:400])
        # Откат из бэкапа
        if backup_path.exists():
            try:
                cfg_path.write_text(backup_path.read_text())
                error("config.json восстановлен из бэкапа")
            except Exception:
                error("Не удалось восстановить из бэкапа — конфиг сломан!")
        return False
    if output and "skipped" not in output:
        info("xray -test: OK")

    # 11. systemctl restart xray + active-check
    if restart_xray:
        # (start-limit-fix): reset-failed перед рестартом
        _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(3)
        rs = _run(["systemctl", "is-active", "xray"],
                  capture=True, check=False, quiet=True)
        if (rs.stdout or "").strip() != "active":
            error("Xray не запустился после патча — "
                  "проверьте: journalctl -u xray -n 30")
            # Откат из бэкапа + повторный restart
            if backup_path.exists():
                try:
                    cfg_path.write_text(backup_path.read_text())
                    # (start-limit-fix): reset-failed — это ВТОРОЙ рестарт
                    # подряд (после провала первого) — старт-лимит вероятен
                    _run(["systemctl", "reset-failed", "xray"],
                         check=False, quiet=True)
                    _run(["systemctl", "restart", "xray"],
                         check=False, quiet=True)
                    error("config.json восстановлен из бэкапа, xray перезапущен")
                except Exception:
                    pass
            return False
        success("Xray активен с SNI-dispatch патчем")

    return True


def revert_reality_sni_dispatch_patch(
    cfg_path=None,
    *,
    restart_xray: bool = True,
) -> bool:
    """Откатывает патч SNI-dispatch на config.json Xray (v4.23.8).

    Возвращает REALITY-инбаунд на :443 напрямую, убирает acceptProxyProtocol.

    Стратегия:
      1. Если есть .pre-sni-dispatch бэкап — восстанавливаем из него
         (наиболее надёжный путь — гарантирует идентичность оригиналу)
      2. Иначе reverse-patch: listen/port из state (или defaults),
         удаляем acceptProxyProtocol из sockopt.

    Args:
      cfg_path: путь к config.json. Если None — авто-поиск.
      restart_xray: перезапустить xray + active-check.

    Returns:
      True при успехе, False при ошибке.
    """
    # 1. Находим config.json
    if cfg_path is None:
        candidates = _xray_config_paths()
        if not candidates:
            warn("config.json Xray не найден — откат не нужен")
            return True
        cfg_path = candidates[0]
    elif not _Path(cfg_path).exists():
        warn(f"config.json не найден: {cfg_path} — откат не нужен")
        return True
    cfg_path = _Path(cfg_path)

    backup_path = cfg_path.with_suffix(cfg_path.suffix + _XRAY_CONFIG_BACKUP_SUFFIX)

    # 2. Если есть бэкап — восстанавливаем (предпочтительный путь)
    if backup_path.exists():
        try:
            cfg_path.write_text(backup_path.read_text())
            info(f"config.json восстановлен из бэкапа: {backup_path}")
        except Exception as e:
            error(f"Не удалось восстановить из бэкапа: {e}")
            return False
    else:
        # 3. Reverse-patch без бэкапа
        try:
            cfg = _json.loads(cfg_path.read_text())
        except Exception as e:
            error(f"Не удалось прочитать {cfg_path}: {e}")
            return False
        if not isinstance(cfg, dict):
            error(f"{cfg_path}: некорректная структура config.json")
            return False

        inbound = _find_reality_inbound(cfg)
        if inbound is None:
            warn("REALITY-инбаунд не найден — откат не нужен")
            return True

        # Читаем оригинальные значения из state, fallback на defaults
        sd_state = singbox_state_get_sni_dispatch()
        main_state = _read_main_state()
        original_listen = sd_state.get("original_listen", "::")
        original_port = sd_state.get(
            "original_port",
            main_state.get("server_port", 443),
        )

        inbound["listen"] = original_listen
        inbound["port"]   = original_port

        stream_settings = inbound.get("streamSettings", {})
        if isinstance(stream_settings, dict):
            sockopt = stream_settings.get("sockopt", {})
            if isinstance(sockopt, dict):
                sockopt.pop("acceptProxyProtocol", None)

        try:
            tmp_path = cfg_path.with_suffix(cfg_path.suffix + ".tmp")
            tmp_path.write_text(_json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
            tmp_path.replace(cfg_path)
        except Exception as e:
            error(f"Не удалось записать {cfg_path}: {e}")
            return False

        info(f"config.json reverse-patched: listen={original_listen}, "
             f"port={original_port}, acceptProxyProtocol убран")

    # 4. xray -test
    ok, output = _xray_test_config(cfg_path)
    if not ok:
        error(f"xray -test провален после отката:")
        error(output[:400])
        return False

    # 5. systemctl restart xray + active-check
    if restart_xray:
        # (start-limit-fix): reset-failed перед рестартом (это рестарт
        # после отката конфига — второй за короткое окно)
        _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(3)
        rs = _run(["systemctl", "is-active", "xray"],
                  capture=True, check=False, quiet=True)
        if (rs.stdout or "").strip() != "active":
            error("Xray не запустился после отката — "
                  "проверьте: journalctl -u xray -n 30")
            return False
        success("Xray активен после отката SNI-dispatch патча")

    return True


def sni_dispatch_reapply_after_rebuild() -> None:
    """Хук для вызова после пересоздания config.json (v4.23.8).

    Если в singbox_state включён SNI-dispatch и auto_configured=True —
    пере-применяем патч к свежему config.json. Иначе generate_xray_config*
    вернёт REALITY-инбаунд обратно на публичный :443 — конфликт биндинга
    с nginx stream{}, и все клиенты получают connection refused.

    Вызывается из _core._rebuild_and_restart_xray() ПОСЛЕ
    server_fragment_reapply_after_rebuild() и ДО рестарта xray.
    restart_xray=False — вызывающий код сам рестартует xray в конце.

    Порядок операций сохранён:
      1. generate_xray_config* перезаписывает config.json
      2. _users_patch_config_no_restart — восстановление пользователей
      3. _ru_subnets_restore_if_needed — RIPE-правила
      4. telemt_tproxy_emergency_restore — Telemt
      5. restore_pq_vless_if_enabled — PQ VLESS
      6. server_fragment_reapply_after_rebuild — server-side fragment
      7. sni_dispatch_reapply_after_rebuild (эта функция) — SNI-dispatch патч
      8. systemctl restart xray — финальный рестарт
      9. systemctl restart nginx (если REALITY + Unix-сокет) — nginx restart

    nginx НЕ трогаем здесь — он уже настроен отдельным потоком
    auto_enable_sni_dispatch() и не зависит от regenerate config.json.
    """
    sd = singbox_state_get_sni_dispatch()
    if not sd.get("enabled"):
        return
    if not sd.get("auto_configured"):
        # Ручной режим — пользователь патчил вручную, не трогаем
        return

    backend = _detect_reality_backend()
    if not backend:
        # protocol_mode сменился на xHTTP/AWG — патч неприменим
        state = _read_main_state()
        proto = state.get("protocol_mode", "reality")
        awg = state.get("awg_exit_enabled", False)
        if proto in ("xhttp", "xhttp_reality") or awg:
            warn("SNI-dispatch: protocol_mode сменился на xHTTP/AWG — "
                 "патч отменён. Требуется ручное отключение SNI-dispatch.")
        return

    info("SNI-dispatch был включён — пере-применяю патч config.json")
    apply_reality_sni_dispatch_patch(restart_xray=False, skip_mode_check=True)
