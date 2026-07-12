"""
vless_installer/modules/singbox_nginx.py
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

from vless_installer.modules.singbox_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run,
    DEFAULT_PORT_SHADOWTLS, DEFAULT_PORT_ANYTLS,
)
from vless_installer.modules.singbox_state import (
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

    return f"""# sing-box SNI-dispatch — generated by VLESS Ultimate Installer
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
    # proxy_protocol on;  # включить если backend поддерживает PROXY protocol
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
