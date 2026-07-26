"""
chimera/modules/awg_qr.py
───────────────────────────────────────────────────────────────────────────────
Генерация QR-кодов и vpn:// URI для клиентов AmneziaWG.

QR-коды рендерятся в терминал (через qrencode -t ANSIUTF8) и сохраняются
в PNG (через qrencode -t PNG). Делегирует в core._show_qr для consistency.
"""
from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path
from typing import Optional

from .awg_constants import AWGS_KEYS_DIR


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ── Генерация клиентского конфига (.conf) ───────────────────────────────────

def awgs_qr_build_client_conf(peer: dict, server_state: dict) -> str:
    """
    Генерирует содержимое клиентского .conf файла.
    peer: dict из awgs_state (с client_privkey, client_ip, и т.д.)
    server_state: dict из awgs_state (с server_pubkey, port, params, endpoint)
    """
    params = server_state.get("params", {})
    endpoint = server_state.get("endpoint_host") or server_state.get("endpoint", "")
    port = server_state.get("port", 51820)
    server_pubkey = server_state.get("server_pubkey", "")
    mtu = server_state.get("mtu", 1280)
    allow_ipv6 = server_state.get("allow_ipv6_tunnel", False)

    client_ip = peer.get("client_ip", "")
    client_ipv6 = peer.get("client_ipv6", "")
    client_privkey = peer.get("client_privkey", "")
    psk = peer.get("preshared_key", "")
    dns1 = peer.get("dns1", "1.1.1.1")
    dns2 = peer.get("dns2", "8.8.8.8")

    # AllowedIPs: 0.0.0.0/0 (route all). Если каскад — клиенту не нужно знать.
    allowed_ips = "0.0.0.0/0"
    if allow_ipv6 and client_ipv6:
        allowed_ips += f", ::/0"

    lines = [
        "[Interface]",
        f"PrivateKey = {client_privkey}",
        f"Address = {client_ip}/32",
    ]
    if allow_ipv6 and client_ipv6:
        lines.append(f"Address = {client_ipv6}/128")
    lines.append(f"DNS = {dns1}, {dns2}")
    lines.append(f"MTU = {mtu}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pubkey}")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}:{port}")
    lines.append(f"AllowedIPs = {allowed_ips}")
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines.append("PersistentKeepalive = 25")
    lines.append("")
    # Параметры AWG 2.0
    lines.append(f"Jc = {params.get('jc', 4)}")
    lines.append(f"Jmin = {params.get('jmin', 40)}")
    lines.append(f"Jmax = {params.get('jmax', 70)}")
    lines.append(f"S1 = {params.get('s1', 0)}")
    lines.append(f"S2 = {params.get('s2', 0)}")
    lines.append(f"S3 = {params.get('s3', 0)}")
    lines.append(f"S4 = {params.get('s4', 0)}")
    lines.append(f"H1 = {params.get('h1', 1)}")
    lines.append(f"H2 = {params.get('h2', 2)}")
    lines.append(f"H3 = {params.get('h3', 3)}")
    lines.append(f"H4 = {params.get('h4', 4)}")
    # v5.4: I1-I5 — КОММЕНТИРУЕМ пустые (как в эталонном конфиге Amnezia).
    # См. awg_standalone.awgs_build_server_conf() для подробного обоснования.
    # Коротко: старые amneziawg-tools падают на 'I2 = ' (пустая строка),
    # но игнорируют '# I2 = '. Закомментированные строки работают везде.
    for key in ("i1", "i2", "i3", "i4", "i5"):
        val = params.get(key, "")
        if val:
            lines.append(f"{key.upper()} = {val}")
        else:
            lines.append(f"# {key.upper()} = ")

    return "\n".join(lines) + "\n"


# ── Сохранение клиентского конфига в файл ───────────────────────────────────

def awgs_qr_save_client_conf(peer: dict, server_state: dict) -> Optional[Path]:
    """Сохраняет .conf файл клиента в /root/awg/keys/<name>.conf."""
    core = _core_module()
    try:
        AWGS_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        # AWGS_KEYS_DIR содержит приватные ключи (.conf, .vpnuri, _qr.png) —
        # 0o700 чтобы другие локальные юзеры не могли читать содержимое.
        try:
            AWGS_KEYS_DIR.chmod(0o700)
        except Exception as e:
            # Тихий провал chmod на директории с секретами недопустим —
            # логируем WARNING, чтобы админ заметил в /var/log/chimera.log.
            core.log_to_file("WARNING", f"chmod 0o700 failed for {AWGS_KEYS_DIR}: {e}")
        name = peer.get("name", "client")
        path = AWGS_KEYS_DIR / f"{name}.conf"
        content = awgs_qr_build_client_conf(peer, server_state)
        path.write_text(content)
        path.chmod(0o600)
        return path
    except Exception as e:
        core = _core_module()
        core.log_to_file("ERROR", f"awgs_qr_save_client_conf: {e}")
        return None


# ── Генерация vpn:// URI ────────────────────────────────────────────────────

def awgs_qr_build_vpn_uri(peer: dict, server_state: dict) -> str:
    """
    Генерирует vpn:// URI для импорта в Amnezia Client одним тапом.
    Формат перенесён из bivlked (awg_common.sh, _build_vpnuri).
    """
    params = server_state.get("params", {})
    endpoint = server_state.get("endpoint_host") or server_state.get("endpoint", "")
    port = server_state.get("port", 51820)
    server_pubkey = server_state.get("server_pubkey", "")
    mtu = server_state.get("mtu", 1280)

    client_ip = peer.get("client_ip", "")
    client_ipv6 = peer.get("client_ipv6", "")
    client_privkey = peer.get("client_privkey", "")
    psk = peer.get("preshared_key", "")

    # Build inner config (raw .conf content)
    raw_conf = awgs_qr_build_client_conf(peer, server_state)

    # Build inner JSON (как в bivlked _build_vpnuri)
    inner = {
        "H1": str(params.get("h1", 1)),
        "H2": str(params.get("h2", 2)),
        "H3": str(params.get("h3", 3)),
        "H4": str(params.get("h4", 4)),
        "Jc": str(params.get("jc", 4)),
        "Jmin": str(params.get("jmin", 40)),
        "Jmax": str(params.get("jmax", 70)),
        "S1": str(params.get("s1", 0)),
        "S2": str(params.get("s2", 0)),
        "S3": str(params.get("s3", 0)),
        "S4": str(params.get("s4", 0)),
    }
    # I1-I5 (опционально)
    for k in ("i1", "i2", "i3", "i4", "i5"):
        v = params.get(k, "")
        if v:
            inner[k.upper()] = str(v)
    inner["allowed_ips"] = ["0.0.0.0/0"]
    inner["client_ip"] = client_ip
    inner["client_ipv6"] = client_ipv6 or ""
    inner["client_priv_key"] = client_privkey
    if psk:
        inner["psk_key"] = psk
    inner["config"] = raw_conf
    inner["hostName"] = endpoint
    inner["mtu"] = str(mtu)
    inner["persistent_keep_alive"] = "25"
    inner["port"] = port
    inner["server_pub_key"] = server_pubkey

    inner_json = json.dumps(inner, ensure_ascii=False)
    inner_b64 = base64.b64encode(inner_json.encode("utf-8")).decode("ascii")

    outer = {
        "containers": [{
            "awg": {
                "isThirdPartyConfig": True,
                "last_config": inner_json,
                "port": str(port),
                "protocol_version": "2",
                "transport_proto": "udp",
            },
            "container": "amnezia-awg",
        }],
        "defaultContainer": "amnezia-awg",
    }
    outer_json = json.dumps(outer, ensure_ascii=False)
    outer_b64 = base64.b64encode(outer_json.encode("utf-8")).decode("ascii")

    return f"vpn://free/{outer_b64}/{inner_b64}"


# ── QR-код в терминал ───────────────────────────────────────────────────────

def awgs_qr_show_terminal(content: str, label: str = "") -> bool:
    """
    Показывает QR-код в терминале через `qrencode -t ANSIUTF8`.
    content может быть .conf файлом или vpn:// URI.

    Для длинных vpn:// URI (1500-2000+ символов) использует флаг -l L
    (низший уровень error correction) — это позволяет вместить больше данных.
    Если всё равно не помещается — возвращает False (вызывающий код может
    показать .conf QR вместо него, он короче).
    """
    core = _core_module()
    r = core._run(["which", "qrencode"], capture=True, check=False)
    if r.returncode != 0:
        core.warn("qrencode не установлен — QR показать нельзя")
        return False
    if label:
        print(f"\n{core.CYAN}{label}{core.NC}")
    # -l L — низший уровень error correction (вместо дефолтного M)
    # Это позволяет вместить больше данных в QR-код
    r = core._run(
        ["qrencode", "-t", "ANSIUTF8", "-o", "-", "-l", "L"],
        input_text=content,
        capture=True, check=False,
    )
    if r.returncode == 0 and r.stdout.strip():
        print(r.stdout)
        return True
    # QR не помещается — это нормально для длинных vpn:// URI
    if "too large" in (r.stderr or "").lower():
        core.warn("QR из vpn:// URI слишком большой для терминала — используйте .conf QR ниже")
    else:
        core.warn(f"qrencode: {r.stderr}")
    return False


def awgs_qr_save_png(content: str, path: Path) -> bool:
    """
    Сохраняет QR-код в PNG файл.
    Для длинных vpn:// URI использует -l L (низший error correction) —
    как в bivlked awg_common.sh:1824 (issue #72).

    ВАЖНО: PNG содержит vpn:// URI с приватным ключом клиента + PSK —
    это боевой секрет. Файл создаётся с правами 0o600, чтобы другие
    локальные юзеры на сервере не могли его прочитать. Раньше (до фикса)
    PNG создавался с дефолтными правами umask (часто 0o644) — что было
    "тихим" багом, пока PNG не начал активно отдаваться через REST API
    /api/awg/peers/{name}/qr и /api/awg/my-peer/qr.
    """
    core = _core_module()
    r = core._run(["which", "qrencode"], capture=True, check=False)
    if r.returncode != 0:
        return False
    # -l L — низший уровень error correction (вместо дефолтного M)
    # -s 6 — размер модуля 6px (читаемый на экране телефона)
    # -m 4 — margin 4 модуля (минимум для сканирования)
    r = core._run(
        ["qrencode", "-t", "PNG", "-l", "L", "-s", "6", "-m", "4", "-o", str(path)],
        input_text=content,
        capture=True, check=False,
    )
    if r.returncode != 0:
        return False
    # chmod 0o600 — PNG содержит приватный ключ + PSK в виде vpn:// URI.
    # Без этого файл создаётся с umask-правами (часто 0o644) и читается
    # любым локальным юзером на сервере.
    try:
        path.chmod(0o600)
    except Exception as e:
        # Тихий провал chmod на файле с приватным ключом недопустим —
        # логируем WARNING, файл остаётся с umask-правами (возможно читаем
        # другими юзерами), но отдавать 500 на QR-запрос тоже неправильно
        # (QR валиден). Админ должен заметить в логе и починить права.
        core.log_to_file("WARNING", f"chmod 0o600 failed for PNG {path}: {e}")
    return True


# ── Полный экспорт пира ─────────────────────────────────────────────────────

def awgs_qr_export_peer(peer: dict, show_terminal: bool = True) -> dict:
    """
    Полный экспорт пира:
      • .conf файл (для AmneziaWG Windows client)
      • vpn:// URI (для Amnezia Client одним тапом)
      • QR-код в терминале (vpn:// URI, fallback на .conf если слишком длинный)
        — только при show_terminal=True (TUI-контекст)
      • PNG файлы с QR-кодом (vpn:// URI + .conf)
    Возвращает dict с путями.

    Параметр show_terminal:
      • True (default) — TUI-режим: после генерации файлов рисует ANSI QR-код
        в stdout через awgs_qr_show_terminal(). Используется из awg_peers.py
        (TUI-меню), CLI, и подобных интерактивных контекстов.
      • False — API-режим (REST API /api/awg/.../qr, /api/awg/my-peer/qr):
        НЕ печатает QR в stdout. Это критично, потому что под systemd
        stdout процесса уходит в journal (journalctl -u vless-web), а
        ANSI QR-код содержит vpn:// URI с приватным ключом клиента + PSK.
        Печать в journal = утечка боевого секрета в системный лог,
        читаемый любым, у кого есть доступ к journalctl.
        Файлы (.conf, .vpnuri, .png) всё равно создаются — они нужны
        для последующей отдачи через HTTP.
    """
    core = _core_module()
    from .awg_state import awgs_state_load
    server_state = awgs_state_load()
    name = peer.get("name", "client")

    # 0. Гарантируем что AWGS_KEYS_DIR существует и имеет права 0o700.
    # Делаем это ЯВНО в начале export_peer, не полагаясь на побочный эффект
    # awgs_qr_save_client_conf() ниже — потому что export_peer может быть
    # вызван для перегенерации QR у уже существующего пира, когда путь
    # создания директории с правильными правами не гарантированно прошёл
    # (например директория была создана раньше, до ввода chmod 0o700 в коде,
    # или права сбросились внешним скриптом). Если директория уже существует
    # с неправильными правами — mkdir(exist_ok=True) не меняет права, поэтому
    # нужен явный chmod.
    try:
        AWGS_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        AWGS_KEYS_DIR.chmod(0o700)
    except Exception as e:
        # Тихий провал chmod на директории с секретами недопустим —
        # логируем WARNING. Продолжаем работу: файлы всё равно запишутся,
        # но возможно с некорректными правами (админ должен заметить в логе).
        core.log_to_file("WARNING", f"chmod 0o700 failed for {AWGS_KEYS_DIR}: {e}")

    # 1. .conf файл
    conf_path = awgs_qr_save_client_conf(peer, server_state)

    # 2. vpn:// URI
    vpn_uri = awgs_qr_build_vpn_uri(peer, server_state)

    # 3. QR в терминале — только в TUI-режиме (show_terminal=True).
    # В API-режиме (show_terminal=False) пропускаем, чтобы не печатать
    # приватный ключ в stdout → journal.
    qr_shown = False
    if show_terminal:
        # Сначала пробуем vpn:// URI (для импорта в Amnezia Client одним тапом)
        qr_shown = awgs_qr_show_terminal(vpn_uri, label=f"QR-код для {name} (vpn:// URI):")
        # Если vpn:// QR не помещается — показываем QR из .conf файла
        # (.conf короче ~600 символов, всегда помещается в QR)
        if not qr_shown and conf_path and conf_path.exists():
            conf_content = conf_path.read_text()
            awgs_qr_show_terminal(
                conf_content,
                label=f"QR-код для {name} (из .conf файла — для AmneziaWG Windows client):",
            )

    # 4. PNG с QR из vpn:// URI (с -l L для длинных URI, как в bivlked)
    png_vpnuri_path = AWGS_KEYS_DIR / f"{name}_qr.png"
    png_vpnuri_ok = awgs_qr_save_png(vpn_uri, png_vpnuri_path)

    # 5. PNG с QR из .conf файла (всегда помещается)
    png_conf_path = AWGS_KEYS_DIR / f"{name}_qr_conf.png"
    if conf_path and conf_path.exists():
        awgs_qr_save_png(conf_path.read_text(), png_conf_path)

    # 6. Сохраняем vpn:// URI в файл
    uri_path = AWGS_KEYS_DIR / f"{name}.vpnuri"
    try:
        uri_path.write_text(vpn_uri + "\n")
        uri_path.chmod(0o600)
    except Exception as e:
        # .vpnuri содержит приватный ключ + PSK в vpn:// URI — тихий провал
        # chmod недопустим, логируем WARNING.
        core.log_to_file("WARNING", f"chmod 0o600 failed for {uri_path}: {e}")

    return {
        "conf_path":       conf_path,
        "vpn_uri":         vpn_uri,
        "uri_path":        uri_path,
        "png_path":        png_vpnuri_path if png_vpnuri_ok else None,
        "png_conf_path":   png_conf_path,
    }
