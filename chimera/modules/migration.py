"""
chimera/modules/migration.py
───────────────────────────────────────────────────────────────────────────────
МОДУЛЬ 5: Полная миграция установки между серверами (зашифрованный архив).

Содержит:
  • ``TG_CONFIG_FILE`` — путь к /var/lib/xray-installer/telegram.json
    (конфиг Telegram-бота; включается в миграционный архив).
  • ``do_full_migration_export()`` — упаковка config.json, сертификатов
    Let's Encrypt, ключей REALITY, users.json, state.json, traffic_limits.json,
    telegram.json, split_tunnel_custom.json, systemd-unit'а Xray (а также
    AWG-конфигов при установленном Режиме B+AWG) в tar.gz, шифрование
    AES-256-CBC (openssl) и сохранение в /root/xray-migration-*.tar.gz.enc.
  • ``do_full_migration_import()`` — обратная операция: дешифровка архива,
    извлечение файлов в правильные пути, авто-патч socket-пути в config.json,
    ``xray run -test`` и перезапуск сервиса.

Точки входа из _core.py:
    from chimera.modules.migration import (
        do_full_migration_export, do_full_migration_import,
    )

Доступ к helpers ядра (``_box_*``, ``_run``, ``warn``/``info``/``success``,
ANSI-цвета, ``STATE_FILE``, ``CONFIG_DIR``, ``USERS_FILE``,
``TRAFFIC_LIMITS_FILE``, ``SPLIT_TUNNEL_CUSTOM_FILE``, ``XRAY_SERVICE``,
``XRAY_BIN``, ``_patch_imported_config_socket``, ``log_to_file``) — через
importlib (см. _core_module()).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import shutil
import tempfile
import textwrap
import time
from datetime import datetime
from pathlib import Path


# ── Константы ─────────────────────────────────────────────────────────────────
TG_CONFIG_FILE = Path("/var/lib/xray-installer/telegram.json")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  МОДУЛЬ 5: ПОЛНАЯ МИГРАЦИЯ (ЗАШИФРОВАННЫЙ АРХИВ)
# =============================================================================
def do_full_migration_export() -> None:
    """
    Полная миграция: config.json, сертификаты, ключи REALITY,
    users.json, state.json — упаковка в зашифрованный архив (AES-256).
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _run = core._run
    warn    = core.warn
    info    = core.info
    success = core.success
    dim     = core.dim
    log_to_file = core.log_to_file
    STATE_FILE            = core.STATE_FILE
    CONFIG_DIR            = core.CONFIG_DIR
    USERS_FILE            = core.USERS_FILE
    TRAFFIC_LIMITS_FILE   = core.TRAFFIC_LIMITS_FILE
    SPLIT_TUNNEL_CUSTOM_FILE = core.SPLIT_TUNNEL_CUSTOM_FILE
    XRAY_SERVICE          = core.XRAY_SERVICE
    YELLOW = core.YELLOW
    NC     = core.NC

    import getpass, tarfile as _tarfile

    print()
    print()
    _box_top(f"Полный экспорт для миграции")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    archive_path = Path(f"/root/xray-migration-{ts}.tar.gz.enc")

    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass

    include_paths = [
        (CONFIG_DIR / "config.json",              "etc/xray/config.json"),
        (Path("/usr/local/etc/xray/config.json"), "usr_local/etc/xray/config.json"),
        (STATE_FILE,                              "state.json"),
        (USERS_FILE,                              "users.json"),
        (TRAFFIC_LIMITS_FILE,                     "traffic_limits.json"),
        (TG_CONFIG_FILE,                          "telegram.json"),
        (SPLIT_TUNNEL_CUSTOM_FILE,                "split_tunnel_custom.json"),
        (XRAY_SERVICE,                            "etc/systemd/system/xray.service"),
    ]
    # AWG 2.0 конфиги (если активен)
    try:
        if STATE_FILE.exists():
            _st = json.loads(STATE_FILE.read_text())
            if _st.get("awg_exit_enabled") and _st.get("install_mode") == "B":
                _awg_conf_dir = Path("/etc/amnezia/amneziawg")
                for _awg_f in _awg_conf_dir.glob("*.conf") if _awg_conf_dir.exists() else []:
                    include_paths.append((_awg_f, f"amnezia/amneziawg/{_awg_f.name}"))
                _awg_svc = Path(f"/etc/systemd/system/amneziawg-awg0.service")
                if _awg_svc.exists():
                    include_paths.append((_awg_svc, "etc/systemd/system/amneziawg-awg0.service"))
    except Exception:
        pass
    # SSL-сертификаты
    if domain:
        le_dir = Path(f"/etc/letsencrypt/live/{domain}")
        for fname in ("fullchain.pem", "privkey.pem", "chain.pem"):
            p = le_dir / fname
            if p.exists():
                include_paths.append((p, f"letsencrypt/{domain}/{fname}"))
        arc_dir = Path(f"/etc/letsencrypt/archive/{domain}")
        if arc_dir.exists():
            for f in arc_dir.iterdir():
                if f.is_file():
                    include_paths.append((f, f"letsencrypt/archive/{domain}/{f.name}"))

    _box_row(f"  {YELLOW}Архив будет зашифрован паролем (AES-256-CBC){NC}")
    _box_bottom()
    while True:
        pw1 = getpass.getpass("  Пароль шифрования: ")
        if len(pw1) < 8:
            warn("  Пароль должен быть не менее 8 символов")
            continue
        pw2 = getpass.getpass("  Повторите пароль:   ")
        if pw1 == pw2:
            break
        warn("  Пароли не совпадают")

    with tempfile.TemporaryDirectory(prefix="xray_migration_") as tmpdir:
        tmp = Path(tmpdir)
        copied = []
        for src, dest_rel in include_paths:
            if not src.exists():
                continue
            dest = tmp / dest_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            copied.append(dest_rel)
            dim(f"  + {dest_rel}")

        if not copied:
            warn("Нечего экспортировать")
            return

        (tmp / "README.txt").write_text(textwrap.dedent(f"""\
            VLESS Ultimate Installer — Полный архив миграции
            Создан: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Домен:  {domain or '—'}
            Файлов: {len(copied)}

            Для восстановления:
              1. Установите Xray на новом сервере
              2. Запустите install_pinned_nodes.py
              3. X → [3] Полный импорт (зашифрованный)
        """))

        tmp_tar = tmp / f"migration_{ts}.tar.gz"
        with _tarfile.open(tmp_tar, "w:gz") as tar:
            for item in tmp.iterdir():
                if item != tmp_tar:
                    tar.add(item, arcname=item.name)

        r = _run([
            "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
            "-in", str(tmp_tar), "-out", str(archive_path),
            "-pass", f"pass:{pw1}",
        ], capture=True, check=False)

        if r.returncode != 0:
            warn(f"Ошибка шифрования: {r.stderr[:200]}")
            return

    archive_path.chmod(0o600)
    size_kb = archive_path.stat().st_size // 1024
    success(f"Архив создан: {archive_path} ({size_kb} КБ, {len(copied)} файлов)")
    info(f"Скопируйте: scp root@{domain or 'SERVER'}:{archive_path} ./")
    log_to_file("INFO", f"Full migration export: {archive_path} ({len(copied)} files)")


def do_full_migration_import() -> None:
    """Импорт полного архива миграции (зашифрованного .tar.gz.enc или обычного .tar.gz)."""
    core = _core_module()
    _run = core._run
    warn    = core.warn
    info    = core.info
    success = core.success
    dim     = core.dim
    log_to_file = core.log_to_file
    _patch_imported_config_socket = core._patch_imported_config_socket
    CONFIG_DIR            = core.CONFIG_DIR
    STATE_FILE            = core.STATE_FILE
    USERS_FILE            = core.USERS_FILE
    TRAFFIC_LIMITS_FILE   = core.TRAFFIC_LIMITS_FILE
    SPLIT_TUNNEL_CUSTOM_FILE = core.SPLIT_TUNNEL_CUSTOM_FILE
    XRAY_SERVICE          = core.XRAY_SERVICE
    XRAY_BIN              = core.XRAY_BIN
    YELLOW = core.YELLOW
    NC     = core.NC
    DIM    = core.DIM

    import getpass, tarfile as _tarfile

    print()
    archive_raw  = input(f"  Путь к архиву (.tar.gz или .tar.gz.enc): ").strip()
    archive_path = Path(archive_raw)
    if not archive_path.exists():
        warn(f"Файл не найден: {archive_path}")
        return

    is_encrypted = archive_path.suffix == ".enc"

    pw = ""
    if is_encrypted:
        pw = getpass.getpass("  Пароль шифрования: ")
    else:
        info("Архив без шифрования — пароль не требуется")
    print()
    warn("ВНИМАНИЕ: импорт перезапишет текущие конфиги, сертификаты и ключи!")
    ans = input(f"{YELLOW}Продолжить? [y/N]:{NC} ").strip().lower()
    if ans != "y":
        info("Отменено")
        return

    with tempfile.TemporaryDirectory(prefix="xray_migimp_") as tmpdir:
        if is_encrypted:
            tmp_tar = Path(tmpdir) / "migration.tar.gz"
            r = _run([
                "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
                "-in", str(archive_path), "-out", str(tmp_tar),
                "-pass", f"pass:{pw}",
            ], capture=True, check=False)
            if r.returncode != 0:
                warn("Ошибка дешифрования — неверный пароль или повреждённый файл")
                return
        else:
            tmp_tar = archive_path

        if not _tarfile.is_tarfile(tmp_tar):
            warn("Файл не является tar-архивом" + (" после дешифрования" if is_encrypted else ""))
            return

        with _tarfile.open(tmp_tar, "r:gz") as tar:
            tar.extractall(tmpdir)

        tmp = Path(tmpdir)
        restore_map = [
            ("etc/xray/config.json",           CONFIG_DIR / "config.json"),
            ("usr_local/etc/xray/config.json", Path("/usr/local/etc/xray/config.json")),
            ("state.json",                     STATE_FILE),
            ("users.json",                     USERS_FILE),
            ("traffic_limits.json",            TRAFFIC_LIMITS_FILE),
            ("telegram.json",                  TG_CONFIG_FILE),
            ("split_tunnel_custom.json",       SPLIT_TUNNEL_CUSTOM_FILE),
            ("etc/systemd/system/xray.service",XRAY_SERVICE),
        ]
        restored = []

        # Сертификаты
        le_src = tmp / "letsencrypt"
        if le_src.exists():
            for src in le_src.rglob("*"):
                if src.is_file():
                    rel = src.relative_to(le_src)
                    dst = Path("/etc/letsencrypt/live") / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
                    try:
                        dst.chmod(0o600 if "privkey" in src.name else 0o644)
                    except Exception:
                        pass
                    restored.append(f"letsencrypt/{rel}")
                    dim(f"  + letsencrypt/{rel}")

        for rel, dst in restore_map:
            # Ищем в извлечённой структуре
            candidates = list(tmp.rglob(Path(rel).name))
            src = next((c for c in candidates if rel.split("/")[-1] in c.name), None)
            if src is None:
                src_direct = tmp / rel
                if src_direct.exists():
                    src = src_direct
            if src is None:
                dim(f"  - {rel} (не найден в архиве)")
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            try:
                dst.chmod(0o640)
            except Exception:
                pass
            restored.append(rel)
            dim(f"  + {rel} → {dst}")

    if not restored:
        warn("Ни один файл не был восстановлен")
        return

    success(f"Восстановлено файлов: {len(restored)}")
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)

    # ── ПАТЧ СОКЕТА ─────────────────────────────────────────────────────────
    # При миграции на новый сервер socket-путь может отличаться.
    # Если в бэкапе /dev/shm/OLDNAME.socket, а текущий state.json
    # содержит другой путь — патчим config.json автоматически.
    print()
    info("Проверка socket-пути в импортированном конфиге...")
    socket_patched = False
    for _cp in (CONFIG_DIR / "config.json",
                Path("/usr/local/etc/xray/config.json")):
        if _patch_imported_config_socket(_cp):
            socket_patched = True
    if not socket_patched:
        dim("  socket-путь совпадает или патч не требуется")

    val = _run([str(XRAY_BIN), "run", "-test", "-config",
                str(CONFIG_DIR / "config.json")],
               capture=True, check=False, quiet=True)
    if val.returncode == 0:
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(2)
        r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if r.stdout.strip() == "active":
            success("Xray запущен с восстановленным конфигом")
        else:
            warn("Xray не запустился — journalctl -u xray -n 20")
            r_jnl = _run(["journalctl", "-u", "xray", "-n", "10", "--no-pager"],
                         capture=True, check=False, quiet=True)
            if r_jnl.stdout.strip():
                print(f"{DIM}{r_jnl.stdout.strip()}{NC}")
    else:
        warn("Конфиг невалиден после восстановления — Xray не перезапускался")
        warn((val.stdout + val.stderr)[:300])
    log_to_file("INFO", f"Full migration import: {len(restored)} files restored, socket_patched={socket_patched}")
