"""
vless_installer/modules/ssh_hardening.py
───────────────────────────────────────────────────────────────────────────────
Интерактивное укрепление SSH: смена порта, отключение паролей,
AllowUsers + MaxAuthTries, 2FA (TOTP) через Google Authenticator.

  • _ssh_2fa_install()  — ставит libpam-google-authenticator, патчит PAM
                           и sshd_config, опционально запускает google-authenticator.
  • do_ssh_hardening()  — меню: смена порта / отключение паролей /
                           AllowUsers / применить всё / включить 2FA.

Никаких state.json мутаций. Только /etc/ssh/sshd_config и /etc/pam.d/sshd.

Точки входа из _core.py:
    from vless_installer.modules.ssh_hardening import (
        _SSHD_CONFIG, _SSHD_BACKUP,
        _ssh_2fa_install, do_ssh_hardening,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────────
_SSHD_CONFIG = Path("/etc/ssh/sshd_config")
_SSHD_BACKUP = Path("/root/sshd_config.bak")


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# ============================================================================
#  2FA (TOTP) через Google Authenticator
# ============================================================================
def _ssh_2fa_install() -> bool:
    """
    Устанавливает google-authenticator (libpam-google-authenticator),
    настраивает PAM и sshd для TOTP 2FA.
    Возвращает True если успешно настроено.
    """
    core = _core_module()
    command_exists = core.command_exists
    info           = core.info
    warn           = core.warn
    _run           = core._run
    log_to_file    = core.log_to_file
    _box_row       = core._box_row
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    YELLOW = core.YELLOW
    CYAN, GREEN, YELLOW, BOLD, DIM, NC = (
        core.CYAN, core.GREEN, core.YELLOW, core.BOLD, core.DIM, core.NC
    )

    # Установка пакета
    if not command_exists("google-authenticator"):
        info("Устанавливаем libpam-google-authenticator…")
        r = _run(["apt-get", "install", "-y", "libpam-google-authenticator"],
                 capture=True, check=False)
        if r.returncode != 0 or not command_exists("google-authenticator"):
            warn("Не удалось установить libpam-google-authenticator")
            return False

    # Патч /etc/pam.d/sshd — добавляем google-authenticator если ещё нет
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        pam_text = pam_sshd.read_text()
        ga_line = "auth required pam_google_authenticator.so nullok"
        if ga_line not in pam_text:
            pam_text = ga_line + "\n" + pam_text
            pam_sshd.write_text(pam_text)
            info("PAM /etc/pam.d/sshd обновлён")
    else:
        warn("/etc/pam.d/sshd не найден — PAM не настроен")
        return False

    # Патч sshd_config: включаем ChallengeResponseAuthentication и UsePAM
    sshd_cfg = _SSHD_CONFIG
    sshd_text = sshd_cfg.read_text()

    def _set(param: str, val: str) -> str:
        p = rf"^\s*#?\s*{re.escape(param)}\s+.*"
        line = f"{param} {val}"
        if re.search(p, sshd_text, re.MULTILINE):
            return re.sub(p, line, sshd_text, flags=re.MULTILINE)
        return sshd_text + f"\n{line}\n"

    sshd_text = _set("ChallengeResponseAuthentication", "yes")
    sshd_text = _set("AuthenticationMethods", "publickey,keyboard-interactive")
    sshd_text = _set("UsePAM", "yes")
    sshd_cfg.write_text(sshd_text)

    # Валидация конфига
    r = _run(["sshd", "-t"], capture=True, check=False)
    if r.returncode != 0:
        warn("sshd -t ошибка после правки для 2FA — откатываем")
        shutil.copy2(_SSHD_BACKUP, sshd_cfg)
        return False

    _run(["systemctl", "reload", "sshd"], check=False, quiet=True)

    print()
    _box_row(f"  {GREEN}✓ 2FA PAM настроен{NC}")
    _box_row()
    _box_row(f"  {BOLD}Последний шаг — сгенерируйте TOTP-секрет для root:{NC}")
    _box_row(f"  {CYAN}  google-authenticator -t -d -f -r 3 -R 30 -w 3{NC}")
    _box_row()
    _box_row(f"  {DIM}Отсканируйте QR-код в Google Authenticator / Aegis / Authy.{NC}")
    _box_row(f"  {YELLOW}  Не закрывайте текущую сессию, пока не проверите вход!{NC}")
    _box_row()
    ans = input(f"  Запустить google-authenticator сейчас? [Y/n]: ").strip().lower()
    if ans != "n":
        _run(["google-authenticator", "-t", "-d", "-f", "-r", "3", "-R", "30", "-w", "3"],
             check=False, quiet=False)

    log_to_file("INFO", "SSH 2FA (TOTP) настроен через google-authenticator")
    return True


# ============================================================================
#  Меню SSH Hardening
# ============================================================================
def do_ssh_hardening() -> None:
    """Интерактивное укрепление SSH: смена порта, отключение паролей, AllowUsers, 2FA."""
    core = _core_module()
    command_exists = core.command_exists
    info           = core.info
    warn           = core.warn
    success        = core.success
    _run           = core._run
    log_to_file    = core.log_to_file
    _box_top       = core._box_top
    _box_sep       = core._box_sep
    _box_row       = core._box_row
    _box_item      = core._box_item
    _box_bottom    = core._box_bottom
    _box_warn      = core._box_warn
    _box_ok        = core._box_ok
    _box_info      = core._box_info
    BLUE = core.BLUE
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, GREEN, YELLOW, RED, BLUE, BOLD, DIM, NC = (
        core.CYAN, core.GREEN, core.YELLOW, core.RED, core.BLUE,
        core.BOLD, core.DIM, core.NC
    )

    print()
    print()
    _box_top(f"SSH Hardening")

    if not _SSHD_CONFIG.exists():
        _box_warn("/etc/ssh/sshd_config не найден")
        return

    # --- Показываем последние SSH-входы перед изменением конфига ---
    _box_sep()
    _box_row(f"  {BOLD}Последние SSH-входы на сервер:{NC}")
    try:
        _r_last = _run(
            ["journalctl", "-u", "ssh", "-u", "sshd",
             "--no-pager", "-n", "8",
             "--output=short", "--grep", "Accepted"],
            capture=True, check=False, quiet=True
        )
        _lines = [l for l in _r_last.stdout.strip().splitlines() if l.strip()]
        if _lines:
            for _l in _lines[-8:]:
                _box_row(f"    {DIM}{_l[:100]}{NC}")
        else:
            _r_last2 = _run(["last", "-n", "5", "-F"], capture=True, check=False, quiet=True)
            for _l in _r_last2.stdout.strip().splitlines()[:5]:
                _box_row(f"    {DIM}{_l[:100]}{NC}")
    except Exception:
        _box_row(f"    {DIM}Не удалось получить данные{NC}")
    _box_sep()

    # --- Проверяем наличие SSH-ключа ---
    auth_keys = Path("/root/.ssh/authorized_keys")
    has_key = auth_keys.exists() and len(auth_keys.read_text().strip().splitlines()) > 0
    if has_key:
        _box_ok("SSH-ключ обнаружен в /root/.ssh/authorized_keys")
    else:
        _box_warn("SSH-ключ НЕ найден в /root/.ssh/authorized_keys")
        _box_warn("Отключение паролей без ключа заблокирует вас на сервере!")

    # Статус 2FA
    ga_installed = command_exists("google-authenticator")
    ga_pam_active = False
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        ga_pam_active = "pam_google_authenticator" in pam_sshd.read_text()
    ga_str = (f"{GREEN}активна{NC}" if ga_pam_active
              else f"{YELLOW}не настроена{NC}" if ga_installed
              else f"{DIM}не установлена{NC}")
    _box_row(f"  2FA (TOTP):  {ga_str}")

    # --- Бэкап ---
    try:
        shutil.copy2(_SSHD_CONFIG, _SSHD_BACKUP)
        _box_info(f"Бэкап sshd_config → {_SSHD_BACKUP}")
    except Exception as e:
        _box_warn(f"Не удалось создать бэкап: {e}")

    sshd_text = _SSHD_CONFIG.read_text()

    cur_port = 22
    m = re.search(r"^\s*Port\s+(\d+)", sshd_text, re.MULTILINE)
    if m:
        cur_port = int(m.group(1))
    _box_row(f"  Текущий SSH-порт: {CYAN}{cur_port}{NC}")

    _box_item("1", f"Сменить порт SSH")
    _box_item("2", f"Отключить парольную аутентификацию "
              f"{RED if not has_key else GREEN}"
              f"{'(нет ключа — опасно!)' if not has_key else '(ключ есть — безопасно)'}{NC}")
    _box_item("3", f"Включить AllowUsers + MaxAuthTries=3")
    _box_item("4", f"Применить всё сразу (безопасный набор)")
    _box_item("5", f"🔐 Включить 2FA (TOTP) через Google Authenticator  "
              f"{DIM}{'(уже активна)' if ga_pam_active else ''}{NC}")
    _box_item("Q", f"Назад")
    _box_bottom()
    ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

    if ch == "q" or not ch:
        return

    # --- 2FA — отдельная ветка, не затрагивает sshd_text ---
    if ch == "5":
        if ga_pam_active:
            warn("2FA уже активна. Для перегенерации секрета запустите: google-authenticator -t -d -f -r 3 -R 30 -w 3")
            input(f"{BLUE}Нажмите Enter...{NC}")
            return
        if not has_key:
            print(f"  {RED}⚠  Для 2FA необходим SSH-ключ (иначе вы можете потерять доступ).{NC}")
            ans = input(f"  Продолжить без ключа? [y/N]: ").strip().lower()
            if ans != "y":
                warn("Отменено")
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
        ok = _ssh_2fa_install()
        if ok:
            success("SSH 2FA (TOTP) включена")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    changes = []

    def _sshd_set(param: str, value: str) -> None:
        nonlocal sshd_text
        pattern = rf"^\s*#?\s*{re.escape(param)}\s+.*"
        new_line = f"{param} {value}"
        if re.search(pattern, sshd_text, re.MULTILINE):
            sshd_text = re.sub(pattern, new_line, sshd_text, flags=re.MULTILINE)
        else:
            sshd_text += f"\n{new_line}\n"
        changes.append(f"{param} = {value}")

    new_ssh_port = cur_port

    if ch in ("1", "4"):
        raw = input(f"  Новый SSH-порт [{cur_port}]: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            new_ssh_port = int(raw)
            _sshd_set("Port", str(new_ssh_port))
        else:
            warn("Порт не изменён")

    if ch in ("2", "4"):
        if not has_key:
            ans = input(f"  {RED}Ключ не найден! Всё равно отключить пароли? [y/N]:{NC} ").strip().lower()
            if ans != "y":
                warn("Отключение паролей пропущено")
            else:
                _sshd_set("PasswordAuthentication", "no")
                _sshd_set("ChallengeResponseAuthentication", "no")
                _sshd_set("UsePAM", "no")
        else:
            _sshd_set("PasswordAuthentication", "no")
            _sshd_set("ChallengeResponseAuthentication", "no")
            _sshd_set("UsePAM", "no")

    if ch in ("3", "4"):
        raw_user = input("  AllowUsers (через пробел, Enter = root): ").strip() or "root"
        _sshd_set("AllowUsers", raw_user)
        _sshd_set("MaxAuthTries", "3")
        _sshd_set("LoginGraceTime", "30")
        _sshd_set("PermitRootLogin", "prohibit-password")

    if not changes:
        warn("Нет изменений для применения")
        return

    print()
    print(f"  {BOLD}Будут применены следующие изменения:{NC}")
    for c in changes:
        print(f"    • {c}")
    print()
    ans = input(f"  Подтвердить? [y/N]: ").strip().lower()
    if ans != "y":
        warn("Отменено")
        return

    _SSHD_CONFIG.write_text(sshd_text)

    r = _run(["sshd", "-t"], capture=True, check=False)
    if r.returncode != 0:
        warn("sshd -t вернул ошибку — восстанавливаем бэкап!")
        warn(r.stderr[:300])
        shutil.copy2(_SSHD_BACKUP, _SSHD_CONFIG)
        return

    if new_ssh_port != cur_port:
        _run(["ufw", "allow", str(new_ssh_port), "comment", "SSH hardening"],
             check=False, quiet=True)
        _run(["ufw", "delete", "allow", str(cur_port)],
             check=False, quiet=True)

    _run(["systemctl", "reload", "sshd"], check=False, quiet=True)
    success("SSH Hardening применён и sshd перезагружен")
    if new_ssh_port != cur_port:
        print(f"  {RED}⚠  Новый SSH-порт: {new_ssh_port} — не закрывайте текущую сессию!{NC}")
    print(f"  Бэкап оригинального конфига: {_SSHD_BACKUP}")
    log_to_file("INFO", f"SSH Hardening: {changes}")
