#!/usr/bin/env python3
"""
chimera/modules/nginx_updater.py
───────────────────────────────────────────────────────────────────────────────
Обновление системного nginx до свежей версии из официального репозитория
nginx.org — с полным набором Chimera-гардов против известных мин перевода.

Мотивация (владелец, 19.11 — «nginx-марафон» по флоту): CVE-2026-123633 и
CVE-2026-123007 (HTTP/2 RCE) закрыты в 1.30.7 (stable) / 1.31.9 (mainline);
дистрибутивные nginx их содержат (Ubuntu 24.04 — nginx 1.24.0). Установка
Химеры ставит nginx из репо дистрибутива (`apt-get install nginx` в
setup_nginx_temp), поэтому дефолтный nginx на свежей ноде — с багами.
Этот модуль — «обновлялка» из меню (1 → 5f) + хук конца установки
(offer_upgrade_after_install): предлагает перевести nginx на nginx.org
сразу после успешного install, пока нода не ушла в прод.

Проверенный скелет — флотовый /root/nginx-upgrade.sh (марафон 19.11,
7 нод): nginx.org-репо (signed-by keyring, pin 900), симуляция удаления
пакетов, --force-confold, Chimera-гард, nginx -t гейт, дифф listen-портов,
restart, проверка master-бинарника. Модуль портирует его и добавляет
авто-роллбек конфигов при провале верификации.

МИНЫ, пойманные марафоном (все — в гардах модуля):
  1. dpkg МОЛЧА заменяет НЕмодифицированный /etc/nginx/nginx.conf на
     nginx.org-версию — БЕЗ конффайл-промпта и НЕСМОТРЯ на
     --force-confold (dpkg сравнивает хэш со СТАРЫМ пакетом: не меняли —
     «ваши правки не нужны», новая версия ставится молча). Итог nginx.org
     nginx.conf: НЕТ include sites-enabled → nginx с 0 слушателей (нет
     :80, :443/масок, REALITY-сокета). Гард: _ensure_include_sites_enabled
     после apt, ДО nginx -t.
  2. nginx.org считает воркера пользователем nginx (Debian-структура —
     www-data): логи из Debian-пакета принадлежат www-data, сокет-схема
     Chimera (0666, adm) рассчитана на www-data. Гард: user www-data.
  3. logrotate из nginx.org-пакета: create 640 nginx adm — новые логи
     получает nginx, а воркер у нас www-data → ротация отвалится на
     правах. Гард: sed → create 640 www-data adm.
  4. nginx.org кладёт свой default-сайт в conf.d/default.conf (listen 80
     default_server → конфликт с нашим :80 vhost). Гард: откат в бэкап.
  5. modules-enabled после смены репо содержит битые симлинки
     mod-stream/mod-mail. Гард: зачистка -xtype l.
  6. /dev/shm — tmpfs: ребут чистит REALITY-сокет; его создаёт nginx при
     старте с полным конфигом (проверка сокета после restart — не просто
     «nginx active», а слушает ли он сокет).
  7. reload НЕ подменяет бинарник: пока master жив, работает СТАРЫЙ
     бинарник (уязвимый). Гард: restart + проверка /proc/<pid>/exe на
     «(deleted)».
  8. Симуляция apt может показать REMOVAL неожидаемых пакетов (модули) —
     такие планы отклоняются ДО каких-либо изменений.

Точки входа:
    from chimera.modules.nginx_updater import (
        parse_version, is_fixed_version, current_nginx_version,
        nginx_upgrade, do_nginx_upgrade_interactive,
        offer_upgrade_after_install,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
import time
from pathlib import Path

# ── Ленивый доступ к ядру ────────────────────────────────────────────────────


def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Версии / CVE-пол ─────────────────────────────────────────────────────────

# HTTP/2 RCE CVE-2026-123633 / CVE-2026-123007 закрыты в stable 1.30.7 и
# mainline 1.31.9; всё, что ≥ 1.32.0 — тоже закрыто (обе ветки слились).
_CVE_FLOOR_MAINLINE = (1, 31, 9)
_CVE_FLOOR_STABLE = (1, 30, 7)
_NEXT_MAJOR = (1, 32, 0)

_NGINX_ORG_KEYRING = Path("/usr/share/keyrings/nginx-archive-keyring.gpg")
_NGINX_ORG_LIST = Path("/etc/apt/sources.list.d/nginx.list")
_NGINX_PIN_FILE = Path("/etc/apt/preferences.d/99nginx")
_NGINX_CONF = Path("/etc/nginx/nginx.conf")
_LOGROTATE_NGINX = Path("/etc/logrotate.d/nginx")


def _backup_dir(ts: str) -> Path:
    """Каталог бэкапа апгрейда (шов для тестов — патчится на tmpdir)."""
    return Path(f"/root/nginx-upgrade-{ts}")


# Пакеты, которые apt законно удаляет при смене distro-nginx → nginx.org
# (метапакеты Debian и модули, чьи файлы переехали в монолитный nginx.org).
_ALLOWED_REMOVALS = {
    "nginx-common", "nginx-core", "nginx-full", "nginx-light",
    "libnginx-mod-stream", "libnginx-mod-mail",
}


def parse_version(text: str):
    """'nginx version: nginx/1.30.7' → (1, 30, 7); None если не нашлось."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def is_fixed_version(ver) -> bool:
    """True — версия закрывает CVE-2026-123633 / CVE-2026-123007."""
    if not ver:
        return False
    return (ver >= _CVE_FLOOR_MAINLINE
            or _CVE_FLOOR_STABLE <= ver < (1, 31, 0)
            or ver >= _NEXT_MAJOR)


def current_nginx_version():
    """(major, minor, patch) живого nginx или None (не установлен/ошибка)."""
    core = _core_module()
    _find = getattr(core, "find_nginx_bin", None)
    _bin = (_find() if callable(_find) else None) or "/usr/sbin/nginx"
    try:
        r = core._run([_bin, "-v"], capture=True, check=False)
        return parse_version((getattr(r, "stderr", "") or "")
                             + (getattr(r, "stdout", "") or ""))
    except Exception:
        return None


def _nginx_origin() -> str:
    """'nginx.org' | 'distro' | 'unknown' — происхождение установленного пакета."""
    try:
        core = _core_module()
        r = core._run(["apt-cache", "policy", "nginx"], capture=True,
                      check=False)
        for line in (getattr(r, "stdout", "") or "").splitlines():
            if "nginx.org" in line:
                return "nginx.org"
        return "distro" if getattr(r, "returncode", 1) == 0 else "unknown"
    except Exception:
        return "unknown"


def _os_release_fields() -> dict:
    """Поля /etc/os-release (ID, VERSION_CODENAME, …) или {} (нет файла).

    Шов для тестов: патчится словарём-фальшивкой.
    """
    fields: dict = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip().strip("\"'")
    except Exception:
        pass
    return fields


def _apt_candidate():
    """Строка Candidate из apt-cache policy nginx (или None)."""
    try:
        core = _core_module()
        r = core._run(["apt-cache", "policy", "nginx"], capture=True,
                      check=False)
        for line in (getattr(r, "stdout", "") or "").splitlines():
            line = line.strip()
            if line.startswith("Candidate:"):
                cand = line.split(":", 1)[1].strip()
                return cand or None
    except Exception:
        pass
    return None


# ── Chimera-гард конфига после смены пакета ──────────────────────────────────

def _guard_nginx_conf() -> list:
    """Возвращает список применённых гардов (строки для отчёта).

    Мины 1-3: nginx.org-пакет подменяет Debian-структуру конфига.
    Выполняется ПОСЛЕ apt install и ДО nginx -t.
    """
    core = _core_module()
    applied = []
    nginx_conf = _NGINX_CONF

    # 1) include sites-enabled (жизненно: без него nginx теряет ВСЕ сайты)
    try:
        from chimera.modules.nginx_setup import (
            _ensure_nginx_sites_enabled_include,
        )
        _ensure_nginx_sites_enabled_include(nginx_conf)
        if "sites-enabled" in nginx_conf.read_text():
            applied.append("include sites-enabled: на месте")
        else:
            applied.append("include sites-enabled: НЕ ВОССТАНОВИЛСЯ — "
                           "проверьте nginx.conf вручную!")
    except Exception as exc:
        applied.append(f"include sites-enabled: гард упал ({exc})")

    # 2) user www-data (Debian-логи и сокет-схема Chimera)
    try:
        if nginx_conf.exists():
            text = nginx_conf.read_text()
            if re.search(r"^user\s+www-data\s*;", text, re.M):
                applied.append("user www-data: на месте")
            else:
                new = re.sub(r"^user\s+\S+\s*;", "user www-data;", text,
                             count=1, flags=re.M)
                if new != text:
                    nginx_conf.write_text(new)
                    applied.append("user www-data: восстановлен")
                else:
                    applied.append("user www-data: директива не найдена — "
                                   "проверьте nginx.conf вручную!")
    except Exception as exc:
        applied.append(f"user www-data: гард упал ({exc})")

    # 3) logrotate: create 640 www-data adm
    try:
        lr = _LOGROTATE_NGINX
        if lr.exists():
            text = lr.read_text()
            if "create 640 nginx adm" in text:
                lr.write_text(text.replace("create 640 nginx adm",
                                           "create 640 www-data adm"))
                applied.append("logrotate: create 640 www-data adm")
            elif "www-data" in text:
                applied.append("logrotate: уже www-data")
    except Exception as exc:
        applied.append(f"logrotate: гард упал ({exc})")

    return applied


def _sockets_in_config(dump_text: str) -> list:
    """Список путей unix-listen из nginx -T (REALITY-сокеты /dev/shm)."""
    out = []
    for line in (dump_text or "").splitlines():
        m = re.match(r"\s*listen\s+unix:([^;\s]+)\s*;", line)
        if m:
            out.append(m.group(1))
    return sorted(set(out))


# ── Основной апгрейд ─────────────────────────────────────────────────────────

def nginx_upgrade(apply: bool = True) -> dict:
    """Перевод nginx на свежую версию nginx.org (stable-ветка репо).

    Возвращает {"ok": bool, "upgraded": bool, "before": str, "after": str,
                "candidate": str, "backup": str, "restarted": bool,
                "warnings": [...], "report": [...]}.

    Пайплайн (скелет — флотовый nginx-upgrade.sh, 7 нод 19.11):
      pre: root / Debian|Ubuntu / nginx установлен / nginx -t уже валиден;
      бэкап: tar /etc/nginx + дамп nginx -T + ss-порты «до»;
      репо: keyring nginx.org + sources.list.d/nginx.list + pin 900 + apt update;
      кандидат: без CVE-фикса → отказ ДО изменений;
      симуляция: apt-get -s install nginx — неожидаемые удаления → отказ;
      установка: DEBIAN_FRONTEND=noninteractive apt-get install -y
                 -o Dpkg::Options::=--force-confold nginx;
      гард: include sites-enabled + user www-data + logrotate (мины 1-3),
            conf.d/default.conf → бэкап, битые module-симлинки → зачистка;
      верификация: nginx -t; число listen/server_name в nginx -T «до» = «после»
                   (иначе — роллбек конфигов из tar и restart прежнего);
      старт: daemon-reload + reset-failed + restart (reload не подменяет
             бинарник — мина 7); порты «после» vs «до»; REALITY-сокеты
             существуют и слушают (/proc/net/unix — мина 6); master не на
             «(deleted)»-бинарнике.

    Идемпотентен: nginx уже свежее кандидата → upgraded=False, система не
    трогается (репо-файлы при apply=True всё равно приводятся к норме —
    это безопасные idempotent-записи).
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    _run = core._run
    report, warnings = [], []

    def _fail(msg: str) -> dict:
        report.append(msg)
        warn(msg)
        return {"ok": False, "upgraded": False, "before": "", "after": "",
                "candidate": "", "backup": "", "restarted": False,
                "warnings": warnings, "report": report}

    # ── pre-проверки ───────────────────────────────────────────────────
    import os as _os
    if getattr(_os, "geteuid", lambda: 0)() != 0:
        return _fail("Нужен root (sudo) — апгрейд системного пакета")
    rel = _os_release_fields()
    distro = rel.get("ID", "")
    if distro not in ("ubuntu", "debian"):
        return _fail(f"Не Debian/Ubuntu (ID={distro!r}) — рецепт nginx.org "
                     "неприменим")
    ver_before = current_nginx_version()
    if ver_before is None:
        return _fail("nginx не установлен (или версия не читается) — "
                     "нечего обновлять")
    codename = rel.get("VERSION_CODENAME", "")
    if not codename:
        r = _run(["lsb_release", "-cs"], capture=True, check=False)
        codename = (getattr(r, "stdout", "") or "").strip()
        if not codename:
            return _fail("Не удалось определить коднейм дистрибутива")

    _find = getattr(core, "find_nginx_bin", None)
    nginx_bin = (_find() if callable(_find) else None) or "/usr/sbin/nginx"

    # Текущий конфиг обязан быть валиден — иначе «после» не с чем сравнивать.
    r_t0 = _run([nginx_bin, "-t"], capture=True, check=False)
    if getattr(r_t0, "returncode", 1) != 0:
        return _fail("Текущий конфиг уже невалиден (nginx -t падает) — "
                     f"сначала почините: {(getattr(r_t0, 'stderr', '') or '')[:160]}")

    ts = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = _backup_dir(ts)
    info(f"nginx {'.'.join(map(str, ver_before))} ({_nginx_origin()}) — "
         f"проверяю кандидата nginx.org…")

    # ── репо nginx.org (idempotent; при отказе ДО установки — откат файлов) ─
    _prev_list = (_NGINX_ORG_LIST.read_text()
                  if _NGINX_ORG_LIST.exists() else None)
    _prev_pin = (_NGINX_PIN_FILE.read_text()
                 if _NGINX_PIN_FILE.exists() else None)

    def _restore_repo() -> None:
        """Откат репо-файлов к состоянию «до вызова» (отказ до установки).

        Иначе pin 900 остался бы настроенным на репо, где для этого
        коднейма лежит уязвимая версия (например, старый коднейм без
        свежих сборок): плановый apt upgrade уехал бы на неё без ведома
        оператора.
        """
        for path, prev in ((_NGINX_ORG_LIST, _prev_list),
                           (_NGINX_PIN_FILE, _prev_pin)):
            try:
                if prev is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(prev)
            except Exception:
                pass

    if apply:
        r_pre = _run(["apt-get", "install", "-y", "-q", "curl", "gnupg2",
                      "ca-certificates", "lsb-release"],
                     env={"DEBIAN_FRONTEND": "noninteractive"},
                     check=False, quiet=True)
        if getattr(r_pre, "returncode", 1) != 0:
            _restore_repo()
            return _fail("Не удалось доставить curl/gnupg2 (prereq)")
        r_key = _run(["bash", "-c",
                      "curl -fsSL https://nginx.org/keys/nginx_signing.key"
                      " | gpg --dearmor > /usr/share/keyrings/"
                      "nginx-archive-keyring.gpg"], check=False, quiet=True)
        if getattr(r_key, "returncode", 1) != 0:
            _restore_repo()
            return _fail("Не удалось получить/разобрать ключ nginx.org")
        _NGINX_ORG_LIST.write_text(
            f"deb [signed-by={_NGINX_ORG_KEYRING}] "
            f"https://nginx.org/packages/{distro} {codename} nginx\n")
        _NGINX_PIN_FILE.write_text(
            "Package: *\nPin: origin nginx.org\nPin: release o=nginx\n"
            "Pin-Priority: 900\n")
        r_upd = _run(["apt-get", "update", "-q"], check=False, quiet=True,
                     env={"DEBIAN_FRONTEND": "noninteractive"})
        if getattr(r_upd, "returncode", 1) != 0:
            _restore_repo()
            return _fail("apt-get update по nginx.org не удался (сеть/зеркало?)")

    cand = _apt_candidate() or ""
    ver_cand = parse_version(cand)
    if not ver_cand:
        _restore_repo()
        return _fail("Кандидат nginx не определился (apt-cache policy пуст?)")
    if not is_fixed_version(ver_cand):
        _restore_repo()
        return _fail(f"Кандидат {cand} без CVE-фикса (нет свежей версии "
                     f"для {codename}?) — обновление отменено")
    cve_before = is_fixed_version(ver_before)
    if ver_cand <= ver_before:
        _restore_repo()
        report.insert(0, f"Уже свежее кандидата: установлено "
                         f"{'.'.join(map(str, ver_before))}, кандидат {cand} — "
                         "изменений нет")
        return {"ok": True, "upgraded": False,
                "before": ".".join(map(str, ver_before)), "after": "",
                "candidate": cand, "backup": "", "restarted": False,
                "warnings": warnings, "report": report}
    if not apply:
        report.insert(0, f"DRY-RUN: nginx {'.'.join(map(str, ver_before))} "
                         f"({_nginx_origin()}, CVE-фикс: "
                         f"{'да' if cve_before else 'НЕТ'}) → {cand} (nginx.org)")
        return {"ok": True, "upgraded": False,
                "before": ".".join(map(str, ver_before)), "after": "",
                "candidate": cand, "backup": "", "restarted": False,
                "warnings": warnings, "report": report}

    # ── симуляция: неожидаемые удаления → отказ ────────────────────────
    r_sim = _run(["apt-get", "-s", "install", "nginx"], capture=True,
                 check=False)
    removals = [ln.split()[1] for ln in (getattr(r_sim, "stdout", "") or "").splitlines()
                if ln.startswith("Remv ")]
    bad = [p for p in removals if p not in _ALLOWED_REMOVALS]
    if bad:
        _restore_repo()
        return _fail(f"apt удалит нестандартные пакеты ({', '.join(bad)}) — "
                     "разберитесь, нужны ли они; обновление отменено")
    if removals:
        report.append(f"apt заменит пакеты Debian: {', '.join(removals)}")

    # ── бэкап «до» ─────────────────────────────────────────────────────
    backup_dir.mkdir(parents=True, exist_ok=True)
    r_tar = _run(["tar", "-czf", str(backup_dir / "etc-nginx.tar.gz"),
                  "-C", "/etc", "nginx"], check=False, quiet=True)
    if getattr(r_tar, "returncode", 1) != 0:
        return _fail("Бэкап /etc/nginx (tar) не удался — отмена")
    r_tb = _run([nginx_bin, "-T"], capture=True, check=False)
    dump_before = getattr(r_tb, "stdout", "") or ""
    (backup_dir / "nginx-T.before").write_text(dump_before)
    cnt_before = len(re.findall(r"^\s*(?:listen|server_name)\b", dump_before,
                                re.M))
    r_ss = _run(["ss", "-ltnH"], capture=True, check=False)
    (backup_dir / "ports.before").write_text(getattr(r_ss, "stdout", "") or "")
    sockets_before = _sockets_in_config(dump_before)
    report.append(f"Бэкап: {backup_dir} (tar /etc/nginx + nginx -T + порты)")

    # ── установка ──────────────────────────────────────────────────────
    info(f"Устанавливаю nginx {cand} из nginx.org…")
    r_inst = _run(["apt-get", "install", "-y", "-o",
                   "Dpkg::Options::=--force-confold", "nginx"],
                  env={"DEBIAN_FRONTEND": "noninteractive"},
                  check=False, quiet=True)
    if getattr(r_inst, "returncode", 1) != 0:
        err = (getattr(r_inst, "stderr", "") or "")[:200]
        return _fail(f"apt-get install nginx не удался: {err}")

    # ── пост-установочные гарды (мины 1-5) ─────────────────────────────
    # conf.d/default.conf от nginx.org — конфликт default_server на :80
    default_conf = Path("/etc/nginx/conf.d/default.conf")
    if default_conf.exists() and "default.conf" not in dump_before:
        default_conf.rename(backup_dir / "default.conf.nginxorg")
        report.append("conf.d/default.conf (nginx.org) → откачен в бэкап")
    # битые симлинки модулей после смены владельца пакета
    r_mod = _run(["bash", "-c",
                  "find /etc/nginx/modules-enabled -xtype l "
                  "\\( -name '*mod-stream.conf' -o -name '*mod-mail.conf' \\) "
                  "-delete 2>/dev/null || true"], check=False, quiet=True)
    guards = _guard_nginx_conf()
    report.extend(f"гард: {g}" for g in guards)

    # ── верификация ────────────────────────────────────────────────────
    def _rollback(reason: str) -> dict:
        report.append(f"ВНИМАНИЕ: {reason}")
        r_rb = _run(["tar", "-xzf", str(backup_dir / "etc-nginx.tar.gz"),
                     "-C", "/etc"], check=False, quiet=True)
        report.append("Конфиги /etc/nginx восстановлены из бэкапа"
                      + ("" if getattr(r_rb, "returncode", 1) == 0
                         else " — С ОШИБКОЙ, проверьте вручную!"))
        _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
        warnings.append(reason)
        return {"ok": False, "upgraded": False,
                "before": ".".join(map(str, ver_before)), "after": "",
                "candidate": cand, "backup": str(backup_dir),
                "restarted": False, "warnings": warnings, "report": report}

    r_t1 = _run([nginx_bin, "-t"], capture=True, check=False)
    if getattr(r_t1, "returncode", 1) != 0:
        return _rollback(
            "nginx -t провалился после обновления — откат конфигов")
    r_ta = _run([nginx_bin, "-T"], capture=True, check=False)
    dump_after = getattr(r_ta, "stdout", "") or ""
    cnt_after = len(re.findall(r"^\s*(?:listen|server_name)\b", dump_after,
                               re.M))
    if cnt_after != cnt_before:
        return _rollback(
            f"число listen/server_name изменилось ({cnt_before} → "
            f"{cnt_after}): часть сайтов выпала из конфига")

    # ── старт нового бинарника (мины 6-7) ──────────────────────────────
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "reset-failed", "nginx"], check=False, quiet=True)
    r_rst = _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
    restarted = getattr(r_rst, "returncode", 1) == 0
    if not restarted:
        time.sleep(2)
        _run(["systemctl", "daemon-reload"], check=False, quiet=True)
        r_rst = _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
        restarted = getattr(r_rst, "returncode", 1) == 0
    if not restarted:
        warnings.append("restart nginx не удался — состояние неизвестно, "
                        "проверьте: systemctl status nginx -l")
        report.append("ВНИМАНИЕ: systemctl restart nginx не удался (дважды)")
        return {"ok": False, "upgraded": False,
                "before": ".".join(map(str, ver_before)), "after": "",
                "candidate": cand, "backup": str(backup_dir),
                "restarted": False, "warnings": warnings, "report": report}
    time.sleep(2)

    # порты «после» vs «до»
    r_ss2 = _run(["ss", "-ltnH"], capture=True, check=False)
    ports_after = (getattr(r_ss2, "stdout", "") or "")
    (backup_dir / "ports.after").write_text(ports_after)
    before_set = {ln.split()[3] for ln in
                  (backup_dir / "ports.before").read_text().splitlines()
                  if len(ln.split()) >= 4}
    after_set = {ln.split()[3] for ln in ports_after.splitlines()
                 if len(ln.split()) >= 4}
    if before_set != after_set:
        diff = ", ".join(sorted((before_set ^ after_set))[:6])
        warnings.append(f"набор слушающих портов изменился: {diff}")
        report.append(f"ВНИМАНИЕ: порты «до» ≠ «после» ({diff})")

    # REALITY-сокеты из конфига обязаны существовать и слушаться (мина 6)
    for sock in sockets_before:
        if not Path(sock).exists():
            warnings.append(f"REALITY-сокет {sock} не создан после restart")
            report.append(f"ВНИМАНИЕ: сокет {sock} отсутствует — "
                          "проверьте nginx status/логи")
        else:
            serving = False
            try:
                for line in Path("/proc/net/unix").read_text().splitlines():
                    if line.split() and line.split()[-1] == sock:
                        serving = True
                        break
            except OSError:
                serving = True  # не смогли прочитать — не кричим
            if not serving:
                warnings.append(f"сокет {sock} есть файлом, но не слушается")

    # master на свежем бинарнике (мина 7)
    r_pg = _run(["bash", "-c",
                 "M=$(pgrep -o -f 'nginx: master'); "
                 "[ -n \"$M\" ] && ls -l /proc/$M/exe || true"],
                capture=True, check=False)
    if "(deleted)" in (getattr(r_pg, "stdout", "") or ""):
        warnings.append("nginx master работает на СТАРОМ бинарнике "
                        "(deleted) — нужен полный restart")

    ver_after = current_nginx_version()
    after_str = ".".join(map(str, ver_after)) if ver_after else "?"
    report.append(f"Готово: nginx {'.'.join(map(str, ver_before))} → "
                  f"{after_str} (nginx.org); CVE-фикс: "
                  f"{'да' if is_fixed_version(ver_after) else 'НЕТ?!'}")
    try:
        core.log_to_file("SUCCESS", f"nginx_updater: nginx "
                         f"{'.'.join(map(str, ver_before))} → {after_str} "
                         f"(репо nginx.org, бэкап {backup_dir})")
    except Exception:
        pass
    return {"ok": True, "upgraded": True,
            "before": ".".join(map(str, ver_before)), "after": after_str,
            "candidate": cand, "backup": str(backup_dir),
            "restarted": restarted, "warnings": warnings, "report": report}


# ── TUI-обёртка (меню 1 → 5f) ────────────────────────────────────────────────

def do_nginx_upgrade_interactive() -> None:
    """Интерактивное обновление nginx из репо nginx.org (меню 1 → 5f).

    Экран 1: текущая версия/происхождение/CVE-статус, кандидат, список
    гards; [1] dry-run / [2] применить / Q-отмена (EOF/Ctrl+C — тихо).
    Экран 2: отчёт апгрейдера.
    """
    core = _core_module()
    warn = core.warn
    CYAN, NC, RED, GREEN, YELLOW, DIM = (core.CYAN, core.NC, core.RED,
                                         core.GREEN, core.YELLOW, core.DIM)
    _box_top, _box_row = core._box_top, core._box_row
    _box_item, _box_back, _box_bottom = (core._box_item, core._box_back,
                                         core._box_bottom)

    ver = current_nginx_version()
    ver_str = ".".join(map(str, ver)) if ver else "не установлен"
    origin = _nginx_origin()
    cve = is_fixed_version(ver)
    cand = _apt_candidate() or "?"

    print()
    _box_top("⬆️  ОБНОВЛЕНИЕ NGINX (репозиторий nginx.org)")
    _box_row()
    _box_row(f"  Установлен: {ver_str} ({origin}) — CVE-2026-123633/123007 "
             f"(HTTP/2 RCE): {'закрыты' if cve else RED + 'ОТКРЫТЫ' + NC}")
    _box_row(f"  Кандидат nginx.org: {cand}")
    _box_row()
    _box_row(f"  {DIM}• nginx.org-репо: keyring + pin 900 (idempotent);{NC}")
    _box_row(f"  {DIM}• бэкап: tar /etc/nginx + nginx -T + порты «до»;{NC}")
    _box_row(f"  {DIM}• симуляция apt: неожидаемые удаления → отказ;{NC}")
    _box_row(f"  {DIM}• Chimera-гарды: include sites-enabled, user www-data,{NC}")
    _box_row(f"    {DIM}logrotate www-data, conf.d/default.conf, модули;{NC}")
    _box_row(f"  {DIM}• верификация: nginx -t, listen/server_name «до»=«после»,{NC}")
    _box_row(f"    {DIM}порты, REALITY-сокеты, master-бинарник; провал → откат;{NC}")
    _box_row(f"  {DIM}• restart обязателен: reload не подменяет бинарник.{NC}")
    _box_row()
    _box_item("1", f"🔍 Dry-run  {DIM}(показать план — без изменений){NC}")
    _box_item("2", f"⬆️  Применить  {DIM}(репо + apt + гард + верификация){NC}")
    _box_row()
    _box_back()
    _box_bottom()
    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except (KeyboardInterrupt, EOFError):
        return
    if ch not in ("1", "2"):
        return

    try:
        result = nginx_upgrade(apply=(ch == "2"))
    except Exception as exc:
        warn(f"Апгрейд nginx упал с исключением: {exc}")
        return

    # ── Экран 2: отчёт ─────────────────────────────────────────────────
    print()
    if result.get("ok"):
        _box_top("⬆️  NGINX — ОТЧЁТ")
        _box_row()
        if result.get("upgraded"):
            _box_row(f"  {GREEN}Готово:{NC} nginx {result.get('before')} → "
                     f"{GREEN}{result.get('after')}{NC} (nginx.org)")
        else:
            _box_row(f"  {GREEN}Изменений не потребовалось:{NC} "
                     f"{result.get('report', [''])[0] if result.get('report') else ''}")
        if result.get("backup"):
            _box_row(f"  Бэкап: {result['backup']}")
    else:
        _box_top("⬆️  NGINX — ПРОВАЛ")
        _box_row()
        _box_row(f"  {RED}Апгрейд не выполнен — система в максимально "
                 f"исходном состоянии.{NC}")
        if result.get("backup"):
            _box_row(f"  Бэкап «до»: {result['backup']}")
    _box_row()
    for line in result.get("warnings") or []:
        _box_row(f"  {YELLOW}⚠ {line}{NC}")
    _box_row()
    for line in result.get("report") or []:
        _box_row(f"  {line}")
    _box_row()
    _box_back()
    _box_bottom()


# ── Хук конца установки ──────────────────────────────────────────────────────

def offer_upgrade_after_install() -> None:
    """Хук do_full_install: предложить nginx.org-обновление на свежей ноде.

    Срабатывает ТОЛЬКО когда установленный nginx уязвим (ниже CVE-пола
    1.30.7/1.31.9) — т.е. дефолтный дистрибутивный nginx после чистой
    установки. Уже фиксованый nginx (переустановка поверх живой ноды,
    повторный прогон) → тихий no-op: вывод install-флоу не меняется.

    EOF (headless-установка) / не-root / отказ → тихо пропускаем; после
    отказа подсказываем пункт меню 1 → 5f. Ошибки хука никогда не роняют
    установку (try/except вокруг всего).
    """
    try:
        core = _core_module()
        info, warn = core.info, core.warn
        GREEN, YELLOW, NC, CYAN = core.GREEN, core.YELLOW, core.NC, core.CYAN
        if getattr(__import__("os"), "geteuid", lambda: 1)() != 0:
            return
        ver = current_nginx_version()
        if ver is None or is_fixed_version(ver):
            return
        print()
        info(f"{YELLOW}Установленный nginx {'.'.join(map(str, ver))} содержит "
             f"открытые CVE-2026-123633/123007 (HTTP/2 RCE).{NC}")
        info("Свежая сборка доступна в официальном репозитории nginx.org — "
             "перевод занимает ~минуту и включает гарды конфига Chimera.")
        try:
            ans = input(f"{CYAN}Перевести nginx на nginx.org сейчас? "
                        f"[Y/n]:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if ans in ("n", "нет", "no"):
            info("Пропущено. Позже: меню 1 «Установка и Система» → 5f "
                 "«Обновить nginx».")
            return
        result = nginx_upgrade(apply=True)
        for line in result.get("report") or []:
            info(f"  {line}")
        if result.get("warnings"):
            for line in result["warnings"]:
                warn(f"  {line}")
        if result.get("ok") and result.get("upgraded"):
            info(f"{GREEN}nginx {result.get('after')} (nginx.org) — "
                 f"уязвимость закрыта.{NC}")
    except Exception:
        # Хук не должен ронять установку ни при каких условиях.
        try:
            core = _core_module()
            core.log_to_file("WARN", "nginx_updater.offer_upgrade_after_"
                             "install: исключение (пропущено тихо)")
        except Exception:
            pass
