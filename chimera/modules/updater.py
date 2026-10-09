"""
chimera/modules/updater.py
─────────────────────────────────────────────────────────────────────────────
Самообновление проекта Chimera (git pull --ff-only из origin).

Зачем: версии выходят регулярно (интеграции, фиксы, новые протоколы), а
обновиться можно было только руками — bootstrap.sh снаружи или
`cd /opt/chimera && git pull` по SSH (INSTALL.md). Теперь то же самое
доступно из TUI: Раздел 1 «Установка и Система» → пункт U.

Как устроено:
  • find_repo_root() — поднимается от этого файла вверх до каталога с .git
    (работает в /opt/chimera, в dev-чекауте и в любом другом пути —
    никаких хардкодов инсталляции, паттерн warp.py).
  • update_info(refresh) — `git fetch origin <ветка>` + сравнение HEAD ↔
    origin/<ветка>. Результат кэшируется в update_check.json
    (TTL 1 час): главное меню читает ТОЛЬКО кэш и никогда не дёргает
    сеть при перерисовке; сеть трогают либо пункт U, либо фоновый тред.
  • do_update_interactive() — пред-чеки (чистота дерева, ветка, ahead),
    список новых коммитов, подтверждение, `git pull --ff-only`,
    сравнение версий до/после, предложение перезапустить TUI (os.execv).
  • Ночное автообновление: /etc/cron.d/chimera-auto-update (04:30) —
    `python3 updater.py --cron`: только ff-only, только при чистом дереве,
    ничего не рестартит (работающий TUI доедет на старом коде — это
    безопасно), лог в /var/log/chimera-update.log, в кэш пишется
    pending_restart — главное меню покажет «перезапустите TUI».
  • Стартовая фоновая проверка: main.py вызывает start_background_check()
    — daemon-тред делает один fetch за сессию; строка-подсказка в главном
    меню рисуется из кэша.

Безопасность (зеркалит политику bootstrap.sh):
  • НИКОГДА не делает reset --hard / force-push — только --ff-only.
  • Локальные коммиты (ahead > 0) → отказ + инструкция руками.
  • Грязное дерево → обновление только по явному выбору юзера:
    [s] stash → pull → stash pop, либо [d] отбросить правки tracked-файлов
    (git checkout -- .). Untracked-файлы не трогаем вовсе.
  • Все git-вызовы с timeout; в фоновых режимах любые ошибки глотаются.

Автономность: состояние — собственный файл /var/lib/xray-installer/
update_check.json (autocheck on/off, последнее сравнение, pending_restart);
в state.json ядра ничего не пишем. В _core.py — только вызов меню,
строка-подсказка и регистрация в TASKS планировщика.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# При запуске файла НАПРЯМУЮ (`python3 .../updater.py --cron` из cron)
# sys.path[0] указывает на chimera/modules/, а не на корень проекта —
# относительный импорт пакета chimera падает раньше точки входа.
# Корень вычисляем от пути файла (паттерн warp.py / telemt_warp_route.py).
if __name__ == "__main__":
    _project_root = Path(__file__).resolve().parent.parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

from chimera.modules.box_renderer import (
    _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
    RED, GREEN, BLUE, CYAN, YELLOW, BOLD, DIM, NC,
)

# ── Константы ────────────────────────────────────────────────────────────────
MODULE_PATH = Path(__file__).resolve()
STATE_DIR   = Path("/var/lib/xray-installer")
CACHE_FILE  = STATE_DIR / "update_check.json"
CRON_FILE   = Path("/etc/cron.d/chimera-auto-update")
LOG_FILE    = Path("/var/log/chimera-update.log")

CACHE_TTL     = 3600   # сек — кэш сравнения для меню/подсказки
FETCH_TIMEOUT = 90     # сек — сеть может быть медленной
GIT_TIMEOUT   = 60     # сек — на локальные git-операции

# HEAD на момент старта TUI: если ночной cron обновил код — главном меню
# покажет «перезапустите TUI», пока код в памяти не совпадёт с диском.
_session_head: Optional[str] = None


# ── Вспомогательные ──────────────────────────────────────────────────────────
def _run(cmd: list, cwd: Optional[Path] = None, timeout: int = GIT_TIMEOUT,
         capture: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    """subprocess.run с timeout и человеческой обработкой таймаута."""
    kw: dict = {"cwd": str(cwd) if cwd else None, "check": check,
                "timeout": timeout}
    if capture:
        kw.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                  text=True, encoding="utf-8", errors="replace")
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=124,
                                           stdout="", stderr="timeout")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, returncode=127,
                                           stdout="", stderr="not found")


def _git(args: list, repo: Path, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess:
    return _run(["git", "-C", str(repo)] + args, cwd=repo, timeout=timeout)


def _git_retry(args: list, repo: Path, timeout: int = FETCH_TIMEOUT,
               attempts: int = 3, delay: int = 4) -> subprocess.CompletedProcess:
    """Сетевая git-команда (fetch/pull) с ретраями.

    gitlab.com под Cloudflare периодически отдаёт транзиентные 403/timeout
    на git-транспорт — они проходят повтором через несколько секунд
    (проверено на пушах/фетчах этой же установки). Локальные операции
    (status/log/stash) ретраить не нужно — там ошибок «шума» не бывает.
    """
    r = _git(args, repo, timeout=timeout)
    for _ in range(attempts - 1):
        if r.returncode == 0:
            return r
        err = (r.stderr or "")
        if ("403" not in err and "timed out" not in err
                and "Connection" not in err and "reset by peer" not in err):
            return r          # не сетевой шум — ретраить бессмысленно
        time.sleep(delay)
        r = _git(args, repo, timeout=timeout)
    return r


def find_repo_root(start: Optional[Path] = None) -> Optional[Path]:
    """Поднимается от start (по умолчанию — этот файл) до каталога с .git.
    Возвращает корень git-репозитория или None (не git-установка)."""
    p = (start or MODULE_PATH).resolve()
    for candidate in [p, *p.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def _current_version() -> str:
    try:
        from chimera import __version__
        return __version__
    except Exception:
        return "unknown"


def _ok(msg: str)    -> None: print(f"  {GREEN}✓{NC} {msg}")
def _info(msg: str)  -> None: print(f"  {CYAN}[i]{NC} {msg}")
def _warn(msg: str)  -> None: print(f"  {YELLOW}⚠{NC} {msg}")
def _err(msg: str)   -> None: print(f"  {RED}✗{NC} {msg}")


# ── Кэш состояния ────────────────────────────────────────────────────────────
def _read_cache() -> dict:
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_cache(data: dict) -> None:
    """Атомарная запись (tmp + rename) — фоновый тред и TUI пишут в один файл."""
    try:
        # Родитель выводим из самого CACHE_FILE (а не из STATE_DIR):
        # тогда кэш relocatable — патчится одной константой (тесты,
        # не-root окружения) и не зависит от прав на /var/lib.
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        tmp.replace(CACHE_FILE)
    except Exception:
        pass


def autocheck_enabled() -> bool:
    """Стартовая фоновая проверка обновлений (подсказка в главном меню)."""
    return bool(_read_cache().get("autocheck", True))


def set_autocheck(enabled: bool) -> None:
    cache = _read_cache()
    cache["autocheck"] = bool(enabled)
    _write_cache(cache)


# ── Сравнение с origin ───────────────────────────────────────────────────────
def current_branch(repo: Path) -> Optional[str]:
    r = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo)
    name = (r.stdout or "").strip()
    if r.returncode != 0 or name in ("", "HEAD", "detached"):
        return None
    return name


def _head(repo: Path, ref: str = "HEAD") -> Optional[str]:
    r = _git(["rev-parse", ref], repo)
    return (r.stdout or "").strip() if r.returncode == 0 else None


def _count_between(repo: Path, a: str, b: str) -> int:
    """Сколько коммитов в b нет в a (rev-list --count a..b)."""
    r = _git(["rev-list", "--count", f"{a}..{b}"], repo)
    try:
        return int((r.stdout or "0").strip() or 0)
    except ValueError:
        return 0


def _log_subjects(repo: Path, a: str, b: str, limit: int = 20) -> list:
    """Список (sha, subject) новых коммитов a..b — для показа юзеру."""
    r = _git(["log", "--format=%h%x09%s", f"{a}..{b}"], repo)
    out = []
    for line in (r.stdout or "").splitlines():
        if "\t" in line:
            sha, subject = line.split("\t", 1)
            out.append((sha, subject))
        elif line.strip():
            out.append(("", line.strip()))
    return out[:limit]


def update_info(refresh: bool = False) -> dict:
    """Сравнение локальной установки с origin/<ветка>.

    refresh=False → вернуть кэш, если он свежее CACHE_TTL (меню/подсказка).
    refresh=True  → сделать git fetch и обновить кэш (пункт U / фоновый тред).

    Возвращает dict:
      repo, branch, local, remote, behind, ahead, new_commits,
      fetched_at, error, cached
    """
    repo = find_repo_root()
    base = {"repo": str(repo) if repo else None, "branch": None,
            "local": None, "remote": None, "behind": 0, "ahead": 0,
            "new_commits": [], "fetched_at": 0, "error": None, "cached": True}
    if repo is None:
        base["error"] = "not-git"
        return base

    cache = _read_cache()
    now = int(time.time())
    fresh = (cache.get("repo") == str(repo)
             and now - int(cache.get("fetched_at", 0)) < CACHE_TTL)
    if not refresh and fresh:
        cache["cached"] = True
        return cache

    branch = current_branch(repo)
    base["branch"] = branch
    base["local"] = _head(repo)
    if branch is None:
        base["error"] = "detached-head"
        _write_cache({**base, "fetched_at": now})
        return base

    fetch = _git_retry(["fetch", "--quiet", "origin", branch], repo,
                       timeout=FETCH_TIMEOUT)
    if fetch.returncode != 0:
        base["error"] = "fetch-failed"
        _write_cache({**base, "fetched_at": now})
        return base

    base["remote"] = _head(repo, f"origin/{branch}")
    if not base["remote"]:
        base["error"] = "no-remote-branch"
        _write_cache({**base, "fetched_at": now})
        return base

    base["behind"] = _count_between(repo, "HEAD", f"origin/{branch}")
    base["ahead"]  = _count_between(repo, f"origin/{branch}", "HEAD")
    base["new_commits"] = (_log_subjects(repo, "HEAD", f"origin/{branch}")
                           if base["behind"] else [])
    base["fetched_at"] = now
    base["cached"] = False
    _write_cache({**base})
    return base


def update_hint_line() -> Optional[str]:
    """Одна строка-подсказка для главного меню. ЧИТАЕТ ТОЛЬКО КЭШ —
    никакой сети из отрисовки меню (меню перерисовывается постоянно)."""
    try:
        cache = _read_cache()
    except Exception:
        return None
    behind = int(cache.get("behind", 0) or 0)
    if behind > 0:
        return (f"{YELLOW}⬆️  Доступно обновление Chimera: {behind} коммит(ов)"
                f"{NC}  {DIM}(Раздел 1 → U){NC}")
    if cache.get("pending_restart"):
        head_now = cache.get("local")
        if head_now and _session_head and head_now != _session_head:
            return (f"{YELLOW}🌙  Код обновлён ночью — перезапустите TUI"
                    f"{NC}  {DIM}(Раздел 1 → U → 1){NC}")
    return None


def _remember_session_head() -> None:
    global _session_head
    repo = find_repo_root()
    if repo:
        _session_head = _head(repo)


def start_background_check() -> None:
    """Стартовая фоновая проверка (вызывается из main.py): daemon-тред
    делает один fetch за сессию. Ошибки глотаются целиком — подсказка
    обновлений никогда не должна мешать запуску TUI."""
    _remember_session_head()
    if not autocheck_enabled():
        return
    repo = find_repo_root()
    if repo is None:
        return

    def _worker() -> None:
        try:
            update_info(refresh=True)
        except Exception:
            pass

    try:
        t = threading.Thread(target=_worker, daemon=True, name="chimera-update-check")
        t.start()
    except Exception:
        pass


# ── Пред-чеки ────────────────────────────────────────────────────────────────
def tree_state(repo: Path) -> dict:
    """Состояние рабочего дерева (git status --porcelain).

    Разделяет правки tracked-файлов и untracked-файлы: untracked НЕ
    блокируют pull --ff-only (git сам откажется, если входящий коммит
    перезаписывает untracked-файл — тогда это станет ошибкой pull с
    понятным сообщением). Поэтому «dirty» = только tracked-правки;
    stash/discard-диалог показываем лишь для них.
    """
    r = _git(["status", "--porcelain"], repo)
    entries = [l for l in (r.stdout or "").splitlines() if l.strip()]
    untracked = [l for l in entries if l.startswith("??")]
    tracked   = [l for l in entries if not l.startswith("??")]
    return {"dirty": bool(tracked), "entries": tracked,
            "untracked": untracked}


def plan_update(info: dict, tree: dict) -> str:
    """Чистая логика: можно ли тянуть. Возвращает вердикт (тестируемый):
    ok / up-to-date / dirty / ahead / detached / no-remote / fetch-failed /
    not-git.
    """
    if info.get("error") == "not-git":
        return "not-git"
    if info.get("error") == "detached-head":
        return "detached"
    if info.get("error"):
        return "no-remote"   # fetch-failed / no-remote-branch / прочее
    behind = int(info.get("behind", 0) or 0)
    ahead = int(info.get("ahead", 0) or 0)
    if ahead > 0:
        return "ahead"
    if behind == 0:
        return "up-to-date"
    if tree.get("dirty"):
        return "dirty"
    return "ok"


# ── Интерактивное обновление ─────────────────────────────────────────────────
def do_update_interactive() -> None:
    """Проверить и обновить сейчас (Раздел 1 → U → 1)."""
    repo = find_repo_root()
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ CHIMERA")
    _box_row()

    if repo is None:
        _box_row(f"  {RED}Установка без git (архив/bootstrap без .git){NC}")
        _box_row(f"  Обновление из TUI недоступно — используйте bootstrap.sh:")
        _box_row(f"  {CYAN}README → «Быстрый старт»: блок безопасной установки{NC}")
        _box_row(f"  {DIM}(проверка подписи Ed25519 перед запуском — docs/faq/BOOTSTRAP_SECURITY.md){NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _box_row(f"  Установка: {CYAN}{repo}{NC}")
    info = update_info(refresh=True)
    _box_row(f"  Версия:    {CYAN}v{_current_version()}{NC}"
             f"  {DIM}@ {(info.get('local') or '?')[:9]}{NC}")

    if info.get("error") == "detached-head":
        _box_bottom()
        _warn("git в состоянии detached HEAD — обновление только вручную.")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    if info.get("error") == "fetch-failed":
        _box_bottom()
        _warn("git fetch не удался (сеть/CF/credentials). Повторите позже")
        _warn("или проверьте вручную: git -C %s fetch origin" % repo)
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    if info.get("error"):
        _box_bottom()
        _warn(f"Не удалось сравнить с origin: {info.get('error')}")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    branch = info.get("branch")
    behind, ahead = int(info.get("behind", 0)), int(info.get("ahead", 0))
    _box_row(f"  Ветка:     {CYAN}{branch}{NC}  {DIM}(origin){NC}")

    if ahead > 0:
        _box_bottom()
        _warn(f"Локальная ветка опережает origin на {ahead} коммит(ов) —")
        _warn("автообновление отключено (политика ff-only). Разберитесь")
        _warn("вручную: git log --oneline origin/%s..HEAD" % branch)
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    if behind == 0:
        _box_bottom()
        _ok(f"У вас последняя версия (v{_current_version()}, {info.get('local')[:9]}).")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Позади origin: показываем что приедет ────────────────────────────────
    _box_sep()
    _box_row(f"  {GREEN}Доступно обновление: {behind} коммит(ов){NC}")
    _box_row()
    commits = info.get("new_commits") or []
    for sha, subject in commits[:15]:
        subj = subject[:58] + ("…" if len(subject) > 58 else "")
        _box_row(f"  {DIM}{(sha or '')[:9]:<9}{NC}  {subj}")
    if len(commits) > 15:
        _box_row(f"  {DIM}… и ещё {len(commits) - 15}{NC}")
    if not commits:
        _box_row(f"  {DIM}(список недоступен){NC}")
    _box_bottom()
    print()

    remote_short = (info.get("remote") or "?")[:9]
    ans = input(f"{YELLOW}Обновиться до {remote_short}? [y/N]:{NC} ").strip().lower()
    if ans != "y":
        return

    # ── Грязное дерево: stash / discard / отмена ─────────────────────────────
    choice = "a"          # тянется в ветку обработки pull-ошибки ниже
    tree = tree_state(repo)
    if tree.get("untracked"):
        _info(f"untracked-файлы не трогаю ({len(tree['untracked'])} шт.) — "
              f"pull либо не заденет их, либо откажется с понятной ошибкой")
    if tree["dirty"]:
        print()
        _warn("Рабочее дерево содержит незакоммиченные правки tracked-файлов:")
        for e in tree["entries"][:10]:
            print(f"    {e}")
        if len(tree["entries"]) > 10:
            _info(f"… и ещё {len(tree['entries']) - 10}")
        print()
        print(f"  {CYAN}[s]{NC} спрятать в stash → обновить → вернуть (рекомендуется)")
        print(f"  {CYAN}[d]{NC} отбросить правки tracked-файлов и обновить")
        print(f"  {CYAN}[a]{NC} отмена (по умолчанию)")
        choice = input(f"{CYAN}Выбор [a]:{NC} ").strip().lower()
        if choice == "s":
            r = _git(["stash", "push", "-m", "chimera-update-auto"], repo)
            if r.returncode != 0:
                _err("git stash не удался — обновление отменено.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
        elif choice == "d":
            r = _git(["checkout", "--", "."], repo)
            if r.returncode != 0:
                _err("git checkout -- . не удался — обновление отменено.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
        else:
            _info("Отмена — ничего не изменено.")
            return

    # ── Тянем ────────────────────────────────────────────────────────────────
    old_version = _current_version()
    print()
    _info("git pull --ff-only …")
    pull = _git_retry(["pull", "--ff-only", "--quiet", "origin", branch], repo,
                      timeout=FETCH_TIMEOUT)
    if pull.returncode != 0:
        _err("git pull --ff-only не удался (divergent?):")
        print(f"    {YELLOW}{(pull.stderr or pull.stdout or '').strip()[:300]}{NC}")
        _info("Установка НЕ изменена. Разберитесь вручную:")
        _info(f"    git -C {repo} status && git -C {repo} pull --ff-only")
        if tree["dirty"] and choice == "s":  # вернуть stash при неудаче
            _git(["stash", "pop"], repo)
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # stash pop после успешного pull
    if tree["dirty"] and choice == "s":
        pop = _git(["stash", "pop"], repo)
        if pop.returncode != 0:
            _warn("git stash pop дал конфликт — правки сохранены в stash:")
            _warn("    git -C %s stash list && git -C %s stash pop" % (repo, repo))
            print()

    new_head = _head(repo) or "?"
    new_version = _current_version()
    update_info(refresh=True)  # обновить кэш: теперь behind=0
    _ok(f"Обновлено: {old_version} → {new_version}  @{new_head[:9]}")
    _remember_session_head()
    print()
    if old_version != new_version:
        _info(f"Версия проекта изменилась: v{old_version} → v{new_version}")
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")

    # ── Предложение перезапустить TUI ────────────────────────────────────────
    if input(f"{YELLOW}Перезапустить TUI сейчас (подхватит новый код)? [y/N]:{NC} "
             ).strip().lower() == "y":
        _restart_tui(repo)


def _restart_tui(repo: Path) -> None:
    """Перезапуск текущего процесса на новом коде (os.execv)."""
    entry = repo / "main.py"
    if not entry.exists():
        entry = repo / "chimera" / "main.py"
    if not entry.exists():
        _warn(f"Точка входа не найдена — перезапустите вручную: python3 {repo}/main.py")
        time.sleep(2)
        return
    print(f"  {CYAN}Перезапуск: {sys.executable} {entry}{NC}")
    time.sleep(1)
    os.execv(sys.executable, [sys.executable, str(entry)])


# ── Ночное автообновление (cron) ─────────────────────────────────────────────
CRON_SCHEDULE = "30 4 * * *"


def cron_enabled() -> bool:
    return CRON_FILE.exists()


def manage_cron(enable: bool) -> bool:
    """Установка/снятие ночного автообновления (паттерн warp._manage_cron)."""
    try:
        if not enable:
            CRON_FILE.unlink(missing_ok=True)
            return True
        content = (f"{CRON_SCHEDULE} root {sys.executable} {MODULE_PATH} --cron"
                   f" >/dev/null 2>&1\n")
        CRON_FILE.write_text(content, encoding="utf-8")
        CRON_FILE.chmod(0o644)
        return True
    except Exception:
        return False


def _log_cron(line: str) -> None:
    try:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{stamp} {line}\n")
    except Exception:
        pass


def cron_tick() -> int:
    """Точка входа --cron: безопасное ночное обновление.

    Условия: git-установка, не detached, дерево чистое, behind>0, ahead=0.
    Тянет --ff-only, пишет лог и pending_restart в кэш. Ничего не
    перезапускает — TUI доедет на старом коде и покажет подсказку.
    """
    repo = find_repo_root()
    if repo is None:
        _log_cron("SKIP: не git-установка")
        return 0
    branch = current_branch(repo)
    if branch is None:
        _log_cron("SKIP: detached HEAD")
        return 0
    fetch = _git_retry(["fetch", "--quiet", "origin", branch], repo,
                       timeout=FETCH_TIMEOUT)
    if fetch.returncode != 0:
        _log_cron(f"WARN: fetch не удался (rc={fetch.returncode})")
        return 0
    remote = _head(repo, f"origin/{branch}")
    behind = _count_between(repo, "HEAD", f"origin/{branch}")
    ahead = _count_between(repo, f"origin/{branch}", "HEAD")
    if ahead > 0:
        _log_cron(f"SKIP: локальная ветка опережает origin на {ahead}")
        return 0
    if behind == 0:
        _log_cron("OK: обновлений нет")
        return 0
    if tree_state(repo)["dirty"]:
        _log_cron(f"SKIP: грязное дерево, позади {behind} — обновление отложено")
        return 0

    old_head = _head(repo) or "?"
    pull = _git_retry(["pull", "--ff-only", "--quiet", "origin", branch], repo,
                      timeout=FETCH_TIMEOUT)
    if pull.returncode != 0:
        _log_cron(f"ERROR: pull --ff-only не удался (rc={pull.returncode}), "
                  f"{(pull.stderr or '').strip()[:200]}")
        return 1

    new_head = _head(repo) or "?"
    cache = _read_cache()
    cache.update({"repo": str(repo), "branch": branch, "local": new_head,
                  "remote": remote, "behind": 0, "ahead": 0, "fetched_at":
                  int(time.time()), "pending_restart": True})
    _write_cache(cache)
    _log_cron(f"OK: обновлён {old_head[:9]} → {new_head[:9]} (+{behind})")
    return 0


# ── Меню (Раздел 1 → U) ──────────────────────────────────────────────────────
def do_manage_update() -> None:
    """Подменю управления обновлением Chimera."""
    while True:
        os.system("clear")
        print()
        cron_on = cron_enabled()
        auto_on = autocheck_enabled()
        repo = find_repo_root()
        _box_top("⬆️  ОБНОВЛЕНИЕ CHIMERA (git)")
        _box_row()
        _box_row(f"  Установка: {CYAN}{repo if repo else 'без git (архив)'}{NC}")
        _box_row(f"  Версия:    {CYAN}v{_current_version()}{NC}")
        _box_row()
        _box_row(f"  Ночное автообновление (04:30): "
                 f"{(GREEN + 'вкл' + NC) if cron_on else (DIM + 'выкл' + NC)}"
                 f"  {DIM}только ff-only, лог {LOG_FILE}{NC}")
        _box_row(f"  Фоновая проверка при старте TUI: "
                 f"{(GREEN + 'вкл' + NC) if auto_on else (DIM + 'выкл' + NC)}"
                 f"  {DIM}строка-подсказка в главном меню{NC}")
        _box_row()
        _box_sep()
        _box_item("1", "🔍  Проверить и обновить сейчас (git fetch + pull --ff-only)")
        _box_item("2", f"{'🌙' if cron_on else '🌙'}  Ночное автообновление: "
                       f"{'выключить' if cron_on else 'включить'}")
        _box_item("3", f"👁  Фоновая проверка при старте: "
                       f"{'выключить' if auto_on else 'включить'}")
        _box_item("L", "📜  Показать лог автообновлений")
        _box_sep()
        _box_back()
        _box_bottom()
        print()

        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch in ("q", "", "0", "b"):
            break
        elif ch == "1":
            try:
                do_update_interactive()
            except KeyboardInterrupt:
                print()
        elif ch == "2":
            if cron_enabled():
                if input(f"{YELLOW}Выключить ночное автообновление? [y/N]:{NC} "
                         ).strip().lower() == "y":
                    _ok("выключено") if manage_cron(False) else \
                        _err("не удалось снять cron-файл")
            else:
                if input(f"{YELLOW}Включить ночное автообновление (04:30, "
                         f"ff-only)? [y/N]:{NC} ").strip().lower() == "y":
                    _ok(f"включено: {CRON_SCHEDULE} → {LOG_FILE}") if \
                        manage_cron(True) else _err("не удалось записать cron-файл")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            set_autocheck(not autocheck_enabled())
            _info(f"фоновая проверка: {'вкл' if autocheck_enabled() else 'выкл'}")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "l":
            print()
            if LOG_FILE.exists():
                print(f"  {DIM}— последние 30 записей {LOG_FILE} —{NC}")
                lines = LOG_FILE.read_text(encoding="utf-8",
                                           errors="replace").splitlines()
                for line in lines[-30:]:
                    print(f"  {line}")
            else:
                _info("лог пуст — автообновления ещё не было")
            input(f"{BLUE}Нажмите Enter...{NC}")
        else:
            _warn("Неверный выбор.")
            time.sleep(1)


# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (cron --cron / диагностика --status)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if "--cron" in sys.argv:
        sys.exit(cron_tick())
    if "--status" in sys.argv:
        info = update_info(refresh=False)
        print(json.dumps(info, ensure_ascii=False, indent=1))
        sys.exit(0)
    # без аргументов — интерактивное меню (для отладки)
    do_manage_update()
