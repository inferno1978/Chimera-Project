# tests/_env_isolation.py
"""
Env-изоляция тестов Химеры: прод-деревья становятся НЕВИДИМЫМИ для
тестового процесса (как в чистом контейнере) на любом раннере.

ЗАЧЕМ
─────
Тесты писались под чистое окружение (см. шапку smoke_test_modules.py):
прод-пути `/var/lib/xray-installer`, `/etc/xray`, `/usr/local/etc/xray`,
`/etc/letsencrypt`, `/opt/chimera` в чистой среде НЕ СУЩЕСТВУЮТ →
`Path.exists()` → False → тестируемый код идёт по веткам дефолтов.
На живой chimera-ноде (раннер ci-de — она же exit-нода каскада) эти пути
СУЩЕСТВУЮТ → три класса расхождений:
  • stat под root-only каталогом → PermissionError вместо False;
  • читаемые прод-файлы (config.json) → утечка реального контента в тесты;
  • записи в реально существующие пути → ЗАГРЯЗНЕНИЕ ПРОДА тестами
    (инцидент 2026-10-27: identity_guard/credential_rotation перезаписали
    live-конфиг xray на de-ноде).

МЕХАНИЗМ
────────
CHIMERA_TEST_ISOLATE=1 → install() подменяет путь-ориентированные функции
os/io/builtins так, что ЛЮБОЕ обращение к изолируемому префиксу ведёт себя
как к несуществующему пути (ENOENT):
  os.stat / os.lstat / os.access / os.open / os.scandir / os.listdir /
  os.mkdir / os.makedirs / os.unlink / os.remove / os.rmdir / os.rename /
  os.replace / os.readlink / os.symlink / os.chmod / os.chown / os.utime /
  io.open / builtins.open
Эффект идентичен запуску в чистой среде — потому что «чистая среда» и есть
«прод-путей нет». Прод-код (chimera/) НЕ трогается вовсе.

ПОДКЛЮЧЕНИЕ
───────────
  • tests/__init__.py — при import tests.* (основной процесс);
  • tests/_ci_site/sitecustomize.py — в САБПРОЦЕССАХ тестов (inner-скрипты
    tg-бота и пр.): ci_suite.sh добавляет каталог в PYTHONPATH, env var
    наследуется → sitecustomize ставит ту же изоляцию.

ОТЛАДКА
───────
CHIMERA_TEST_ISOLATE_PREFIXES="/a:/b" — переопределить список префиксов
(используется tests/test_env_isolation.py для самопроверки на фейковых
путях; НЕ задавать в CI).
"""
import errno
import os

# ─── изолируемые префиксы (прод-деревья живой ноды) ─────────────────────────
_DEFAULT_PREFIXES = (
    "/var/lib/xray-installer",
    "/usr/local/etc/xray",
    "/etc/xray",
    "/etc/letsencrypt",
    "/opt/chimera",
    "/opt/vless-ultimate",
    "/opt/VLESS-Ultimate-Installer",
    # бинарри xray: os.access(..., X_OK) → False → shutil.which('xray') → None
    # (runtime-проверки вида «если xray доступен — прогнать -test» корректно
    # скипаются, как в чистой среде)
    "/usr/local/bin/xray",
)

_installed = False


def _prefixes():
    override = os.environ.get("CHIMERA_TEST_ISOLATE_PREFIXES")
    if override:
        return tuple(p for p in override.split(os.pathsep) if p)
    return _DEFAULT_PREFIXES


def _is_isolated(path) -> bool:
    """True если path лежит под одним из изолируемых префиксов."""
    try:
        p = os.fspath(path)
    except TypeError:
        return False
    if not isinstance(p, str) or not p.startswith("/"):
        return False
    for pref in _prefixes():
        if p == pref or p.startswith(pref + "/"):
            return True
    return False


def _enoent(path):
    """FileNotFoundError с канонической 3-аргументной формой OSError."""
    return FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                             os.fspath(path))


def is_active() -> bool:
    return _installed


class _MethodSafe:
    """Обёртка, безопасная к метод-биндингу.

    pathlib на Python 3.10/3.11 биндит os-функции в КЛАСС-АТРИБУТЫ
    _NormalAccessor (`stat = os.stat` в теле класса). Если pathlib
    импортируется ПОСЛЕ install(), он захватывает наши обёртки, и при
    доступе через экземпляр (`accessor.stat(path)`) обычная функция
    получила бы лишний self. Дескриптор __get__ возвращает саму обёртку —
    вызов через класс/экземпляр идентичен прямому вызову os.stat(...).
    """
    __slots__ = ("_fn",)

    def __init__(self, fn):
        self._fn = fn

    def __call__(self, *args, **kwargs):
        return self._fn(*args, **kwargs)

    def __get__(self, obj, objtype=None):
        return self


def _bind(target, name, fn):
    """Привязать обёртку fn как target.name через _MethodSafe."""
    try:
        setattr(target, name, _MethodSafe(fn))
    except Exception:  # pragma: no cover
        pass


def install():
    """Устанавливает перехватчики. Идемпотентно; без CHIMERA_TEST_ISOLATE=1
    — no-op (возвращает False)."""
    global _installed
    if _installed:
        return True
    if os.environ.get("CHIMERA_TEST_ISOLATE", "") != "1":
        return False
    _installed = True

    wrappers = {}

    # ── os.stat / os.lstat (pathlib.exists/is_file/is_dir, os.path.*) ──────
    _stat, _lstat = os.stat, os.lstat

    def stat(path, *args, **kwargs):
        if _is_isolated(path):
            raise _enoent(path)
        return _stat(path, *args, **kwargs)

    def lstat(path, *args, **kwargs):
        if _is_isolated(path):
            raise _enoent(path)
        return _lstat(path, *args, **kwargs)

    wrappers["stat"] = stat
    wrappers["lstat"] = lstat

    # ── os.access (shutil.which, проверки прав) ────────────────────────────
    _access = os.access

    def access(path, mode, *args, **kwargs):
        if _is_isolated(path):
            return False
        return _access(path, mode, *args, **kwargs)

    wrappers["access"] = access

    # ── io.open + builtins.open (pathlib.read_text/write_text, json) ───────
    import builtins
    import io
    _bio_open = builtins.open
    _io_open = io.open

    def fopen(file, mode="r", *args, **kwargs):
        if _is_isolated(file):
            raise _enoent(file)
        return _bio_open(file, mode, *args, **kwargs)

    def fio_open(file, mode="r", *args, **kwargs):
        if _is_isolated(file):
            raise _enoent(file)
        return _io_open(file, mode, *args, **kwargs)

    # ── os.open(path, flags, mode) — низкоуровневый fd-open (Path.touch) ────
    _os_open = os.open

    def fos_open(path, flags, mode=0o777, *args, **kwargs):
        if _is_isolated(path):
            raise _enoent(path)
        return _os_open(path, flags, mode, *args, **kwargs)

    wrappers["os_open"] = fos_open

    # ── перечисление каталогов (pathlib.iterdir/glob, os.walk) ─────────────
    _scandir = os.scandir
    _listdir = os.listdir

    def scandir(path="."):
        if _is_isolated(path):
            raise _enoent(path)
        return _scandir(path)

    def listdir(path="."):
        if _is_isolated(path):
            raise _enoent(path)
        return _listdir(path)

    wrappers["scandir"] = scandir
    wrappers["listdir"] = listdir

    # ── однопутёвые мутации: любая операция под префиксом = «пути нет» ─────
    def _single(name, orig):
        def mut(path, *args, **kwargs):
            if _is_isolated(path):
                raise _enoent(path)
            return orig(path, *args, **kwargs)
        return mut

    for name in ("unlink", "remove", "rmdir", "mkdir", "makedirs",
                 "chmod", "chown", "utime", "readlink"):
        wrappers[name] = _single(name, getattr(os, name))

    # ── двухпутёвые (src, dst): изоляция любого из аргументов → ENOENT ─────
    def _dual(name, orig):
        def mut(src, dst, *args, **kwargs):
            for p in (src, dst):
                if _is_isolated(p):
                    raise _enoent(p)
            return orig(src, dst, *args, **kwargs)
        return mut

    for name in ("rename", "replace", "symlink"):
        wrappers[name] = _dual(name, getattr(os, name))

    # ── применение: os.* / io.open / builtins.open ─────────────────────────
    for name in ("stat", "lstat", "access", "scandir", "listdir",
                 "unlink", "remove", "rmdir", "mkdir", "makedirs",
                 "chmod", "chown", "utime", "readlink",
                 "rename", "replace", "symlink"):
        _bind(os, name, wrappers[name])
    _bind(os, "open", wrappers["os_open"])
    _bind(builtins, "open", fopen)
    _bind(io, "open", fio_open)

    # ── pathlib 3.10/3.11: _NormalAccessor мог захватить оригиналы ДО ──────
    # install() (pathlib импортирован раньше) — перепривязываем явно.
    # Если pathlib импортируется ПОЗЖЕ — его класс-атрибуты возьмут уже наши
    # _MethodSafe-обёртки с os.*: дескриптор гасит метод-биндинг.
    try:
        import pathlib
        acc = getattr(pathlib, "_NormalAccessor", None)
        if acc is not None:
            for name in ("stat", "lstat", "listdir", "scandir", "chmod",
                         "mkdir", "rmdir", "unlink", "utime",
                         "replace", "rename", "symlink"):
                _bind(acc, name, wrappers[name])
            # _NormalAccessor.open = io.open
            _bind(acc, "open", fio_open)
    except Exception:  # pragma: no cover
        pass

    return True
