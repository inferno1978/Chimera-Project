#!/usr/bin/env python3
"""
chimera/modules/xray_downgrade.py
───────────────────────────────────────────────────────────────────────────────
Даунгрейд ядра Xray-core под эпоху совместимости + автоматическая подгонка
гейта версий клиента REALITY (minClientVer) под целевую версию ядра.

Эпохи Xray-core (docs/faq/VLESS_FAQ.md §18, матрица «клиент × эпоха»):
  • MLKEM-эпоха, 26.9.8+ (текущий флот 26.9.9): дефолт-гейт убран —
    "" = гейт выкл (норма); НО ClientHello обязан содержать
    X25519MLKEM768 → sing-box-семья (Nyamebox, Karing, Hiddify, SFM)
    несовместима В ПРИНЦИПЕ (конфигом не лечится), mihomo работает
    только с «рецептом B» (fp=chrome + support-x25519mlkem768 —
    генераторы Chimera пишут это автоматически);
  • гейт-эпоха, 26.7.11–26.7.28: MLKEM-чека нет; пустой/отсутствующий
    minClientVer включает ДЕФОЛТ-гейт 26.3.27, который валит sing-box
    [1,8,1] и mihomo [1,8,2] (соединение молча уводится в декой);
    явный minClientVer="1.8.0" проходят ВСЕ клиенты;
  • до-гейт, ≤ 26.6.27: ни гейта, ни MLKEM-чека — все клиенты работают
    из коробки, значение minClientVer не важно (пишем "").

Серверных «MLKEM-полей» в конфиге Xray НЕ СУЩЕСТВУЕТ — это поведение
бинарника ядра, меняется только сменой версии. Единственное конфиг-поле,
зависящее от эпохи, — minClientVer (+ maxClientVer="").

Пункт меню 5c делает всё автоматически («руками лезть в конфиг — не
комильфо»):
  1. показывает текущую версию ядра, её эпоху, значение minClientVer
     (state.json) и матрицу «какие клиенты работают сейчас»;
  2. предлагает ровно ДВЕ целевые версии («много не нужно»):
       v26.7.28 — последний пререлиз перед MLKEM-эпохой («оптимум
                  совместимости»): авто minClientVer="1.8.0", работают
                  ВСЕ клиенты (Xray, sing-box, mihomo);
       v26.3.27 — последний СТАБИЛЬНЫЙ релиз GitHub (до-гейт): авто
                  minClientVer="", все клиенты из коробки.
     Даунгрейда на 26.9.8 в списке нет — это та же MLKEM-эпоха, что и
     26.9.9: конфиг не меняется, sing-box всё равно не работает;
  3. ставит ядро через _xray_do_upgrade() — тот же путь, что обычное
     обновление из пункта [5]: download manager (fetch_package, 10
     зеркал, SHA256), бэкап бинарника в /var/backups/xray/binaries,
     тест конфига новым ядром, авт. откат при провале;
  4. подгоняет конфиг под эпоху: сохраняет min_client_ver в state.json
     (read-modify-write под flock) и патчит minClientVer/maxClientVer
     во всех REALITY-инбаундах живых конфигов (/etc/xray/config.json +
     /usr/local/etc/xray/config.json) с `xray run -test` и откатом
     при провале; генераторы (xray_install / chain_nodes / pq_vless /
     credential_rotation) читают значение из state.json — оверрайд
     переживает любые rebuild/ротации;
  5. гард таймера xray-autoupdate: его bash-скрипт сравнивает версии
     только на РАВЕНСТВО с GitHub-stable (v26.3.27) — после даунгрейда
     он молча перетянет ядро на v26.3.27, даже если та СТАРШЕ. 5c
     предлагает отключить таймер (по подтверждению);
  6. перезапускает Xray и печатает итоговую матрицу «клиент → работает?».

Обратный путь (пункт [5] → do_xray_update_interactive) после апгрейда
тоже вызывает sync_min_client_ver_for_core(): эпоха-управляемые значения
("", "1.8.0") мигрируют под новую эпоху (на 26.9.8+ гейт сбрасывается
в ""), кастомное значение юзера не трогается.

Точки входа:
    from chimera.modules.xray_downgrade import (
        parse_version, era_for_version, required_min_client_ver,
        read_min_client_ver_from_state, save_min_client_ver,
        apply_min_client_ver_to_live_configs, sync_min_client_ver_for_core,
        do_xray_downgrade_interactive,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import fcntl
import json
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Константы — те же реальные пути, что по всему проекту (pq_vless.py).
# Продублированы локально, чтобы модуль был автономен и не зависел от
# порядка импортов (тесты патчат эти атрибуты на tmp-пути).
STATE_FILE        = Path("/var/lib/xray-installer/state.json")
XRAY_CONFIG_PATHS = [Path("/etc/xray/config.json"),
                     Path("/usr/local/etc/xray/config.json")]
AUTOUPDATE_TIMER  = "xray-autoupdate.timer"

# Границы эпох (факты стенда 2026-09-10, VLESS_FAQ.md §18).
MLKEM_ERA_FIRST = (26, 9, 8)    # ClientHello обязан содержать X25519MLKEM768
GATE_ERA_FIRST  = (26, 7, 11)   # ""/unset → дефолт-гейт 26.3.27
GATE_ERA_LAST   = (26, 7, 28)   # последний релиз перед MLKEM-эпохой
GATE_ERA_VALUE  = "1.8.0"       # порог: sing-box [1,8,1] и mihomo [1,8,2] проходят

# Цели даунгрейда — ровно две («много не нужно»).
DOWNGRADE_TARGETS: List[Dict[str, Any]] = [
    {
        "tag": "v26.7.28",
        "version": "26.7.28",
        "era": "gate",
        "is_prerelease": True,
        "min_client_ver": "1.8.0",
        "title": "последний пререлиз перед MLKEM-эпохой — «оптимум совместимости»",
        "notes": [
            "MLKEM-чека НЕТ — sing-box-семья снова проходит",
            "(против 26.9.8+ она несовместима в принципе);",
            "авто-прописывается minClientVer=\"1.8.0\" — без него дефолт-гейт",
            "26.3.27 молча валит sing-box [1,8,1] и mihomo [1,8,2]",
        ],
        "clients": [
            ("Xray (Incy, v2rayNG)", "✓ работает"),
            ("sing-box (Nyamebox, Karing, Hiddify, SFM)",
             "✓ работает — [1,8,1] проходит порог «1.8.0»"),
            ("mihomo (Clash Verge, FlClash, роутеры)",
             "✓ работает — рецепт B уже в конфигах (тут не обязателен)"),
        ],
    },
    {
        "tag": "v26.3.27",
        "version": "26.3.27",
        "era": "pre-gate",
        "is_prerelease": False,
        "min_client_ver": "",
        "title": "последний СТАБИЛЬНЫЙ релиз GitHub (до-гейт-эпоха)",
        "notes": [
            "ни гейта, ни MLKEM-чека — все клиенты работают из коробки,",
            "правок конфига не требуется (minClientVer → \"\")",
            "мартовское ядро: был прецедент DPI-резки REALITY-ноги",
            "entry→exit (инцидент 29.08.2026, VLESS_FAQ §18) — цепочки осторожно",
        ],
        "clients": [
            ("Xray (Incy, v2rayNG)", "✓ работает"),
            ("sing-box (Nyamebox, Karing, Hiddify, SFM)", "✓ работает"),
            ("mihomo (Clash Verge, FlClash, роутеры)",
             "✓ работает (рецепт B не нужен, но и не мешает)"),
        ],
    },
]


# =============================================================================
#  ЧИСТЫЕ ХЕЛПЕРЫ: версия → эпоха → требуемое значение
# =============================================================================
def parse_version(ver: Any) -> Optional[Tuple[int, int, int]]:
    """'v26.7.28' / '26.7.28' / [26,7,28] → (26, 7, 28); None если не парсится."""
    if isinstance(ver, (list, tuple)):
        try:
            return tuple(int(x) for x in list(ver)[:3])  # type: ignore[return-value]
        except (TypeError, ValueError):
            return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(ver or ""))
    if not m:
        return None
    try:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def era_for_version(ver: Any) -> Optional[str]:
    """Версия ядра → эпоха: "mlkim" | "gate" | "pre-gate" | None (не парсится)."""
    v = parse_version(ver)
    if v is None:
        return None
    if v >= MLKEM_ERA_FIRST:
        return "mlkim"
    if GATE_ERA_FIRST <= v <= GATE_ERA_LAST:
        return "gate"
    return "pre-gate"


def required_min_client_ver(ver: Any) -> Optional[str]:
    """Требуемое minClientVer для эпохи версии ядра.

    gate-эпоха (26.7.11–26.7.28) → "1.8.0" (иначе дефолт-гейт 26.3.27
    валит sing-box/mihomo); MLKEM- и до-гейт-эпохи → "" (гейт выкл —
    норма). None = версию не удалось разобрать.
    """
    era = era_for_version(ver)
    if era is None:
        return None
    return GATE_ERA_VALUE if era == "gate" else ""


def era_label(era: Optional[str]) -> str:
    return {
        "mlkim": "MLKEM-эпоха",
        "gate": "гейт-эпоха",
        "pre-gate": "до-гейт",
        None: "эпоха не определена",
    }.get(era, "эпоха не определена")


def era_client_rows(era: Optional[str], mcv: str = "") -> List[Tuple[str, str]]:
    """Матрица «клиент → работает?» для эпохи (для меню 5c).

    В гейт-эпохе статус sing-box/mihomo зависит от фактического порога:
    пусто → дефолт-гейт 26.3.27 (оба валятся); порог считается от
    ClientVer клиента (sing-box [1,8,1], mihomo [1,8,2], Xray — 26.x).
    """
    if era == "mlkim":
        return [
            ("Xray (Incy, v2rayNG)", "✓ работает (fp=chrome/safari/firefox)"),
            ("mihomo (Clash Verge, FlClash, роутеры)",
             "✓ только рецепт B — уже в конфигах Chimera"),
            ("sing-box (Nyamebox, Karing, Hiddify, SFM)",
             "✗ несовместим в принципе — нет MLKEM в ClientHello"),
        ]
    if era == "pre-gate":
        return [
            ("Xray (Incy, v2rayNG)", "✓ работает"),
            ("mihomo (Clash Verge, FlClash, роутеры)",
             "✓ работает (рецепт B не нужен, но и не мешает)"),
            ("sing-box (Nyamebox, Karing, Hiddify, SFM)", "✓ работает"),
        ]
    if era == "gate":
        threshold = parse_version(mcv) if (mcv or "").strip() else (26, 3, 27)
        note = "" if (mcv or "").strip() else "  ← пусто = дефолт-гейт 26.3.27"
        sb = "✓ проходит порог" if (1, 8, 1) >= threshold else "✗ ниже порога"
        mh = "✓ проходит порог" if (1, 8, 2) >= threshold else "✗ ниже порога"
        xr = "✓ (отчитывают версию ядра 26.x)" if (26, 9, 9) >= threshold else "✗ порог выше ядер"
        return [
            (f"Xray (Incy, v2rayNG){note}", xr),
            ("sing-box (Nyamebox, Karing, Hiddify, SFM)", sb),
            ("mihomo (Clash Verge, FlClash, роутеры)", mh),
        ]
    return []


# =============================================================================
#  STATE.JSON — min_client_ver (read-modify-write под flock, паттерн pq_state_save)
# =============================================================================
def read_min_client_ver_from_state() -> str:
    """minClientVer из state.json (без глобали — чистое чтение файла)."""
    try:
        state = json.loads(STATE_FILE.read_text())
        v = state.get("min_client_ver", "")
        return v if isinstance(v, str) else ""
    except Exception:
        return ""


def save_min_client_ver(value: str) -> bool:
    """Сохраняет min_client_ver в state.json (flock, read-modify-write).

    Тот же паттерн атомарности, что pq_state_save()/_save_min_client_ver_
    to_state(): перечитывает файл под эксклюзивной блокировкой — не
    затирает чужие ключи (UUID юзеров, ключи REALITY, PQ-VLESS...).
    Дополнительно синхронизирует глобаль PARAM_MIN_CLIENT_VER в уже
    ЗАГРУЖЕННОМ chimera._core (по sys.modules, без импорта) — иначе 5b
    в той же сессии прочитал бы устаревшую глобаль.
    """
    value = (value or "").strip()
    if not STATE_FILE.exists():
        return False
    try:
        with STATE_FILE.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read()
                state = json.loads(content) if content else {}
                state["min_client_ver"] = value
                f.seek(0)
                f.truncate()
                f.write(json.dumps(state, indent=2, ensure_ascii=False))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception:
        return False
    _sync_core_global(value)
    return True


def _sync_core_global(value: str) -> None:
    """PARAM_MIN_CLIENT_VER в загруженном chimera._core (sys.modules-lookup).

    Импорт _core здесь НЕ выполняется сознательно: модуль ядра тяжёлый
    (побочные эффекты на ФС при импорте), а синхронизация нужна только
    если ядро уже и так работает в этой сессии.
    """
    mod = sys.modules.get("chimera._core")
    if mod is not None:
        try:
            mod.PARAM_MIN_CLIENT_VER = value
        except Exception:
            pass


# =============================================================================
#  ПРИВЯЗКА К ЯДРУ (_core.py) — лениво, как в xray_install.py
# =============================================================================
def _core_module():
    """chimera._core лениво (паттерн xray_install._core_module).

    При сбое импорта — минимальный shim (plain-print, subprocess._run),
    чтобы модуль оставался автономным (cron/скрипты/тесты).
    """
    try:
        import importlib
        return importlib.import_module("chimera._core")
    except Exception:
        return _core_shim()


def _core_shim() -> types.ModuleType:
    m = types.ModuleType("chimera._core.shim")
    for c in ("NC", "CYAN", "BOLD", "DIM", "GREEN", "RED", "YELLOW", "BLUE"):
        setattr(m, c, "")
    m.info    = lambda s: print(f"[i] {s}")
    m.warn    = lambda s: print(f"[!] {s}")
    m.success = lambda s: print(f"[+] {s}")
    m.dim     = lambda s: print(f"    {s}")

    def _run(cmd, capture=True, check=False, quiet=False):
        return subprocess.run(cmd, capture_output=capture, text=True, check=check)

    m._run = _run
    m._box_top    = lambda t="": print(f"\n{'=' * 64}\n  {t}\n{'=' * 64}")
    m._box_row    = lambda s="": print(s)
    m._box_sep    = lambda: print("-" * 64)
    m._box_item   = lambda k="", s="": print(f"  [{k}] {s}")
    m._box_back   = lambda: print("  [Q] Назад")
    m._box_bottom = lambda: print("=" * 64)
    m.PARAM_MIN_CLIENT_VER = ""
    return m


# =============================================================================
#  ПАТЧЕР ЖИВЫХ КОНФИГОВ — minClientVer/maxClientVer во всех REALITY-инбаундах
# =============================================================================
def _find_xray_bin() -> Optional[str]:
    for candidate in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if Path(candidate).exists():
            return candidate
    return shutil.which("xray")


def _xray_config_test(cfg_path: Path, xray_bin: Optional[str],
                      core) -> Optional[str]:
    """`xray run -test -config` — None = ОК, иначе текст ошибки."""
    if not xray_bin:
        return None  # бинарника нет (стенд/тест) — тест считаем пройденным
    cmd = [xray_bin, "run", "-test", "-config", str(cfg_path)]
    try:
        rt = core._run(cmd, capture=True, check=False)
    except Exception:
        try:
            rt = subprocess.run(cmd, capture_output=True, text=True)
        except Exception as e:
            return f"не удалось запустить тест: {e}"
    if getattr(rt, "returncode", 1) != 0:
        out = (getattr(rt, "stderr", "") or getattr(rt, "stdout", "") or "")
        return str(out).strip() or "xray run -test провалился (без вывода)"
    return None


def apply_min_client_ver_to_live_configs(value: str,
                                         *, run_test: bool = True) -> Dict[str, Any]:
    """Патчит minClientVer/maxClientVer во всех REALITY-инбаундах живых
    конфигов Xray (/etc/xray/config.json + зеркало /usr/local/etc/xray/).

    Возвращает отчёт:
        {"files": [{"path", "patched_inbounds", "status", "error"}],
         "changed_files": int, "test_ok": bool}

    Статусы файла: "ok" (записан+тест прошёл), "unchanged" (значение уже
    правильное), "skipped" (файла нет), "test_failed" (записан, тест
    провален → файл ОТКАЧЕН к прежнему содержимому; провалившийся вариант
    сохранён рядом как *.downgrade-failed), "error" (I/O/JSON).

    maxClientVer нормализуется в "" — как пишут генераторы (непустой
    верхний порог никто не использует).
    """
    core = _core_module()
    value = (value or "").strip()
    files_report: List[Dict[str, Any]] = []
    changed_files = 0
    test_ok = True
    xray_bin = _find_xray_bin() if run_test else None

    for cfg_path in XRAY_CONFIG_PATHS:
        entry: Dict[str, Any] = {"path": str(cfg_path),
                                 "patched_inbounds": 0,
                                 "status": "skipped", "error": None}
        try:
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text())
                changed = 0
                for ib in cfg.get("inbounds") or []:
                    if not isinstance(ib, dict):
                        continue
                    ss = ib.get("streamSettings") or {}
                    if not isinstance(ss, dict):
                        continue
                    if str(ss.get("security", "")).lower() != "reality":
                        continue
                    rs = ss.get("realitySettings")
                    if not isinstance(rs, dict):
                        rs = {}
                        ss["realitySettings"] = rs
                    if rs.get("minClientVer") != value or rs.get("maxClientVer", "") != "":
                        rs["minClientVer"] = value
                        rs["maxClientVer"] = ""
                        changed += 1
                if changed:
                    backup_text = cfg_path.read_text()
                    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                    entry["patched_inbounds"] = changed
                    test_err = _xray_config_test(cfg_path, xray_bin, core)
                    if test_err:
                        # Дамп провалившегося конфига ДО отката (паттерн
                        # pq_vless._write_and_test) — иначе он теряется.
                        try:
                            cfg_path.with_suffix(
                                cfg_path.suffix + ".downgrade-failed"
                            ).write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                        except Exception:
                            pass
                        cfg_path.write_text(backup_text)
                        entry["status"] = "test_failed"
                        entry["error"] = (test_err or "")[:800]
                        test_ok = False
                    else:
                        entry["status"] = "ok"
                        changed_files += 1
                else:
                    entry["status"] = "unchanged"
        except Exception as e:
            entry["status"] = "error"
            entry["error"] = str(e)
            test_ok = False
        files_report.append(entry)

    return {"files": files_report, "changed_files": changed_files, "test_ok": test_ok}


# =============================================================================
#  СИНК ЭПОХИ — значение следует за версией ядра
# =============================================================================
def sync_min_client_ver_for_core(version_str: Any, *,
                                 verbose: bool = True) -> bool:
    """Подгоняет min_client_ver (state.json + живые конфиги) под эпоху ядра.

    Вызывается после ЛЮБОЙ смены бинарника: даунгрейд из 5c и апгрейд из
    пункта [5] (do_xray_update_interactive). Правило:
      • эпоха-управляемые значения ("", "1.8.0") мигрируют автоматически:
        гейт-эпоха требует "1.8.0", MLKEM/до-гейт — "";
      • КАСТОМНОЕ значение (например "1.0.0", выставленное юзером через
        5b) не трогается — только предупреждение.

    Конфигы патчатся ДО рестарта сервиса — рестарт делает вызывающий
    (один на всё: бинарник + конфиг). Возвращает True, если значение
    менялось.
    """
    core = _core_module()
    era = era_for_version(version_str)
    if era is None:
        if verbose:
            core.warn(f"Не удалось определить эпоху ядра {version_str!r} — "
                      "minClientVer не менялся")
        return False
    required = GATE_ERA_VALUE if era == "gate" else ""
    current = read_min_client_ver_from_state()

    if current == required:
        if verbose:
            core.info(f"minClientVer = {current or '\"\"'} — уже соответствует "
                      f"эпохе {era_label(era)} ({version_str})")
        return False

    if current and current != GATE_ERA_VALUE:
        if verbose:
            core.warn(f"minClientVer = {current!r} (кастомное) — под эпоху "
                      f"{era_label(era)} не подгоняю, значение оставлено. "
                      f"Сменить: пункт [5b]. Требуемое для эпохи: "
                      f"{required or '\"\"'}")
        return False

    # Эпоха-управляемое значение — мигрируем: сначала state (источник
    # правды для генераторов), затем живые конфиги.
    saved = save_min_client_ver(required)
    if not saved and verbose:
        core.warn(f"{STATE_FILE} недоступен — значение применено только к "
                  "конфигам (до следующего rebuild)")
    report = apply_min_client_ver_to_live_configs(required)

    if verbose:
        for f in report["files"]:
            if f["status"] == "ok":
                core.success(f"{f['path']}: minClientVer → "
                             f"{required or '\"\"'} ({f['patched_inbounds']} "
                             "REALITY-инбаунд(ов))")
            elif f["status"] == "test_failed":
                core.warn(f"{f['path']}: тест конфига провалился, файл "
                          "откачен как был — перегенерируйте через [5b]; "
                          f"причина: {f['error']}")
            elif f["status"] == "error":
                core.warn(f"{f['path']}: {f['error']}")
        if all(f["status"] == "skipped" for f in report["files"]):
            core.info("Живых конфигов Xray не найдено — значение сохранено "
                      "в state.json, применится при перегенерации [5b]")
        if saved:
            core.success(f"state.json: min_client_ver → {required or '\"\"'} "
                         f"(эпоха {era_label(era)}), переживёт rebuild/ротации")
    return True


# =============================================================================
#  ГАРД АВТООБНОВЛЕНИЯ — таймер сравнивает версии только на РАВЕНСТВО
# =============================================================================
def autoupdate_timer_enabled() -> bool:
    """Активен ли xray-autoupdate.timer.

    Его bash-скрипт (xray_install._install_autoupdate_service) сравнивает
    текущую версию с GitHub-stable ТОЛЬКО на равенство (==) — после
    даунгрейда он молча перетянет ядро на v26.3.27, даже если та старше.
    """
    try:
        rt = subprocess.run(["systemctl", "is-enabled", AUTOUPDATE_TIMER],
                            capture_output=True, text=True, timeout=10)
        return rt.stdout.strip().lower() == "enabled"
    except Exception:
        return False


def disable_autoupdate_timer() -> bool:
    try:
        subprocess.run(["systemctl", "disable", "--now", AUTOUPDATE_TIMER],
                       capture_output=True, text=True, timeout=30)
        return True
    except Exception:
        return False


# =============================================================================
#  МЕНЮ 5c — даунгрейд ядра с авто-подгонкой конфига под эпоху
# =============================================================================
def do_xray_downgrade_interactive() -> None:
    """Интерактивный даунгрейд ядра Xray (пункт меню 5c).

    Ядро ставится через _xray_do_upgrade() (download manager: 10 зеркал +
    SHA256 + бэкап + тест конфига + авт. откат) — тот же путь, что пункт
    [5] Обновить Xray-core. Конфиг подгоняется под эпоху автоматически
    (sync_min_client_ver_for_core): «ядро → какие поля/значения» больше
    не головоломка юзера.
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    CYAN, NC = core.CYAN, core.NC
    BOLD, DIM, GREEN, RED, YELLOW = core.BOLD, core.DIM, core.GREEN, core.RED, core.YELLOW
    _box_top, _box_row = core._box_top, core._box_row
    _box_sep, _box_item, _box_back, _box_bottom = \
        core._box_sep, core._box_item, core._box_back, core._box_bottom

    try:
        from chimera.modules import xray_install
    except ImportError as e:
        warn(f"Модуль xray_install не найден: {e}")
        return

    cur_ver = xray_install._xray_current_version()
    cur_era = era_for_version(cur_ver)
    mcv = read_min_client_ver_from_state()

    # ── Экран 1: текущее состояние + цели ──────────────────────────────
    print()
    _box_top("⬇️  ДАУНГРЕЙД ЯДРА XRAY-CORE")
    _box_row()
    _box_row(f"  Текущее ядро: {CYAN}{cur_ver}{NC} — {era_label(cur_era)}")
    _box_row(f"  minClientVer (state.json): {CYAN}{mcv or '\"\"'}{NC}")
    if cur_era == "gate" and mcv != GATE_ERA_VALUE:
        _box_row(f"  {YELLOW}⚠  эпоха гейта без \"{GATE_ERA_VALUE}\" — дефолт-гейт "
                 f"26.3.27 валит sing-box/mihomo{NC}")
    _box_row()
    _box_row("  Сейчас работают клиенты:")
    for name, st in era_client_rows(cur_era, mcv):
        _box_row(f"   • {name}: {st}")
    _box_row()
    _box_row(f"  Даунгрейд подгоняет конфиг под эпоху нового ядра сам")
    _box_row(f"  (minClientVer; {DIM}серверных MLKEM-полей не существует — это "
             f"поведение ядра{NC}).")
    _box_row(f"  {DIM}Установка — через download manager (10 зеркал + SHA256 + "
             f"бэкап + тест конфига с откатом). Матрица: VLESS_FAQ.md §18{NC}")
    _box_sep()

    keys = []
    for i, t in enumerate(DOWNGRADE_TARGETS, 1):
        keys.append(str(i))
        _box_row(f"  [{i}] {BOLD}{t['tag']}{NC} — {t['title']}")
        for line in t["notes"]:
            _box_row(f"      {DIM}{line}{NC}")
        _box_row(f"      Конфиг после даунгрейда: minClientVer="
                 f"{BOLD}{t['min_client_ver'] or '\"\"'}{NC}")
        _box_row("      Клиенты после даунгрейда:")
        for cname, cst in t["clients"]:
            _box_row(f"       • {cname}: {cst}")
        if parse_version(t["version"]) == parse_version(cur_ver):
            _box_row(f"      {GREEN}(уже установлено — даунгрейд не требуется){NC}")
    _box_sep()
    _box_item("Q", "Отмена")
    _box_row()
    _box_back()
    _box_bottom()
    print()

    try:
        choice = input(f"{CYAN}Выбор:{NC} ").strip()
    except (KeyboardInterrupt, EOFError):
        info("Отменено.")
        return
    if choice.lower() in ("q", ""):
        info("Даунгрейд отменён.")
        return
    target = None
    for i, t in enumerate(DOWNGRADE_TARGETS, 1):
        if choice == str(i):
            target = t
            break
    if target is None:
        warn("Неверный выбор.")
        return
    if parse_version(target["version"]) == parse_version(cur_ver):
        info(f"Ядро {target['tag']} уже установлено — даунгрейд не требуется.")
        return

    # ── Экран 2: подтверждение ──────────────────────────────────────────
    print()
    print(f"{YELLOW}{'═' * 64}{NC}")
    print(f"{YELLOW}  ⚠  ДАУНГРЕЙД ЯДРА: {cur_ver} → {target['tag']}{NC}")
    print(f"{YELLOW}{'═' * 64}{NC}")
    print(f"  Бинарник будет заменён (бэкап: /var/backups/xray/binaries/,")
    print(f"  при провале теста конфига — автоматический откат).")
    print(f"  Конфиг подгонится под эпоху: minClientVer → "
          f"{BOLD}{target['min_client_ver'] or '\"\"'}{NC}.")
    print(f"  {DIM}Вернуть актуальное ядро — пункт [5] Обновить Xray-core; "
          f"minClientVer{NC}")
    print(f"  {DIM}мигрирует обратно автоматически.{' ' * 24}{NC}")
    print(f"{YELLOW}{'═' * 64}{NC}")
    print()
    try:
        confirm = input(f"{YELLOW}Продолжить? [y/N]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        confirm = "n"
    if confirm not in ("y", "yes"):
        info("Отменено.")
        return

    # ── Гард автапдейта: таймер перетянет ядро на GitHub-stable ────────
    if autoupdate_timer_enabled():
        print()
        warn(f"Таймер {AUTOUPDATE_TIMER} активен: его скрипт сравнивает "
             "версии только на РАВЕНСТВО с GitHub-stable (v26.3.27) и "
             "молча сменит ядро после следующего запуска (03:30), даже "
             "если та старше.")
        try:
            ans = input(f"{CYAN}Отключить автообновление? [Y/n]:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = "y"
        if ans in ("y", "yes", ""):
            if disable_autoupdate_timer():
                success(f"Автообновление отключено (вернуть: пункт [5] → "
                        "предложит включить, или setup_xray_autoupdate)")
            else:
                warn("Не удалось отключить таймер — проверьте вручную: "
                     f"systemctl disable --now {AUTOUPDATE_TIMER}")
        else:
            warn("Таймер оставлен — ядро может смениться на v26.3.27 "
                 "в ближайшую ночь.")

    # ── Установка ядра (тот же путь, что пункт [5]) ─────────────────────
    print()
    info(f"Даунгрейд {cur_ver} → {target['tag']} "
         "(download manager: зеркала + SHA256 + бэкап + тест конфига)...")
    try:
        ok = xray_install._xray_do_upgrade(target["tag"],
                                           is_prerelease=target["is_prerelease"])
    except Exception as e:
        warn(f"Сбой установки ядра: {e}")
        ok = False
    if not ok:
        warn("Даунгрейд не выполнен (скачивание/тест провалились) — "
             "бинарник и конфиг не менялись (автоматический откат).")
        return

    # ── Подгонка конфига под эпоху ДО рестарта (один рестарт на всё) ────
    try:
        sync_min_client_ver_for_core(target["version"], verbose=True)
    except Exception as e:
        warn(f"Подгонка minClientVer под эпоху пропущена: {e} — "
             "выставьте вручную через [5b]")

    # ── Перезапуск + итог ───────────────────────────────────────────────
    try:
        started = xray_install._xray_restart_all_services()
    except Exception as e:
        warn(f"Ошибка перезапуска: {e}")
        started = False
    try:
        new_ver = xray_install._xray_current_version()
    except Exception:
        new_ver = target["version"]

    if not started:
        print()
        print(f"{RED}{'═' * 64}{NC}")
        print(f"{RED}  ✗ XRAY НЕ ЗАПУСТИЛСЯ ПОСЛЕ ДАУНГРЕЙДА{NC}")
        print(f"{RED}{'═' * 64}{NC}")
        print()
        print(f"  Причина:   {BOLD}{CYAN}journalctl -u xray -n 50 --no-pager{NC}")
        print(f"  Тест:      {BOLD}{CYAN}xray run -test -config /etc/xray/config.json{NC}")
        print(f"  Вернуть актуальное ядро: пункт [5] (или бэкапы ")
        print(f"  /var/backups/xray/binaries/)")
        print(f"{RED}{'═' * 64}{NC}")
        return

    if parse_version(new_ver) != parse_version(target["version"]):
        warn(f"Версия после установки ({new_ver}) не совпала с ожидаемой "
             f"{target['tag']} — проверьте `xray version`")

    print()
    _box_top("✅  ДАУНГРЕЙД ВЫПОЛНЕН")
    _box_row()
    _box_row(f"  Ядро: {CYAN}{cur_ver}{NC} → {GREEN}{new_ver}{NC} "
             f"({era_label(era_for_version(new_ver))})")
    _box_row(f"  minClientVer: {GREEN}{target['min_client_ver'] or '\"\"'}{NC} "
             "(state.json + все REALITY-инбаунды живых конфигов)")
    _box_row()
    _box_row("  Теперь работают клиенты:")
    for cname, cst in target["clients"]:
        _box_row(f"   • {cname}: {cst}")
    _box_row()
    _box_row(f"  {DIM}mihomo-конфиги менять не нужно: рецепт B (chrome +{NC}")
    _box_row(f"  {DIM}support-x25519mlkem768) безвреден на всех эпохах.{NC}")
    _box_row(f"  {DIM}exit-ноды цепочки получат значение при следующей "
             f"перегенерации.{NC}")
    _box_row(f"  {DIM}Вернуть актуальное ядро — пункт [5]: minClientVer "
             f"мигрирует{NC}")
    _box_row(f"  {DIM}обратно автоматически. Матрица: VLESS_FAQ.md §18{NC}")
    _box_row()
    _box_bottom()
