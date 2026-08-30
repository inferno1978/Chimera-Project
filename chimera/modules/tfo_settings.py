# =============================================================================
#  tfo_settings.py — централизованное управление TCP Fast Open (TFO)
# =============================================================================
#  ИСТОРИЯ (инцидент 28.08.2026, vds-old / 203.0.113.104):
#    Каскад .112 → exit.example:9443 (VLESS+REALITY) внезапно умер:
#    TLS-хендшейк проходил (openssl 0.27s), но VLESS-ответ не приходил.
#    A/B-тест на самой .112 это доказал:
#      • конфиг с tcpFastOpen=true  → таймаут, 0 байт;
#      • тот же конфиг без TFO      → туннель работает мгновенно.
#    Вывод: TSPU/DPI на транзитном сегменте начали резать пакеты с данными
#    внутри SYN (data-in-SYN = «не браузерная» сигнатура TFO). Нормальный
#    браузер TFO ClientHello в SYN не отправляет.
#
#  ПОЛИТИКА ПРОЕКТА С ЭТОГО МОМЕНТА:
#    • TFO ПОЛНОСТЬЮ ВЫКЛЮЧЕН ПО УМОЛЧАНИЮ во ВСЕХ генераторах/перегенераторах
#      конфигов: серверный Xray (REALITY + xHTTP, одиночный и каскад),
#      клиентские Xray/sing-box профили, fragment/noise/mux конфиги,
#      exit-ноды Режима B, YouTube-route freedom outbound.
#    • Включить TFO можно ТОЛЬКО явно:
#        — промптом во время установки (с предупреждением);
#        — пунктом меню: Настройки сети → T (TCP Fast Open).
#    • Выбор персистится в state.json ("tfo_enabled") и применяется ко всем
#      последующим генерациям/перегенерациям конфигов.
#
#  ВАЖНО ПРО SYSCTL: ядро (net.ipv4.tcp_fastopen = 3) НЕ трогаем — оно
#  остаётся как было (network_setup.py). Настройка ядра безвредна:
#  data-in-SYN возникает ТОЛЬКО когда приложение явно просит TFO
#  (sockopt tcpFastOpen в конфиге Xray). С выключенным sockopt ядро
#  TFO не активирует. Решение администратора: sysctl работе не мешал.
#
#  МОДУЛЬ САМОСТОЯТЕЛЕН (stdlib-only) — импортируется из _core.py,
#  fragment_*, chain_nodes, youtube_route, network_setup без циклических
#  зависимостей. UI-функции (промпт/меню) тянут _core лениво.
# -----------------------------------------------------------------------------
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# ── Пути (те же, что использует _core.py) ──────────────────────────────────
STATE_FILE  = Path("/var/lib/xray-installer/state.json")
XRAY_CONFIG = Path("/etc/xray/config.json")

# Ключ в state.json
TFO_KEY = "tfo_enabled"

# Runtime-override: используется во время УСТАНОВКИ, когда state.json ещё
# не существует (или содержит значение от прошлой установки). Промпт
# установки вызывает set_tfo_override(); после сохранения state.json
# значение «переезжает» в state.json, override можно очистить.
_OVERRIDE: bool | None = None

# Резервный сброс цвета для _error (когда _core недоступен)
NC_FALLBACK = "\033[0m"


# =============================================================================
#  ЧТЕНИЕ / ЗАПИСЬ СОСТОЯНИЯ
# =============================================================================
def set_tfo_override(enabled: bool) -> None:
    """Установить runtime-override (этап установки, до записи state.json)."""
    global _OVERRIDE
    _OVERRIDE = bool(enabled)


def clear_tfo_override() -> None:
    """Сбросить runtime-override (после сохранения state.json)."""
    global _OVERRIDE
    _OVERRIDE = None


def is_tfo_enabled(state_file: Path | None = None) -> bool:
    """Включён ли TFO.

    Приоритет: runtime-override → state.json → False (дефолт проекта).
    """
    if _OVERRIDE is not None:
        return _OVERRIDE
    sf = Path(state_file) if state_file else STATE_FILE
    try:
        if sf.exists():
            state = json.loads(sf.read_text())
            return bool(state.get(TFO_KEY, False))
    except Exception:
        pass
    return False


def set_tfo_state(enabled: bool, state_file: Path | None = None) -> bool:
    """Персистнуть tfo_enabled в state.json (merge, атомарная запись).

    Возвращает True при успехе.
    """
    sf = Path(state_file) if state_file else STATE_FILE
    try:
        state: dict = {}
        if sf.exists():
            state = json.loads(sf.read_text())
        state[TFO_KEY] = bool(enabled)
        sf.parent.mkdir(parents=True, exist_ok=True)
        tmp = sf.with_suffix(sf.suffix + ".tmp")
        tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(sf)
        return True
    except Exception as e:
        _emit("error", f"Не удалось сохранить tfo_enabled в {sf}: {e}")
        return False


# =============================================================================
#  ПОЛЯ ДЛЯ ГЕНЕРАТОРОВ КОНФИГОВ
# =============================================================================
def tfo_sockopt() -> dict:
    """Поля для Xray streamSettings.sockopt.

    Возвращает {"tcpFastOpen": True} если TFO включён, иначе {} —
    генераторы просто делают **tfo_sockopt() в свой словарь.
    """
    return {"tcpFastOpen": True} if is_tfo_enabled() else {}


def tfo_dial() -> dict:
    """Поля для sing-box dial-объекта outbound'а.

    Возвращает {"tcp_fast_open": True} если TFO включён, иначе {}.
    """
    return {"tcp_fast_open": True} if is_tfo_enabled() else {}


# =============================================================================
#  ПРИМЕНЕНИЕ К ЖИВОМУ КОНФИГУ XRAY (вкл/выкл без переустановки)
# =============================================================================
def apply_tfo_to_xray_config(
    enabled: bool | None = None,
    cfg_path: Path | None = None,
) -> tuple[int, int]:
    """Пропатчить живой /etc/xray/config.json: добавить/убрать tcpFastOpen
    во ВСЕХ inbounds/outbounds, где есть streamSettings.

    Возвращает (добавлено, удалено). Идемпотентно, атомарная запись.
    Не трогает остальные поля sockopt (mark, fragment, keepalive и т.д.).
    """
    if enabled is None:
        enabled = is_tfo_enabled()
    path = Path(cfg_path) if cfg_path else XRAY_CONFIG
    added = removed = 0
    try:
        if not path.exists():
            _emit("warn", f"Конфиг не найден: {path}")
            return (0, 0)
        cfg = json.loads(path.read_text())

        def _walk(entries):
            nonlocal added, removed
            for ent in entries or []:
                if not isinstance(ent, dict):
                    continue
                ss = ent.get("streamSettings")
                if not isinstance(ss, dict):
                    continue  # dokodemo-door stats и пр. — не трогаем
                so = ss.setdefault("sockopt", {})
                if not isinstance(so, dict):
                    so = {}
                    ss["sockopt"] = so
                if enabled:
                    if not so.get("tcpFastOpen"):
                        so["tcpFastOpen"] = True
                        added += 1
                else:
                    if so.pop("tcpFastOpen", None) is not None:
                        removed += 1

        _walk(cfg.get("inbounds"))
        _walk(cfg.get("outbounds"))

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(path)
    except Exception as e:
        _emit("error", f"Не удалось пропатчить {path}: {e}")
        return (0, 0)
    return (added, removed)


# =============================================================================
#  UI: промпт установки
# =============================================================================
def prompt_tfo_choice() -> bool:
    """Промпт установки: включить/выключить TCP Fast Open.

    Вызывается из do_full_install() и dry-run ПОСЛЕ выбора split tunneling,
    действует для ЛЮБОГО режима (A/B, REALITY/xHTTP, одиночный/каскад).
    Дефолт (Enter) = ВЫКЛЮЧИТЬ.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_desc   = core._box_desc
    _box_bottom = core._box_bottom
    success = core.success
    warn    = core.warn
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    NC     = core.NC

    _box_top("⚡  TCP Fast Open (TFO)")
    _box_row()
    _box_desc(f"TFO отправляет данные (TLS ClientHello) внутри SYN-пакета.")
    _box_desc(f"{RED}Провайдерские DPI/TSPU распознают это как не-браузерный")
    _box_desc(f"трафик и могут ПОЛНОСТЬЮ обрезать соединение{NC} — TLS при")
    _box_desc(f"этом проходит, а туннель умирает (инцидент 28.08.2026).")
    _box_row()
    _box_item("1", f"🚫 ВЫКЛЮЧИТЬ  {GREEN}(рекомендуется, Enter по умолчанию){NC}")
    _box_desc(f"Совместимо с любыми DPI. Микро-выигрыш в latency теряется —")
    _box_desc(f"это нормальная цена стабильности.")
    _box_row()
    _box_item("2", f"⚡ Включить  {YELLOW}(только если уверены в своём маршруте){NC}")
    _box_desc(f"Экономит 1 RTT на каждом соединении. Риск: см. выше.")
    _box_row()
    _box_bottom()
    enabled = False
    while True:
        try:
            ch = input(f"  Выбор [1]: ").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if ch == "1":
            enabled = False
            break
        elif ch == "2":
            enabled = True
            break
        warn("Введите 1 или 2")

    set_tfo_override(enabled)
    # Дублируем в глобаль _core — для отображения и сохранения в state.json
    setattr(core, "TFO_ENABLED", enabled)
    if enabled:
        success("TFO: ВКЛЮЧЁН (по явному выбору). Помните: может резаться DPI.")
    else:
        success("TFO: ВЫКЛЮЧЕН (дефолт безопасности)")
    return enabled


# =============================================================================
#  UI: пункт меню «Настройки сети → T»
# =============================================================================
def do_manage_tfo() -> None:
    """Меню управления TFO: статус, переключение, применение на живую.

    При переключении: state.json → живой config.json (все sockopt) →
    безопасный рестарт Xray (xray run -test, откат при ошибке).
    Sysctl-ядро (net.ipv4.tcp_fastopen=3) НЕ трогаем — оно безвредно без
    прикладного запроса TFO и решением администратора оставлено как есть.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_desc   = core._box_desc
    _box_back   = core._box_back
    _box_bottom = core._box_bottom
    info    = core.info
    success = core.success
    warn    = core.warn
    # ВНИМАНИЕ: в _core.py НЕТ функции error (только info/success/warn) —
    # свой хелпер _error (инцидент 29.08.2026: AttributeError в меню T).
    error   = _error
    GREEN  = core.GREEN
    RED    = core.RED
    YELLOW = core.YELLOW
    DIM    = core.DIM
    NC     = core.NC

    cur = is_tfo_enabled()
    while True:
        status = (f"{GREEN}ВКЛЮЧЁН ⚡{NC}" if cur else f"{RED}ВЫКЛЮЧЕН 🚫{NC}")
        _box_top("⚡  TCP FAST OPEN (TFO)")
        _box_row()
        _box_row(f"  Текущее состояние:  {status}")
        _box_row(f"  {DIM}Хранится в state.json: tfo_enabled{NC}")
        _box_row()
        _box_desc(f"Дефолт проекта — {RED}ВЫКЛЮЧЕН{NC}: TFO кладёт ClientHello")
        _box_desc(f"внутрь SYN-пакета, что DPI/TSPU распознают как не-браузерный")
        _box_desc(f"трафик и режут (инцидент 28.08.2026: каскад умер при живом TLS).")
        _box_row()
        if cur:
            _box_item("1", f"🚫 ВЫКЛЮЧИТЬ  {GREEN}(рекомендуется){NC}")
            _box_item("2", "↻ Переприменить текущее состояние (ремонт конфига)")
        else:
            _box_item("1", f"🚫 Оставить ВЫКЛЮЧЕННЫМ (ничего не менять)")
            _box_item("2", f"⚡ ВКЛЮЧИТЬ  {YELLOW}(риск блокировки DPI!){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{core.CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break

        if ch in ("b", "B", "0", ""):
            break
        if ch == "1":
            if cur:
                _tfo_apply(False)
                cur = is_tfo_enabled()
            else:
                break
        elif ch == "2":
            if cur:
                _tfo_apply(True)   # переприменить
            else:
                _tfo_apply(True)   # включить
            cur = is_tfo_enabled()
        else:
            warn("Введите 1, 2 или B")
        input(f"{core.BLUE}Нажмите Enter...{NC}")


def _tfo_apply(enabled: bool) -> None:
    """Применить состояние TFO: state → config.json → рестарт."""
    core = _core_module()
    info    = core.info
    success = core.success
    warn    = core.warn
    error   = _error  # в _core нет error — см. do_manage_tfo

    if not set_tfo_state(enabled):
        error("Не удалось сохранить состояние — отмена.")
        return
    set_tfo_override(enabled)

    # 1. Живой config.json
    if XRAY_CONFIG.exists():
        backup = XRAY_CONFIG.with_suffix(".json.bak-tfo")
        try:
            backup.write_bytes(XRAY_CONFIG.read_bytes())
        except Exception as e:
            warn(f"Бэкап config.json не создан: {e}")
        added, removed = apply_tfo_to_xray_config(enabled)
        info(f"config.json: tcpFastOpen добавлен в {added} sockopt, "
             f"удалён из {removed}")
        # 2. Валидация + рестарт
        if _test_and_restart_xray(backup):
            success(f"TFO {'ВКЛЮЧЁН' if enabled else 'ВЫКЛЮЧЕН'} и применён "
                    f"к живому конфигу, Xray перезапущен.")
        else:
            # откат уже выполнен внутри _test_and_restart_xray
            set_tfo_state(not enabled)
            set_tfo_override(not enabled)
    else:
        warn(f"{XRAY_CONFIG} не найден — state сохранён, конфиг не тронут "
             f"(применится при следующей генерации).")

    # 3. Ядро (sysctl net.ipv4.tcp_fastopen=3) сознательно НЕ трогаем:
    #    без прикладного sockopt TFO ядро data-in-SYN не отправляет.
    info("Клиентские профили (подписки/экспорт) подхватят настройку "
         "при следующей генерации.")


def _test_and_restart_xray(backup: Path | None) -> bool:
    """xray run -test → systemctl restart xray; откат из backup при неудаче.

    v72.1: reset-failed перед каждым рестартом (паттерн v57 — двойной
    рестарт при откате без сброса ловит start-limit-hit, guard-тест
    test_v57_...::test_no_bare_xray_restarts).
    """
    core = _core_module()
    warn = core.warn
    r = subprocess.run(["xray", "run", "-test", "-c", str(XRAY_CONFIG)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        warn(f"Новый конфиг НЕ валиден — откатываю и не перезапускаю Xray.")
        _rollback(backup)
        return False
    subprocess.run(["systemctl", "reset-failed", "xray"],
                   capture_output=True, check=False)
    r = subprocess.run(["systemctl", "restart", "xray"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        warn("systemctl restart xray вернул ошибку — откат конфига.")
        _rollback(backup)
        subprocess.run(["systemctl", "reset-failed", "xray"],
                       capture_output=True, check=False)
        subprocess.run(["systemctl", "restart", "xray"],
                       capture_output=True, timeout=60)
        return False
    return True


def _rollback(backup: Path | None) -> None:
    if backup and backup.exists():
        try:
            XRAY_CONFIG.write_bytes(backup.read_bytes())
        except Exception as e:
            _emit("error", f"Откат не удался: {e}")


# =============================================================================
#  Вспомогательное
# =============================================================================
def _core_module():
    """Ленивая привязка к chimera._core (как в chain_nodes.py)."""
    import importlib
    return importlib.import_module("chimera._core")


def _error(msg: str) -> None:
    """[ERROR]-печать. В _core.py функции error НЕТ (только info/success/
    warn + log_to_file) — свой хелпер по паттерну olcrtc.py. Отказ _core
    (headless/тесты) → печать в stderr, без падения."""
    try:
        core = _core_module()
        print(f"{core.RED}[ERROR]{NC_FALLBACK} {msg}")
        try:
            core.log_to_file("ERROR", msg)
        except Exception:
            pass
    except Exception:
        print(f"[tfo:ERROR] {msg}", file=sys.stderr)


def _emit(level: str, msg: str) -> None:
    """Логирование без жёсткой зависимости от _core (для cron/тестов)."""
    try:
        core = _core_module()
        fn = {"info": core.info, "warn": core.warn, "error": _error}.get(level)
        if fn:
            fn(msg)
            return
    except Exception:
        pass
    print(f"[tfo:{level}] {msg}", file=sys.stderr)
