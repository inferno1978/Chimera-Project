#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# scripts/ci_suite.sh — единый CI-прогон Химеры (Forgejo Actions + GitHub
# Actions вызывают ОДИН этот скрипт; разница только в питоне и режиме).
#
# ENV-ИЗОЛЯЦИЯ: все unittest-режимы гоняются с CHIMERA_TEST_ISOLATE=1
# (tests/_env_isolation.py): прод-деревья ноды (/var/lib/xray-installer,
# /etc/xray, /usr/local/etc/xray, /etc/letsencrypt, /opt/chimera,
# /usr/local/bin/xray) для тестового процесса НЕВИДИМЫ — как в чистом
# контейнере. Без этого раннер на живой ноде и «чистые» GHA-раннеры
# расходятся (env-класс падений), а часть тестов пишет в реальный
# /etc/xray/config.json (инцидент 2026-10-27). Отключить: экспортировать
# CHIMERA_TEST_ISOLATE=0 до запуска.
#
# Режимы:
#   static <py312>   — compileall + PEP 701-сканер + full_test.py +
#                      test_py_compat (запускать под python3.12: сканеру
#                      нужен токенайзер 3.12, см. scripts/fstring_compat_scan.py)
#   gate   <py>      — compileall($PY) + unittest ГЕЙТ-сьютов из
#                      tests/ci_gate.txt (зелёных на 3.10 И 3.12 по baseline
#                      2026-10-27). Exit != 0 при любом провале — блокирующий.
#   full   <py>      — ВСЕ модули tests/, по-модульный таймаут, сводка;
#                      отчётный: exit 0 всегда (для nightly/dispatch-режима и
#                      ручного триажа новых красных).
#
# Таймаут на модуль: ловит зависшие тесты (урок песочницы: долгие процессы
# надо уметь прерывать; зависший сьют = красный флаг для триажа, а не вечный CI).
# ─────────────────────────────────────────────────────────────────────────────
set -u
MODE="${1:-}"
PY="${2:-python3}"
LIST="${3:-tests/ci_gate.txt}"   # gate: какой список гнать (дефолт — манифест;
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT"

# ─── env-изоляция прод-деревьев (см. tests/_env_isolation.py) ────────────────
# Включена всегда по умолчанию; sitecustomize-каталог — в PYTHONPATH, чтобы
# сабпроцессы тестов (inner-скрипты tg-бота и т.п.) получали ту же изоляцию.
export CHIMERA_TEST_ISOLATE="${CHIMERA_TEST_ISOLATE:-1}"
export PYTHONPATH="$ROOT:$ROOT/tests/_ci_site${PYTHONPATH:+:$PYTHONPATH}"

echo "env-изоляция: CHIMERA_TEST_ISOLATE=$CHIMERA_TEST_ISOLATE"

MODULE_TIMEOUT="${MODULE_TIMEOUT:-240}"

fail=0
mods_ok=0; mods_bad=0; mods_to=0
FAILDETAIL=/tmp/ci_fails.txt
: > "$FAILDETAIL"

header() { echo; echo "═══ $1 ═══"; }

_summary() {  # дописать блок в $GITHUB_STEP_SUMMARY (если задан)
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -s "$FAILDETAIL" ]; then
    {
      echo "### Падения модулей: fail=$mods_bad timeout=$mods_to ok=$mods_ok"
      echo '```'
      head -c 20000 "$FAILDETAIL"
      echo '```'
    } >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true
  fi
}

run_modules() {  # $1=список-файл, $2=блокирующий(0/1)
  local list="$1" blocking="$2"
  while IFS= read -r m; do
    case "$m" in ''|\#*) continue;; esac
    local out st ran
    out=$(timeout "$MODULE_TIMEOUT" "$PY" -m unittest "$m" -q 2>&1); st=$?
    ran=$(printf '%s' "$out" | grep -oE 'Ran [0-9]+' | tail -1 | grep -oE '[0-9]+' || true)
    if [ "$st" -eq 0 ]; then
      mods_ok=$((mods_ok+1))
    elif [ "$st" -eq 5 ]; then
      # unittest rc=5: «no tests ran» (pytest-native файлы под stdlib-гардом)
      mods_ok=$((mods_ok+1)); echo "SKIP(0 тестов): $m"
    elif [ "$st" -eq 124 ]; then
      mods_to=$((mods_to+1)); echo "TIMEOUT(${MODULE_TIMEOUT}s): $m (${ran:-0} тестов)"
      echo "::error::TIMEOUT ${MODULE_TIMEOUT}s: $m (${ran:-0} тестов)"
      [ "$blocking" = 1 ] && fail=1
    else
      mods_bad=$((mods_bad+1)); echo "FAIL: $m (${ran:-0} тестов, rc=$st)"
      echo "::error::FAIL $m (${ran:-0} тестов, rc=$st)"
      { echo "──── FAIL: $m (${ran:-0} тестов, rc=$st)"; printf '%s\n' "$out" | tail -25; echo; } >> "$FAILDETAIL"
      printf '%s\n' "$out" | grep -E "^(FAIL|ERROR):" | head -4
      [ "$blocking" = 1 ] && fail=1
    fi
  done < "$list"
}

case "$MODE" in
  static)
    header "[1/4] compileall (python3 = $($PY --version 2>&1))"
    "$PY" -m compileall -q chimera main.py full_test.py smoke_test_modules.py || fail=1
    header "[2/4] PEP 701 / pre-3.12 f-string сканер"
    "$PY" scripts/fstring_compat_scan.py || fail=1
    header "[3/4] full_test.py (статанализ: пути/права/дубликаты/гигиена)"
    "$PY" full_test.py >/tmp/ci_full_test.log 2>&1
    rc=$?; tail -3 /tmp/ci_full_test.log
    [ $rc -ne 0 ] && { echo "full_test.py rc=$rc"; fail=1; }
    header "[4/4] test_py_compat (гард совместимости + самопроверка сканера)"
    "$PY" -m unittest tests.test_py_compat -q || fail=1
    ;;
  gate)
    echo "GATE: python = $($PY --version 2>&1); список = $LIST"
    header "[1/2] compileall под гейтевым питоном"
    "$PY" -m compileall -q chimera main.py full_test.py smoke_test_modules.py || fail=1
    header "[2/2] unittest гейт-сьютов ($LIST)"
    run_modules "$LIST" 1
    echo
    echo "ГЕЙТ: ok=$mods_ok fail=$mods_bad timeout=$mods_to"
    _summary
    ;;
  full)
    echo "FULL REPORT: python = $($PY --version 2>&1) (не блокирующий)"
    ls tests/test_*.py | sed 's|^tests/|tests.|; s|\.py$||' > /tmp/ci_full_list.txt
    run_modules /tmp/ci_full_list.txt 0
    echo
    echo "FULL: ok=$mods_ok fail=$mods_bad timeout=$mods_to"
    echo "FULL-режим отчётный: красные модули выше — кандидаты в триаж (tests/ci_gate.txt их не содержит)."
    _summary
    ;;
  *)
    echo "usage: $0 {static <py312> | gate <py> | full <py>}" >&2
    exit 2
    ;;
esac

exit $fail
