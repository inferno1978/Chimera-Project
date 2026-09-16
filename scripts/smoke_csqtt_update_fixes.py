#!/usr/bin/env python3
"""smoke_csqtt_update_fixes.py — смоук починки трёх живых кейсов CSQTT.

Кейс юзера (сервер на актуальной ветке):
  установлен CSQTT v2.0.0 (rev неизвестна — legacy, ручной бинарь),
  апстрим уже 2.1.9. Симптомы:
    1. «Проверить обновление» → «обновите вручную один раз», а
       «Обновить сейчас» → «актуален (—)» и НИЧЕГО не делает.
    2. удаление+переустановка → «зависание при освобождении порта»
       (ufw-лок /run/ufw.lock — блокирующий fcntl; systemctl stop
       без потолка; вывод в DEVNULL — промпт не виден).
    3. Ctrl+C во время зависания → меню «Не установлено», а установка
       говорит «уже установлено» (две разные проверки состояния).

Проверки смоука:
  1. legacy + известный latest → update_target СКАЧИВАЕТ и пишет
     installed_rev (выход из legacy-режима пунктом 2, без force).
  2. Меню обновлений для legacy показывает РЕАЛЬНЫЙ latest в колонке
     «Последняя» (не «legacy-установка»).
  3. Агент автообновления legacy пропускает (доктрина «не
     пересобираем вслепую» сохранена).
  4. _run с таймаутом → rc=124, не исключение (не виснем никогда).
  5. _svc_stop_hard: stop → ещё жив → SIGKILL → stop → pkill.
  6. Удаление закрывает порты state + дефолты + легаси 40000/40500.
  7. Частичное состояние (бинарник есть, юнита нет): меню показывает
     «частично» + «Доустановить» — и НЕТ «не установлен» в статусе.
"""
from __future__ import annotations

import io
import re
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chimera.modules import upstream_updates as uu
from chimera.modules import csqtt as cs

_ANSI = re.compile(r"\033\[[0-9;]*m")
_plain = lambda s: _ANSI.sub("", s)

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    mark = "[OK]  " if cond else "[FAIL]"
    print(f"  {mark}  {name}" + (f"\n        {detail}" if detail and not cond else ""))
    PASS += 1 if cond else 0
    FAIL += 0 if cond else 1


def main() -> int:
    tmp = Path(tempfile.mkdtemp())

    # ─── перенаправляем upstream_updates state + бинарник ─────────────
    orig_uu = {
        "state": uu.STATE_FILE,
        "bin": uu.UPSTREAM_TARGETS["csqtt"]["binary"],
    }
    uu.STATE_FILE = tmp / "upstream-updates.json"
    uu.UPSTREAM_TARGETS["csqtt"]["binary"] = tmp / "csqtt-server"
    (tmp / "csqtt-server").write_bytes(b"\x7fELF-fake")

    # ─── перенаправляем пути csqtt-модуля ─────────────────────────────
    orig_cs = {
        "_BIN_PATH": cs._BIN_PATH,
        "_SERVICE_FILE": cs._SERVICE_FILE,
        "_MODULE_STATE": cs._MODULE_STATE,
        "_CFG_DIR": cs._CFG_DIR,
        "_CFG_FILE": cs._CFG_FILE,
        "_PASSWORDS_FILE": cs._PASSWORDS_FILE,
    }
    cs._BIN_PATH = tmp / "usr-local-bin-csqtt-server"
    cs._SERVICE_FILE = tmp / "csqtt.service"
    cs._MODULE_STATE = tmp / "csqtt.json"
    cs._CFG_DIR = tmp / "csqtt-etc"
    cs._CFG_FILE = tmp / "csqtt-etc" / "config.json"
    cs._PASSWORDS_FILE = tmp / "csqtt-etc" / "passwords.json"

    try:
        print("=== 1. legacy: «Обновить сейчас» скачивает и фиксирует rev ===")
        # state юзера: версия есть, ревизии нет
        uu.update_state("csqtt", installed_version="2.0.0")
        fetched = {}

        def fake_fetch(spec, **kw):
            fetched.update(kw)
            return True

        with patch.object(uu, "_github_api_json",
                          return_value={"sha": "a1b2c3d4e5f6" + "0123456789ab"}), \
             patch.object(uu, "get_installed_version", return_value="2.1.9"), \
             patch.object(uu, "_installed_version_cached", return_value="2.0.0"), \
             patch.object(uu, "_svc_active", return_value=False), \
             patch.object(uu, "_backup_binary", return_value=None), \
             patch.object(uu, "_build_info", return_value={}), \
             patch("chimera.modules.download_manager.fetch_package",
                   side_effect=fake_fetch), \
             patch.object(uu, "_spec_for", return_value=MagicMock()):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = uu.update_target("csqtt", interactive=False)
        out = _plain(buf.getvalue())
        check("update_target вернул True", ok)
        check("НЕ отвечает «актуален»", "актуален" not in out, out[:200])
        check("стрелка с версией юзера v2.0.0", "v2.0.0" in out, out[:200])
        st = uu.read_state()["csqtt"]
        check("installed_rev записан (legacy кончился)",
              st.get("installed_rev") == "a1b2c3d4e5f6", str(st))
        check("installed_version обновлён до 2.1.9",
              st.get("installed_version") == "2.1.9", str(st))

        print("=== 2. Меню обновлений: реальный latest в колонке «Последняя» ===")
        uu.update_state("csqtt", installed_rev=None, installed=None,
                        installed_version="2.0.0")
        with patch.object(uu, "_github_api_json",
                          return_value={"sha": "a1b2c3d4e5f6" + "0123456789ab"}), \
             patch.object(uu, "_installed_version_cached", return_value="2.0.0"):
            uu.check_target("csqtt", force=True)
        row = _plain(uu._fmt_target_row("csqtt"))
        check("«Установлено: v2.0.0 (rev неизвестен — legacy)»",
              "v2.0.0 (rev неизвестен — legacy)" in row, row)
        check("«Последняя: rev … — обновить вручную»",
              "обновить вручную" in row and "a1b2c3d4e5f6" in row, row)
        check("НЕ «Последняя: legacy-установка»",
              "Последняя: legacy-установка" not in row, row)
        uu.update_state("csqtt", latest="a1b2c3d4e5f6")
        line = _plain(uu.get_update_status_line("csqtt"))
        check("статус-строка шапки: «legacy → rev …»",
              "legacy" in line and "a1b2c3d4e5f6" in line, line)

        print("=== 3. Агент автообновления пропускает legacy ===")
        uu.update_state("csqtt", installed_rev=None, installed=None,
                        installed_version="2.0.0", auto=True)

        def boom(*a, **kw):
            raise AssertionError("агент не должен обновлять legacy")

        with patch.object(uu, "_github_api_json",
                          return_value={"sha": "a1b2c3d4e5f6" + "0123456789ab"}), \
             patch.object(uu, "_installed_version_cached", return_value="2.0.0"), \
             patch.object(uu, "update_target", side_effect=boom):
            rc = uu.run_agent()
        check("агент завершился без ошибок (skip, не fail)", rc == 0, str(rc))

        print("=== 4. _run с таймаутом → rc=124 (не виснем) ===")
        def hang(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

        with patch.object(subprocess, "run", side_effect=hang):
            r = cs._run(["ufw", "delete", "allow", "40000/udp"],
                        timeout=1, input="y\n")
        check("таймаут → псевдо-результат rc=124", r.returncode == 124)

        print("=== 5. _svc_stop_hard: SIGKILL-фолбэк ===")
        with patch.object(cs, "_run") as m:
            m.side_effect = [
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),
                subprocess.CompletedProcess(["systemctl"], 0, "active\n", ""),
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),
                subprocess.CompletedProcess(["pkill"], 0, "", ""),
            ]
            cs._svc_stop_hard("csqtt")
        cmds = [c.args[0] for c in m.call_args_list]
        check("stop с потолком ожидания",
              ["systemctl", "stop", "csqtt"] in cmds, str(cmds))
        check("SIGKILL после не-умирания",
              ["systemctl", "kill", "--signal=SIGKILL", "csqtt"] in cmds, str(cmds))
        check("pkill одиночных остатков",
              cmds[-1] == ["pkill", "-9", "-x", "csqtt-server"], str(cmds))

        print("=== 6. Удаление: порты state + дефолты + легаси ===")
        cs._BIN_PATH.write_bytes(b"bin")
        cs._SERVICE_FILE.write_text("[Unit]")
        cs.proto_save_state(cs._MODULE_STATE, {
            "installed": True, "data_port": 40000, "web_port": 40500,
        })
        closed_udp, closed_tcp = [], []
        with patch.object(cs, "_svc_stop_hard"), \
             patch.object(cs, "_csqtt_nginx_remove"), \
             patch.object(cs, "_run"), \
             patch.object(cs, "_ipt_close_udp",
                          side_effect=lambda p: closed_udp.append(p)), \
             patch.object(cs, "_ipt_close_tcp",
                          side_effect=lambda p: closed_tcp.append(p)), \
             patch.object(cs, "_ipt_remove_masquerade"), \
             patch.object(cs, "proto_ipt_persist"):
            ok = cs._full_uninstall(silent=True)
        check("удаление завершилось", ok is True)
        check("UDP: легаси 40000 + дефолт 46000",
              closed_udp == [40000, 46000], str(closed_udp))
        check("TCP: легаси 40500 + дефолт 46002",
              closed_tcp == [40500, 46002], str(closed_tcp))
        check("state-файл удалён", not cs._MODULE_STATE.exists())

        print("=== 7. Частичное состояние: меню и установка согласованы ===")
        # юнит удалён при прерванном удалении, бинарник выжил
        cs._BIN_PATH.write_bytes(b"bin")
        buf = io.StringIO()
        with patch.object(cs, "proto_ask", return_value="q"), \
             patch.object(cs.os, "system"), \
             patch.object(cs, "_run",
                          return_value=subprocess.CompletedProcess(
                              ["systemctl"], 3, "inactive\n", "")), \
             redirect_stdout(buf):
            cs.do_csqtt_menu()
        menu = _plain(buf.getvalue())
        check("статус «частично: нет systemd-сервиса»",
              "частично: нет systemd-сервиса" in menu, menu[:400])
        check("пункт «Доустановить»", "Доустановить" in menu, menu[:400])
        status_rows = [ln for ln in menu.splitlines() if "Статус:" in ln]
        check("статус НЕ «не установлен»",
              status_rows and "не установлен" not in status_rows[0],
              str(status_rows))
        # установщик при этом НЕ говорит «уже установлен»
        buf2 = io.StringIO()
        with patch.object(cs, "proto_ask", return_value=""), \
             patch.object(cs, "_build_csqtt_server", return_value=False), \
             patch.object(cs, "_pause"), \
             patch.object(cs.os, "system"), \
             redirect_stdout(buf2):
            cs._run_install_inner()
        inst = _plain(buf2.getvalue())
        check("установщик: «незавершённая установка», не «уже установлен»",
              "незавершённая установка" in inst and "уже установлен" not in inst,
              inst[:400])

        print()
        print("=" * 60)
        if FAIL:
            print(f"  СМОУК csqtt-update-fixes: {PASS}/{PASS + FAIL} — ЕСТЬ ПРОВАЛЫ")
            return 1
        print(f"  СМОУК csqtt-update-fixes: {PASS}/{PASS + FAIL} проверок ПРОЙДЕН")
        print("=" * 60)
        return 0
    finally:
        uu.STATE_FILE = orig_uu["state"]
        uu.UPSTREAM_TARGETS["csqtt"]["binary"] = orig_uu["bin"]
        for k, v in orig_cs.items():
            setattr(cs, k, v)


if __name__ == "__main__":
    sys.exit(main())
