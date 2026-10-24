#!/usr/bin/env python3
"""
tests/test_entry_mirrors_ui_smoke.py
───────────────────────────────────────────────────────────────────────────────
UI-smoke стилизации Entry Mirrors (продолжение кейса стилизации TUI, окт.2026).

Все интерактивные диалоги entry_mirrors — добавление mirror (вставка ссылки
или ручной ввод полей с подсказками), рамочный выбор mirror из списка
(удаление/вкл-выкл), y/N-подтверждение, проверка доступности, показ
mirror-ссылок по пользователям — рисуются рамками box_renderer и не падают
под пайпом (EOF на input = значение по умолчанию / отмена).

Канон: tests/test_awg_ui_smoke.py (фейковый chimera._core — эталонный
паттерн test_speed_test_cf_cap._setup_core_in_sysmodules).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (эталонный паттерн test_awg_ui_smoke)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core, g


def _feed(func, answers, *args, **kwargs):
    """Прогоняет func с очередью ответов на input (EOF = исчерпание).

    os.system (clear) замокан, stdout перехвачен. Возвращает (текст, результат).
    """
    it = iter(answers)

    def _fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    out = io.StringIO()
    with patch("builtins.input", _fake_input), \
         patch("os.system", lambda *a, **k: None), \
         redirect_stdout(out):
        res = func(*args, **kwargs)
    return out.getvalue(), res


_MIRROR = {
    "id": "a1", "label": "EU-2 Hetzner", "enabled": True,
    "host": "9.9.9.9", "port": 443, "sni": "mask.example.org",
    "pbk": "PUBKEYabcdef", "sid": "ab12", "fp": "chrome",
    "added_ts": 1, "last_check": {"ok": True, "ts": 1, "latency_ms": 51},
}

_VLESS_LINK = (
    "vless://uuid-1234@9.9.9.9:443?type=tcp&security=reality"
    "&pbk=PUBKEYabcdef&sid=ab12&sni=mask.example.org&fp=chrome#EU-2%20Hetzner"
)


class _EmUiBase(unittest.TestCase):
    """База: фейковый chimera._core + временный state-файл entry_mirrors."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import entry_mirrors
        self._em = entry_mirrors
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "entry_mirrors.json"
        self._state.write_text(json.dumps({"mirrors": []}))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self):
        return patch.object(self._em, "_STATE_FILE", self._state)

    def _menu(self, answers, probe=None, users=None):
        """Прогон меню с очередью ответов; возвращает захваченный текст."""
        ctx = [self._patch_state()]
        if probe is not None:
            ctx.append(patch.object(self._em, "_probe", side_effect=probe))
        if users is not None:
            ctx.append(patch.object(self._em, "_load_all_users",
                                    return_value=users))
        with ctx[0]:
            for c in ctx[1:]:
                c.start()
            try:
                text, _ = _feed(self._em.do_entry_mirrors_menu, answers)
            finally:
                for c in ctx[1:]:
                    c.stop()
        return text

    def _mirrors(self) -> list:
        return json.loads(self._state.read_text())["mirrors"]


# ── Главное меню: рамки + EOF-безопасность ───────────────────────────────────

class TestMenuFramed(_EmUiBase):

    def test_menu_framed_and_eof_safe(self):
        text = self._menu([])
        self.assertIn("╔", text)                    # рамки вообще
        self.assertIn("ENTRY MIRRORS", text)        # заголовок меню
        self.assertIn("[1]", text)                  # пункт добавления
        self.assertIn("[Q]", text)                  # выход
        self.assertEqual(self._mirrors(), [])       # state не тронут

    def test_menu_lists_mirrors(self):
        self._state.write_text(json.dumps({"mirrors": [_MIRROR]}))
        text = self._menu([])
        self.assertIn("EU-2 Hetzner", text)
        self.assertIn("9.9.9.9:443", text)
        self.assertIn("живой", text)


# ── Добавление mirror ────────────────────────────────────────────────────────

class TestAddMirror(_EmUiBase):

    def test_add_manual_full_flow_framed(self):
        answers = ["1", "", "Test M", "1.2.3.4", "443",
                   "s.example.com", "PUBKEY", "sid", "chrome"]
        text = self._menu(answers, probe=[(True, 25)])
        self.assertIn("ДОБАВЛЕНИЕ ENTRY MIRROR", text)       # рамка диалога
        self.assertIn("ПАРАМЕТРЫ MIRROR", text)              # хинт-бокс полей
        self.assertIn("ВРУЧНУЮ", text)
        self.assertIn("добавлен", text)                      # результат-бокс
        self.assertIn("Доступен по TCP, 25ms", text)
        mirrors = self._mirrors()
        self.assertEqual(len(mirrors), 1)
        self.assertEqual(mirrors[0]["host"], "1.2.3.4")
        self.assertEqual(mirrors[0]["port"], 443)
        self.assertEqual(mirrors[0]["sni"], "s.example.com")

    def test_add_manual_missing_name_framed_error(self):
        answers = ["1", "", ""]          # ссылка пусто, название пусто (EOF)
        text = self._menu(answers)
        self.assertIn("Название обязательно", text)
        self.assertIn("❌", text)
        self.assertEqual(self._mirrors(), [])                # ничего не saved

    def test_add_via_link_defaults_from_link(self):
        answers = ["1", _VLESS_LINK, "EU-2 Hetzner"]         # далее EOF = defaults
        text = self._menu(answers, probe=[(True, 51)])
        self.assertIn("ПАРАМЕТРЫ ИЗ ССЫЛКИ", text)           # хинт-бокс parsed
        self.assertIn("ENTER = КАК ЕСТЬ", text)
        mirrors = self._mirrors()
        self.assertEqual(len(mirrors), 1)
        self.assertEqual(mirrors[0]["host"], "9.9.9.9")
        self.assertEqual(mirrors[0]["port"], 443)
        self.assertEqual(mirrors[0]["sni"], "mask.example.org")
        self.assertEqual(mirrors[0]["pbk"], "PUBKEYabcdef")

    def test_add_unreachable_mirror_warns_in_frame(self):
        answers = ["1", "", "M", "1.2.3.4", "443",
                   "s.example.com", "PUBKEY", "", ""]
        text = self._menu(answers, probe=[(False, None)])
        self.assertIn("Недоступен по TCP", text)
        mirrors = self._mirrors()
        self.assertEqual(len(mirrors), 1)                    # добавлен, но с меткой
        self.assertFalse(mirrors[0]["last_check"]["ok"])

    def test_add_nonreality_link_falls_back_to_manual(self):
        answers = ["1", "https://example.com", ""]           # ссылка не REALITY
        text = self._menu(answers)
        self.assertIn("Не похоже на REALITY-ссылку", text)
        self.assertIn("Название обязательно", text)          # дальше EOF-отмена
        self.assertEqual(self._mirrors(), [])

    def test_add_port_validation_reasks(self):
        answers = ["1", "", "P", "h.io", "abc", "2053",
                   "s.x", "PK", "", ""]
        text = self._menu(answers, probe=[(True, 15)])
        self.assertIn("ПОРТ MIRROR", text)                   # рамка ошибки
        self.assertIn("Порт должен быть числом 1-65535", text)
        mirrors = self._mirrors()
        self.assertEqual(len(mirrors), 1)
        self.assertEqual(mirrors[0]["port"], 2053)           # вторая попытка


# ── Выбор mirror / удаление / вкл-выкл ───────────────────────────────────────

class TestPickRemoveToggle(_EmUiBase):

    def test_picker_framed_remove_eof_cancel_keeps_state(self):
        self._state.write_text(json.dumps({"mirrors": [_MIRROR]}))
        text = self._menu(["2", "1"])            # выбор 1, confirm EOF = N
        self.assertIn("ВЫБОР MIRROR", text)      # рамочный пикер
        self.assertIn("Отмена (Enter)", text)
        self.assertIn("УДАЛЕНИЕ MIRROR", text)   # карточка mirror
        self.assertIn("Mirror пропадёт из подписки", text)
        self.assertEqual(len(self._mirrors()), 1)  # не удалён

    def test_remove_confirm_y_deletes(self):
        self._state.write_text(json.dumps({"mirrors": [_MIRROR]}))
        text = self._menu(["2", "1", "y"])
        self.assertIn("удалён", text)
        self.assertEqual(self._mirrors(), [])

    def test_toggle_flips_enabled(self):
        self._state.write_text(json.dumps({"mirrors": [_MIRROR]}))
        text = self._menu(["3", "1"])
        self.assertIn("ВКЛ/ВЫКЛ MIRROR", text)
        self.assertIn("выключен", text)
        self.assertFalse(self._mirrors()[0]["enabled"])

    def test_pick_empty_list_framed_hint(self):
        text = self._menu(["2"])
        self.assertIn("ВЫБОР MIRROR", text)
        self.assertIn("Mirror-нод нет", text)

    def test_pick_invalid_number_framed_error(self):
        self._state.write_text(json.dumps({"mirrors": [_MIRROR]}))
        text = self._menu(["2", "99"])
        self.assertIn("Неверный номер", text)
        self.assertEqual(len(self._mirrors()), 1)


# ── Проверка доступности / ссылки ────────────────────────────────────────────

class TestProbeAndLinks(_EmUiBase):

    def test_probe_boxed_updates_state(self):
        m2 = dict(_MIRROR, id="b2", label="PL friend", host="8.8.8.8")
        self._state.write_text(json.dumps({"mirrors": [_MIRROR, m2]}))
        text = self._menu(["4"], probe=[(True, 42), (False, None)])
        self.assertIn("ПРОВЕРКА ДОСТУПНОСТИ MIRROR", text)
        self.assertIn("✅", text)
        self.assertIn("❌", text)
        self.assertIn("нет TCP", text)
        mirrors = self._mirrors()
        self.assertTrue(mirrors[0]["last_check"]["ok"])
        self.assertEqual(mirrors[0]["last_check"]["latency_ms"], 42)
        self.assertFalse(mirrors[1]["last_check"]["ok"])

    def test_links_boxed_per_user(self):
        self._state.write_text(json.dumps({"mirrors": [_MIRROR]}))
        users = [{"email": "user1@x.io", "uuid": "uuid-1234",
                  "disabled": False}]
        text = self._menu(["5"], users=users)
        self.assertIn("MIRROR-ССЫЛКИ ПО ПОЛЬЗОВАТЕЛЯМ", text)
        self.assertIn("user1@x.io", text)
        self.assertIn("vless://", text)          # ссылки на месте
        self.assertIn("ВНИМАНИЕ", text)          # канонный warning про копирование

    def test_links_no_mirrors_hint(self):
        users = [{"email": "u@x.io", "uuid": "uuid-1234", "disabled": False}]
        text = self._menu(["5"], users=users)
        self.assertIn("Ни у одного пользователя пока нет mirror-ссылок", text)

    def test_links_no_users_framed(self):
        text = self._menu(["5"], users=[])
        self.assertIn("Нет активных пользователей", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
