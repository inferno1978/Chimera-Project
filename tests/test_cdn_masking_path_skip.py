#!/usr/bin/env python3
"""
tests/test_cdn_masking_path_skip.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для проверки skip-логики вопроса о path в _prompt_xhttp_options()
при активном профиле CDN masking.

ПОЧЕМУ ЭТО ОТДЕЛЬНЫЙ ФАЙЛ:
  _prompt_xhttp_options() — большая функция в _core.py, которая спрашивает
  ~10 параметров XHTTP. При XHTTP_CDN_MASKING=True вопрос о path должен
  пропускаться (path уже выставлен скрытым меню). Если этот skip сломается,
  пользователь получит перезапись path на случайный — и связка с Rewrite
  в Beeline CDN разорвётся.

  Тестируем именно этот инвариант: при CDN masking активном path НЕ меняется
  после вызова _prompt_xhttp_options().
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает _core.py через exec и регистрирует фейк в sys.modules.

    Паттерн из tests/test_xray_install.py (эталон): Path.mkdir/touch/chmod,
    os.chown, os.geteuid — патчатся, чтобы код _core.py не падал.
    """
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
    return fake_core


class TestCdnMaskingPathSkip(unittest.TestCase):
    """_prompt_xhttp_options skip-логика для path при CDN masking."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        # Устанавливаем флаг CDN masking и предзаполненный path
        # (как делает run_cdn_masking_install() в xhttp_cdn_masking.py).
        self._fake_core.XHTTP_CDN_MASKING = True
        self._fake_core.XHTTP_PATH = "/test-cdn-path.ts"
        self._fake_core.XHTTP_MODE = "streamup"

    def test_path_preserved_when_cdn_masking_active(self):
        """При XHTTP_CDN_MASKING=True path НЕ перезаписывается вопросом."""
        original_path = self._fake_core.XHTTP_PATH
        # Все вопросы input() отвечаем дефолтом '1'
        import builtins
        orig_input = builtins.input
        builtins.input = lambda prompt='': '1'
        try:
            self._fake_core._prompt_xhttp_options()
        finally:
            builtins.input = orig_input
        # Path должен остаться прежним
        self.assertEqual(self._fake_core.XHTTP_PATH, original_path,
            f"XHTTP_PATH must be preserved as {original_path!r} when "
            f"XHTTP_CDN_MASKING=True, but got {self._fake_core.XHTTP_PATH!r}")

    def test_path_not_overwritten_by_random_auto(self):
        """CDN masking skip не должен позволить auto-path перезаписать path.

        Если бы skip не работал, '1' (Авто: /<hex>) перезаписал бы path.
        Проверяем, что path не стал случайным hex-форматом.
        """
        import builtins
        import re
        orig_input = builtins.input
        builtins.input = lambda prompt='': '1'
        try:
            self._fake_core._prompt_xhttp_options()
        finally:
            builtins.input = orig_input
        # Если бы skip сломался, path был бы вида /abcd (4 hex символа).
        # Проверяем что это НЕ случайный hex — наш test path имеет формат
        # /test-cdn-path.ts (с точкой и расширением).
        self.assertNotRegex(self._fake_core.XHTTP_PATH,
            r'^/[0-9a-f]{4}$',
            f"XHTTP_PATH was overwritten by random auto-path: "
            f"{self._fake_core.XHTTP_PATH!r}")

    def test_path_skip_only_when_cdn_masking_active(self):
        """При XHTTP_CDN_MASKING=False вопрос о path ДОЛЖЕН задаваться.

        Это регрессионный тест: skip должен работать ТОЛЬКО при активном
        CDN masking, иначе простой XHTTP-режим сломается (path всегда
        будет оставаться пустым).

        Проверяем через инспекцию исходника _prompt_xhttp_options(): при
        XHTTP_CDN_MASKING=False код должен входить в ветку 'else' с
        _box_top("xHTTP path (путь endpoint)") и input().
        """
        import inspect
        src = inspect.getsource(self._fake_core._prompt_xhttp_options)
        # Должна быть ветка if globals().get("XHTTP_CDN_MASKING", False)
        self.assertIn('globals().get("XHTTP_CDN_MASKING", False)', src,
            "_prompt_xhttp_options must check XHTTP_CDN_MASKING flag")
        # Должен быть fallback с вопросом о path (else-ветка)
        self.assertIn('xHTTP path (путь endpoint)', src,
            "_prompt_xhttp_options must have path question in else-branch "
            "(for non-CDN-masking mode)")
        self.assertIn('input("  Выбор [1/2]: ")', src,
            "_prompt_xhttp_options must call input() for path choice "
            "in else-branch")

    def test_path_preserved_with_different_mode_choice(self):
        """Path сохраняется при CDN masking, mode выбирается отдельно.

        Проверяем через инспекцию: mode-вопрос идёт ДО path-skip-логики,
        значит mode можно выбрать любой, а path останется.
        """
        import inspect
        src = inspect.getsource(self._fake_core._prompt_xhttp_options)
        # mode-вопрос должен быть ДО path-skip-блока
        mode_pos = src.find('streamup   — однонаправленный')
        path_skip_pos = src.find('globals().get("XHTTP_CDN_MASKING", False)')
        self.assertGreater(mode_pos, 0, "Mode question not found in source")
        self.assertGreater(path_skip_pos, 0, "Path skip block not found")
        self.assertLess(mode_pos, path_skip_pos,
            "Mode question must come BEFORE path-skip block "
            "(so mode is choosable independently of path)")


if __name__ == "__main__":
    unittest.main()
