#!/usr/bin/env python3
"""
tests/test_tg_client_bot_inner_script.py
───────────────────────────────────────────────────────────────────────────────
End-to-end тесты для сгенерированного inner-скрипта клиентского бота
(vless_installer/modules/tg_client_bot.py::_generate_client_bot_script).

В отличие от test_tg_client_bot.py, который делает только ast.parse для
проверки синтаксиса, этот файл:

  1. Записывает сгенерированный inner-скрипт во временный файл.
  2. Подкладывает fake project_root с минимальным linkqr_lib-заглушкой
     (по структуре /opt/vless-ultimate/vless_installer/modules/linkqr_lib.py).
  3. Реально ИСПОЛНЯЕТ inner-скрипт через subprocess, импортируя его как модуль.
  4. Вызывает _call_linkqr_helper для каждого из 5 actions и проверяет,
     что subprocess-вызов РЕАЛЬНО находит linkqr_lib и возвращает не-None.

Это ловит регрессии, которые ast.parse не видит:
  • неправильный путь к linkqr_lib (баг с /opt/VLESS-Ultimate-Installer)
  • отсутствие канонического /opt/vless-ultimate в fallback-списке
  • сломанная сериализация аргументов через stdin/JSON
  • неверный PYTHONPATH в subprocess env

Покрывает также негативный сценарий: linkqr_lib нигде не найден —
пользователь получает явное сообщение об ошибке в handle_config,
а не молча пропущенный протокол.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый vless_installer._core (как в test_tg_bot.py)."""
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


# ── Заглушка linkqr_lib ──────────────────────────────────────────────────────
# Минимальный модуль с теми же публичными функциями, что и реальный
# linkqr_lib, но с предсказуемыми ответами для тестов. Подкладывается в
# fake project_root/vless_installer/modules/linkqr_lib.py.
# Используем textwrap.dedent для читаемости, без хитрого escaping.
_FAKE_LINKQR_LIB_SRC = textwrap.dedent('''\
    """Fake linkqr_lib for inner-script end-to-end tests."""
    import os, json
    _state = json.loads(os.environ.get("FAKE_LINKQR_STATE", "{}"))

    def build_awg_link_for_user(email):
        if _state.get("awg_email") == email:
            return "vpn://fake-awg-for-" + email
        return ""

    def build_mieru_link_for_user(email_or_name):
        uname = (email_or_name or "").split("@")[0]
        if _state.get("mieru_user") == uname:
            return "mierus://fake-mieru-for-" + uname
        return ""

    def build_naive_link_for_user(email_or_name):
        uname = (email_or_name or "").split("@")[0]
        if _state.get("naive_user") == uname:
            return "naive+https://fake-naive-for-" + uname
        return ""

    def build_singbox_links_for_user(uuid):
        if _state.get("sb_uuid") == uuid:
            return [("tuic", "tuic://fake-tuic-for-" + uuid)]
        return []

    def build_subscription_url_for_user(user):
        if user and user.get("uuid") and _state.get("sub_pepper"):
            return "https://example.com/sub/" + user["uuid"][:8]
        return None
''')


class TestInnerScriptExecutesLinkqrHelper(unittest.TestCase):
    """
    Реально исполняет inner-скрипт и вызывает _call_linkqr_helper для
    каждого из 5 actions с разными данными.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        # 1) Fake project_root, имитирующий структуру /opt/vless-ultimate/
        #    с рабочим linkqr_lib.py
        self._fake_project = self._tmpdir / "fake-vless-ultimate"
        self._linkqr_lib_path = (
            self._fake_project / "vless_installer" / "modules" / "linkqr_lib.py"
        )
        self._linkqr_lib_path.parent.mkdir(parents=True, exist_ok=True)
        # __init__.py для пакетов
        (self._fake_project / "vless_installer" / "__init__.py").write_text("")
        (self._fake_project / "vless_installer" / "modules" / "__init__.py").write_text("")
        self._linkqr_lib_path.write_text(_FAKE_LINKQR_LIB_SRC)
        # 2) Сгенерировать inner-скрипт с PROJECT_ROOT = self._fake_project
        #    Для этого патчим __file__ в tg_client_bot (нужно для parents[2])
        #    Проще: вручную заменить PROJECT_ROOT в сгенерированном скрипте.
        from vless_installer.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A", "rate_limit_seconds": 2}
        script = tg_client_bot._generate_client_bot_script(cfg)
        # Заменяем PROJECT_ROOT на наш fake-путь
        import re
        # PROJECT_ROOT = "/some/path" → наш fake-путь
        script = re.sub(
            r'^PROJECT_ROOT = .+$',
            f'PROJECT_ROOT = {json.dumps(str(self._fake_project))}',
            script,
            count=1,
            flags=re.MULTILINE,
        )
        # 3) Записываем inner-скрипт во временный файл
        self._inner_script = self._tmpdir / "inner_bot.py"
        self._inner_script.write_text(script)
        # 4) Также кладём state-файлы, которые inner-скрипт читает напрямую
        #    (usres.json, awg_standalone_state.json, и т.д. — для тестов
        #    _build_all_links). Используем /tmp путём через env-variable
        #    или через monkey-patch. Но inner-скрипт имеет hardcoded пути,
        #    поэтому просто подкладываем в реальные места через env.
        # Альтернатива: тестируем только _call_linkqr_helper напрямую.

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_inner_snippet(self, snippet: str, env_extra: dict = None) -> dict:
        """
        Запускает Python-subprocess: импортирует inner-скрипт как модуль,
        выполняет snippet (который должен записать JSON-результат в stdout),
        возвращает распарсенный JSON.
        """
        env = dict(os.environ)
        env["PYTHONPATH"] = str(self._fake_project) + os.pathsep + env.get("PYTHONPATH", "")
        if env_extra:
            env.update(env_extra)
        # ВАЖНО: cwd=fake_project — иначе Python видит '' в sys.path[0]
        # (текущая директория теста, где лежит РЕАЛЬНЫЙ vless_installer/)
        # и подгружает настоящий linkqr_lib вместо нашей заглушки.
        # В production-боте этого нет, т.к. systemd запускает с cwd=/
        # и PROJECT_ROOT ставится первым в PYTHONPATH.
        full_code = (
            f"import sys; sys.path.insert(0, {str(self._fake_project)!r});\n"
            f"import importlib.util;"
            f"spec = importlib.util.spec_from_file_location('inner_bot', {str(self._inner_script)!r});\n"
            f"bot = importlib.util.module_from_spec(spec);\n"
            f"spec.loader.exec_module(bot);\n"
            f"import json;\n"
            f"{snippet}\n"
        )
        r = subprocess.run(
            ["python3", "-c", full_code],
            capture_output=True, text=True, env=env, timeout=30,
            cwd=str(self._fake_project),
        )
        if r.returncode != 0:
            self.fail(f"Inner script execution failed:\nSTDERR:\n{r.stderr}\nSTDOUT:\n{r.stdout}")
        try:
            return json.loads(r.stdout) if r.stdout.strip() else None
        except json.JSONDecodeError:
            self.fail(f"Inner script returned non-JSON: {r.stdout!r}\nSTDERR: {r.stderr}")

    # ── Позитивные тесты: каждый action возвращает не-None при наличии данных ──

    def test_awg_link_returns_valid_url(self):
        """_call_linkqr_helper('awg_link', email=...) → 'vpn://...'."""
        snippet = (
            "r = bot._call_linkqr_helper('awg_link', email='alice@xray');\n"
            "import json; sys.stdout.write(json.dumps(r))\n"
        )
        env_extra = {"FAKE_LINKQR_STATE": json.dumps({"awg_email": "alice@xray"})}
        result = self._run_inner_snippet(snippet, env_extra)
        self.assertIsNotNone(result)
        self.assertEqual(result, "vpn://fake-awg-for-alice@xray")

    def test_mieru_link_returns_valid_url(self):
        snippet = (
            "r = bot._call_linkqr_helper('mieru_link', email='alice@xray');\n"
            "sys.stdout.write(json.dumps(r))\n"
        )
        env_extra = {"FAKE_LINKQR_STATE": json.dumps({"mieru_user": "alice"})}
        result = self._run_inner_snippet(snippet, env_extra)
        self.assertIsNotNone(result)
        self.assertEqual(result, "mierus://fake-mieru-for-alice")

    def test_naive_link_returns_valid_url(self):
        snippet = (
            "r = bot._call_linkqr_helper('naive_link', email='bob@xray');\n"
            "sys.stdout.write(json.dumps(r))\n"
        )
        env_extra = {"FAKE_LINKQR_STATE": json.dumps({"naive_user": "bob"})}
        result = self._run_inner_snippet(snippet, env_extra)
        self.assertIsNotNone(result)
        self.assertEqual(result, "naive+https://fake-naive-for-bob")

    def test_singbox_links_returns_list(self):
        snippet = (
            "r = bot._call_linkqr_helper('singbox_links', uuid='uuid-1234');\n"
            "sys.stdout.write(json.dumps(r))\n"
        )
        env_extra = {"FAKE_LINKQR_STATE": json.dumps({"sb_uuid": "uuid-1234"})}
        result = self._run_inner_snippet(snippet, env_extra)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "tuic")
        self.assertIn("tuic://", result[0][1])

    def test_subscription_url_returns_https(self):
        snippet = (
            "r = bot._call_linkqr_helper('subscription_url', user={'uuid': 'uuid-1234'});\n"
            "sys.stdout.write(json.dumps(r))\n"
        )
        env_extra = {"FAKE_LINKQR_STATE": json.dumps({"sub_pepper": "pepper"})}
        result = self._run_inner_snippet(snippet, env_extra)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("https://"))
        self.assertIn("uuid-1234"[:8], result)

    # ── Негативные сценарии ─────────────────────────────────────────────────────

    def test_returns_empty_string_when_no_data_for_awg(self):
        """Если данных нет — awg_link возвращает '' (не None, не исключение)."""
        snippet = (
            "r = bot._call_linkqr_helper('awg_link', email='nobody@xray');\n"
            "sys.stdout.write(json.dumps(r))\n"
        )
        env_extra = {"FAKE_LINKQR_STATE": json.dumps({})}  # без awg_email
        result = self._run_inner_snippet(snippet, env_extra)
        # build_awg_link_for_user возвращает "" при отсутствии — но JSON
        # сериализует пустую строку как "". Это нормально.
        self.assertEqual(result, "")

    def test_returns_empty_list_when_no_data_for_singbox(self):
        snippet = (
            "r = bot._call_linkqr_helper('singbox_links', uuid='unknown');\n"
            "sys.stdout.write(json.dumps(r))\n"
        )
        env_extra = {"FAKE_LINKQR_STATE": json.dumps({})}
        result = self._run_inner_snippet(snippet, env_extra)
        self.assertEqual(result, [])


class TestInnerScriptProjectRootResolvesAtGenerationTime(unittest.TestCase):
    """
    Проверяет, что PROJECT_ROOT вычисляется В МОМЕНТ генерации скрипта
    (через Path(__file__).resolve().parents[2]), а не угадывается с диска
    во время выполнения.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_project_root_literal_points_to_real_project(self):
        """PROJECT_ROOT в сгенерированном скрипте = корень проекта."""
        import re
        from vless_installer.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        m = re.search(r'^PROJECT_ROOT = "(.+?)"', script, re.MULTILINE)
        self.assertIsNotNone(m, "PROJECT_ROOT literal not found")
        project_root = m.group(1)
        # Должен указывать на каталог, содержащий vless_installer/modules/linkqr_lib.py
        linkqr = Path(project_root) / "vless_installer" / "modules" / "linkqr_lib.py"
        self.assertTrue(linkqr.exists(),
                        f"linkqr_lib.py not found at {linkqr} — PROJECT_ROOT is wrong")

    def test_project_root_literal_includes_main_py(self):
        """PROJECT_ROOT должен содержать main.py (это корень проекта)."""
        import re
        from vless_installer.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        m = re.search(r'^PROJECT_ROOT = "(.+?)"', script, re.MULTILINE)
        project_root = Path(m.group(1))
        self.assertTrue((project_root / "main.py").exists(),
                        f"main.py not found in PROJECT_ROOT {project_root}")

    def test_no_runtime_path_guessing_for_primary_lookup(self):
        """
        Проверяем, что PRIMARY lookup использует PROJECT_ROOT, а не угадывание.
        Старый код начинал с цикла for p in (...) — это и было источником бага.
        """
        from vless_installer.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        # Первая проверка в _call_linkqr_helper должна быть PROJECT_ROOT
        # (не цикл по кандидатурам).
        helper_start = script.find("def _call_linkqr_helper")
        helper_end = script.find("\n# ── Сборка всех ссылок пользователя")
        helper_body = script[helper_start:helper_end]
        # Должен использовать PROJECT_ROOT как первичный источник
        self.assertIn("if PROJECT_ROOT and", helper_body)
        # Fallback-список должен идти ПОСЛЕ проверки PROJECT_ROOT
        project_root_check_pos = helper_body.find("if PROJECT_ROOT and")
        fallback_pos = helper_body.find('"/opt/vless-ultimate"')
        self.assertGreater(fallback_pos, project_root_check_pos,
                           "Fallback list must come AFTER PROJECT_ROOT check")


class TestInnerScriptFallbackListOrder(unittest.TestCase):
    """
    Проверяет, что в fallback-списке канонический /opt/vless-ultimate идёт
    ПЕРВЫМ (а не legacy /opt/VLESS-Ultimate-Installer).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_canonical_path_first_in_fallback(self):
        from vless_installer.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        helper_start = script.find("def _call_linkqr_helper")
        helper_body = script[helper_start:]
        # /opt/vless-ultimate должен встретиться раньше /opt/VLESS-Ultimate-Installer
        canonical_pos = helper_body.find('"/opt/vless-ultimate"')
        legacy_pos = helper_body.find('"/opt/VLESS-Ultimate-Installer"')
        self.assertGreater(canonical_pos, 0, "/opt/vless-ultimate missing in fallback")
        self.assertGreater(legacy_pos, 0, "legacy path missing in fallback")
        self.assertLess(canonical_pos, legacy_pos,
                        "Canonical /opt/vless-ultimate must come BEFORE legacy path")

    def test_no_legacy_only_list(self):
        """Старый баг: только legacy-пути без /opt/vless-ultimate."""
        from vless_installer.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        # Не должно быть секции где ТОЛЬКО legacy-пути
        # (старый код начинался с ('/opt/VLESS-Ultimate-Installer', ...))
        # Проверим что любая тройка начинается с /opt/vless-ultimate
        helper_start = script.find("def _call_linkqr_helper")
        helper_body = script[helper_start:helper_start + 3000]
        # Находим первый for p in (
        for_match = helper_body.find("for p in (")
        self.assertGreater(for_match, 0, "fallback 'for p in (' loop missing")
        # Сразу после 'for p in (' должен идти canonical path
        after_for = helper_body[for_match + len("for p in ("):].lstrip()
        self.assertTrue(
            after_for.startswith('"/opt/vless-ultimate"'),
            f"First path in fallback list must be /opt/vless-ultimate, got: {after_for[:50]!r}"
        )


class TestInnerScriptNegativeScenarioErrorMessage(unittest.TestCase):
    """
    Негативный сценарий: linkqr_lib нигде не найден → _call_linkqr_helper
    возвращает None, _build_all_links возвращает (links, errors) с непустым
    errors (а не молча пропущенный протокол).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_call_linkqr_helper_returns_none_when_project_root_invalid(self):
        """
        Если PROJECT_ROOT указывает на несуществующий путь и fallback не
        сработал — _call_linkqr_helper возвращает None (не исключение).
        """
        from vless_installer.modules import tg_client_bot
        import re
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        # Подменяем PROJECT_ROOT на несуществующий путь
        script = re.sub(
            r'^PROJECT_ROOT = .+$',
            'PROJECT_ROOT = "/nonexistent/path"',
            script,
            count=1,
            flags=re.MULTILINE,
        )
        inner_script = self._tmpdir / "inner_bot.py"
        inner_script.write_text(script)

        # Запускаем в чистом окружении — без /opt/vless-ultimate на диске.
        # Используем tmpdir как cwd, чтобы sys.path[0]='' указывал туда
        # (где нет vless_installer/).
        env = dict(os.environ)
        env["PYTHONPATH"] = self._tmpdir.as_posix() + os.pathsep + env.get("PYTHONPATH", "")
        snippet = (
            "r = bot._call_linkqr_helper('awg_link', email='alice@xray')\n"
            "sys.stdout.write(json.dumps(r))\n"
        )
        full_code = (
            f"import sys; sys.path.insert(0, {str(self._tmpdir)!r});\n"
            f"import importlib.util;\n"
            f"spec = importlib.util.spec_from_file_location('inner_bot', {str(inner_script)!r});\n"
            f"bot = importlib.util.module_from_spec(spec);\n"
            f"spec.loader.exec_module(bot);\n"
            f"import json;\n"
            f"{snippet}\n"
        )
        r = subprocess.run(
            ["python3", "-c", full_code],
            capture_output=True, text=True, env=env, timeout=30,
            cwd=str(self._tmpdir),  # нет vless_installer/ здесь
        )
        if r.returncode != 0:
            self.fail(f"Inner script failed:\nSTDERR:\n{r.stderr}\nSTDOUT:\n{r.stdout}")
        # None в Python → "null" в JSON
        self.assertEqual(r.stdout.strip(), "null",
                         f"Expected None (null in JSON), got: {r.stdout!r}\nSTDERR: {r.stderr}")

    def test_build_all_links_returns_errors_when_helper_returns_none(self):
        """
        Если _call_linkqr_helper возвращает None для протокола, который
        должен быть активен (пир/пользователь есть в state) —
        _build_all_links добавляет читабельное сообщение в errors.
        """
        from vless_installer.modules import tg_client_bot
        import re
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        # Подменяем PROJECT_ROOT на несуществующий путь
        script = re.sub(
            r'^PROJECT_ROOT = .+$',
            'PROJECT_ROOT = "/nonexistent/path"',
            script,
            count=1,
            flags=re.MULTILINE,
        )
        inner_script = self._tmpdir / "inner_bot.py"
        inner_script.write_text(script)

        # Подкладываем awg_state с пиром для alice@xray во временный путь
        awg_state_file = self._tmpdir / "awg_standalone_state.json"
        awg_state_file.write_text(json.dumps({
            "installed": True,
            "peers": [{"name": "alice", "owner_email": "alice@xray",
                       "client_privkey": "x", "client_ip": "10.0.0.2"}],
        }))

        # Snippet: monkey-patch bot.Path так, чтобы
        # /var/lib/xray-installer/awg_standalone_state.json указывал на наш файл.
        env = dict(os.environ)
        env["PYTHONPATH"] = self._tmpdir.as_posix() + os.pathsep + env.get("PYTHONPATH", "")
        snippet = textwrap.dedent(f"""
            import json as _json
            # Save original Path
            OrigPath = bot.Path
            _awg_state_path = {str(awg_state_file)!r}
            class FakePath(OrigPath):
                def __new__(cls, *args, **kw):
                    p = str(args[0]) if args else ''
                    # Redirect awg_standalone_state.json to our fake file
                    if 'awg_standalone_state.json' in p:
                        return OrigPath(_awg_state_path)
                    return OrigPath.__new__(cls, *args, **kw)
            bot.Path = FakePath
            r = bot._build_all_links({{"uuid": "u1", "email": "alice@xray"}})
            sys.stdout.write(_json.dumps(r))
        """)
        full_code = (
            f"import sys; sys.path.insert(0, {str(self._tmpdir)!r});\n"
            f"import importlib.util;\n"
            f"spec = importlib.util.spec_from_file_location('inner_bot', {str(inner_script)!r});\n"
            f"bot = importlib.util.module_from_spec(spec);\n"
            f"spec.loader.exec_module(bot);\n"
            f"import json;\n"
            f"{snippet}\n"
        )
        r = subprocess.run(
            ["python3", "-c", full_code],
            capture_output=True, text=True, env=env, timeout=30,
            cwd=str(self._tmpdir),
        )
        if r.returncode != 0:
            self.fail(f"Inner script failed:\nSTDERR:\n{r.stderr}\nSTDOUT:\n{r.stdout}")
        result = json.loads(r.stdout)
        # _build_all_links возвращает (links_dict, errors_list)
        # JSON сериализует tuple как list
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        links, errors = result
        self.assertIsInstance(links, dict)
        self.assertIsInstance(errors, list)
        # Должна быть ошибка про AWG (т.к. _call_linkqr_helper вернул None
        # из-за несуществующего PROJECT_ROOT, а пир в state есть)
        awg_errors = [e for e in errors if "AWG" in e]
        self.assertGreater(len(awg_errors), 0,
                           "Expected AWG error in errors list, got: " + str(errors))


class TestInnerScriptRealLinkqrLibIntegration(unittest.TestCase):
    """
    Полный e2e: использует РЕАЛЬНЫЙ linkqr_lib.py из проекта (не заглушку).
    Подкладывает его в fake project_root и вызывает _call_linkqr_helper.
    Это ловит рассинхронизацию сигнатур между linkqr_lib и кодом в inner-скрипте.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        # Fake project_root с РЕАЛЬНЫМ linkqr_lib.py
        self._fake_project = self._tmpdir / "real-vless-ultimate"
        self._linkqr_lib_path = (
            self._fake_project / "vless_installer" / "modules" / "linkqr_lib.py"
        )
        self._linkqr_lib_path.parent.mkdir(parents=True, exist_ok=True)
        (self._fake_project / "vless_installer" / "__init__.py").write_text("")
        (self._fake_project / "vless_installer" / "modules" / "__init__.py").write_text("")
        # Копируем РЕАЛЬНЫЙ linkqr_lib.py
        real_linkqr = _PROJECT_ROOT / "vless_installer" / "modules" / "linkqr_lib.py"
        shutil.copy(real_linkqr, self._linkqr_lib_path)
        # Также нужен фейковый _core.py (linkqr_lib делает lazy import)
        fake_core = self._fake_project / "vless_installer" / "_core.py"
        # Минимальный stub — функции, которые linkqr_lib реально вызывает
        fake_core.write_text(textwrap.dedent('''
            import subprocess
            def _run(cmd, capture=False, quiet=False, **kw):
                kw = {}
                if capture:
                    kw.update(capture_output=True, text=True)
                return subprocess.run(cmd, **kw)
            PARAM_PUBLIC_IP = ""
            PUBLIC_IP = ""
            SERVER_IP = ""
            def log_to_file(*a, **kw): pass
        '''))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_real_linkqr_subscription_url_returns_https(self):
        """Реальный linkqr_lib.build_subscription_url_for_user через inner-скрипт."""
        from vless_installer.modules import tg_client_bot
        import re
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        script = re.sub(
            r'^PROJECT_ROOT = .+$',
            f'PROJECT_ROOT = {json.dumps(str(self._fake_project))}',
            script,
            count=1,
            flags=re.MULTILINE,
        )
        inner_script = self._tmpdir / "inner_bot.py"
        inner_script.write_text(script)

        # Подкладываем state.json и subscription.json в fake-пути
        state_file = self._tmpdir / "state.json"
        state_file.write_text(json.dumps({"domain": "vpn.example.com"}))
        sub_file = self._tmpdir / "sub.json"
        sub_file.write_text(json.dumps({"pepper": "my-pepper", "port": 8443}))

        # Snippet: monkey-patch linkqr_lib path-константы ВНУТРИ subprocess,
        # до вызова _call_linkqr_helper. Это нужно потому что subprocess
        # импортирует linkqr_lib заново с оригинальными path-константами.
        env = dict(os.environ)
        env["PYTHONPATH"] = str(self._fake_project) + os.pathsep + env.get("PYTHONPATH", "")
        snippet = textwrap.dedent(f"""
            import json as _json
            import pathlib
            # Патчим path-константы ВНУТРИ subprocess-кода (выполняемого
            # _call_linkqr_helper). Используем os.environ для передачи путей.
            import os as _os
            _state_path = {str(state_file)!r}
            _sub_path = {str(sub_file)!r}
            # Перехватываем subprocess.run внутри inner-бота, чтобы перед
            # вызовом патчить linkqr_lib в дочернем процессе.
            _orig_run = bot.subprocess.run
            def _patched_run(args, **kw):
                # Модифицируем code (args[2] после 'python3', '-c')
                # добавив патч path-констант в начало
                code = args[2]
                patch = (
                    "import os as _os; "
                    "from pathlib import Path as _P; "
                    "from vless_installer.modules import linkqr_lib as _ll; "
                    f"_ll._MAIN_STATE_FILE = _P(_os.environ['VLESS_TEST_STATE_FILE']); "
                    f"_ll._SUB_CONF_FILE = _P(_os.environ['VLESS_TEST_SUB_FILE']); "
                )
                args[2] = patch + code
                # Добавляем env vars для дочернего процесса
                child_env = kw.get('env', dict(_os.environ))
                child_env['VLESS_TEST_STATE_FILE'] = _state_path
                child_env['VLESS_TEST_SUB_FILE'] = _sub_path
                kw['env'] = child_env
                return _orig_run(args, **kw)
            bot.subprocess.run = _patched_run
            r = bot._call_linkqr_helper('subscription_url', user={{'uuid': 'test-uuid'}})
            sys.stdout.write(_json.dumps(r))
        """)
        full_code = (
            f"import sys; sys.path.insert(0, {str(self._fake_project)!r});\n"
            f"sys.path.insert(0, {str(self._tmpdir)!r});\n"
            f"import importlib.util;\n"
            f"spec = importlib.util.spec_from_file_location('inner_bot', {str(inner_script)!r});\n"
            f"bot = importlib.util.module_from_spec(spec);\n"
            f"spec.loader.exec_module(bot);\n"
            f"{snippet}\n"
        )
        r = subprocess.run(
            ["python3", "-c", full_code],
            capture_output=True, text=True, env=env, timeout=30,
            cwd=str(self._fake_project),
        )
        if r.returncode != 0:
            self.fail(f"Inner script failed:\nSTDERR:\n{r.stderr}\nSTDOUT:\n{r.stdout}")
        result = json.loads(r.stdout)
        self.assertIsNotNone(result, f"Expected subscription URL, got None. STDERR: {r.stderr}")
        self.assertTrue(result.startswith("https://"))
        self.assertIn("vpn.example.com:8443/sub/", result)

    def test_real_linkqr_vless_link_works(self):
        """
        Прямой вызов linkqr_lib.build_vless_link_for_user через subprocess
        (аналог того, что делает inner-скрипт). Двойная проверка: реальный
        linkqr_lib + корректная передача аргументов через stdin/JSON.
        """
        state_file = self._tmpdir / "state.json"
        state_file.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
        }))
        # Код аналогичен тому, что в inner-скрипте _call_linkqr_helper
        code = (
            "import json, sys; "
            "from vless_installer.modules import linkqr_lib; "
            f"linkqr_lib._MAIN_STATE_FILE = __import__('pathlib').Path({str(state_file)!r}); "
            "args = json.loads(sys.stdin.read()); "
            "r = linkqr_lib.build_vless_link_for_user(args.get('uuid','')); "
            "sys.stdout.write(json.dumps(r));"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(self._fake_project) + os.pathsep + env.get("PYTHONPATH", "")
        r = subprocess.run(
            ["python3", "-c", code],
            input=json.dumps({"uuid": "test-uuid"}),
            capture_output=True, text=True, env=env, timeout=15,
            cwd=str(self._fake_project),
        )
        if r.returncode != 0:
            self.fail(f"subprocess failed: STDERR:\n{r.stderr}")
        result = json.loads(r.stdout)
        self.assertTrue(result.startswith("vless://test-uuid@"))
        self.assertIn("vpn.example.com", result)


if __name__ == "__main__":
    unittest.main()
