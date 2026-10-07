#!/usr/bin/env python3
"""
tests/test_ssl_cert_guard.py
───────────────────────────────────────────────────────────────────────────────
: защита LE-сертификата + устойчивая DNS-проверка (инцидент 203.0.113.102).

Хронология инцидента (переустановка на новой ВМ, DNSCrypt без AGH):
  1. [WARN] «Домен panel.example НЕ резолвится в IP сервера» — ЛОЖНЫЙ:
     единственный dig шёл через 127.0.0.1 (DNSCrypt только что перезапущен
     установщиком, кэш холодный, DoH-upstream бутстрапится). nslookup через
     1.1.1.1 и даже через 127.0.0.1 (A-запись, из кэша) отвечали мгновенно.
  2. certbot certonly --force-renewal (безусловный флаг!) упал — лимит LE
     «5 дублей за 7 дней» исчерпан множественными переустановками.
  3. Фолбэк сгенерировал самоподписанный ПРЯМО В
     /etc/letsencrypt/live/<domain>/ — у certbot это СИМЛИНКИ в archive/ →
     ВАЛИДНЫЙ LE-сертификат (выпущен часом ранее, 90 дней) затёрт насмерть.
  4. nginx/xray остановлены atexit-обработчиком упавшей установки.

Контракт 
  1. domain_points_to_server — локальный (2 попытки) → getaddrinfo →
     внешние 1.1.1.1/8.8.8.8/77.88.8.8; WARN только если не резолвится НИГДЕ
  2. existing_cert_status — (exists, self_signed, days_left, expiry, issuer)
  3. certbot: --force-renewal ТОЛЬКО при явном «R»; свежая установка — без
     флага (идемпотентность: «not yet due» → exit 0 → cert сохранён)
  4. certbot упал + валидный НЕсамоподписанный cert на диске → REUSE,
     самоподпис НЕ генерируется
  5. generate_self_signed_cert: перед записью — tar-бэкап lineage в /root/
  6. U/R-бокс: показывает «Кем выдан», дефолт R для самоподписа
"""
from __future__ import annotations

import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test)."""
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


def _cp(args, rc=0, out="", err=""):
    return subprocess.CompletedProcess(args, rc, out, err)


# ─────────────────────────────────────────────────────────────────────────────
#  1. domain_points_to_server — много-путевая проверка DNS
# ─────────────────────────────────────────────────────────────────────────────
class TestDomainPointsToServer(unittest.TestCase):
    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.ssl_certbot as sc
        importlib.reload(sc)
        self.sc = sc
        self.dig_calls = []

    def _dig(self, answers):
        """answers: dict server -> list строк (или callable)."""
        core = self.core
        def fake_run(args, **kw):
            if args[0] == "dig":
                server = args[4].lstrip("@")
                self.dig_calls.append(server)
                ans = answers.get(server, [])
                if callable(ans):
                    ans = ans(server, len(self.dig_calls))
                return _cp(args, 0, "\n".join(ans))
            return _cp(args, 0, "")
        core._run = fake_run
        return fake_run

    def test_local_first_try_ok(self):
        self._dig({"127.0.0.1": ["203.0.113.102"]})
        ok, via = self.sc.domain_points_to_server("panel.example", "203.0.113.102")
        self.assertTrue(ok)
        self.assertEqual(via, "локальный резолвер")
        self.assertEqual(self.dig_calls, ["127.0.0.1"])  # sleep-ретрай не понадобился

    def test_local_flap_second_try_ok(self):
        # первый dig — пусто (DNSCrypt бутстрапится), второй — отвечает
        counter = {"n": 0}
        def local(server, n):
            counter["n"] += 1
            return ["203.0.113.102"] if counter["n"] >= 2 else []
        self._dig({"127.0.0.1": local})
        with patch("time.sleep"):
            ok, via = self.sc.domain_points_to_server("panel.example", "203.0.113.102")
        self.assertTrue(ok)
        self.assertEqual(via, "локальный резолвер")
        self.assertEqual(counter["n"], 2)

    def test_local_dead_external_ok_no_false_warn(self):
        # ЯДРО локальный резолвер мёртв, но 1.1.1.1 подтверждает
        # раньше это давало ЛОЖНЫЙ WARN «домен НЕ резолвится»
        self._dig({"1.1.1.1": ["203.0.113.102"]})
        with patch("time.sleep"), \
             patch("socket.getaddrinfo", side_effect=OSError("no dns")):
            ok, via = self.sc.domain_points_to_server("panel.example", "203.0.113.102")
        self.assertTrue(ok)
        self.assertEqual(via, "1.1.1.1")

    def test_getaddrinfo_fallback_when_dig_missing(self):
        # dig не установлен (rc=127, пустой stdout) — спасает getaddrinfo
        self._dig({})
        fake_gai = lambda host, port, fam: [(2, 1, 6, "", ("203.0.113.102", 0))]
        with patch("time.sleep"), patch("socket.getaddrinfo", fake_gai):
            ok, via = self.sc.domain_points_to_server("panel.example", "203.0.113.102")
        self.assertTrue(ok)
        self.assertEqual(via, "getaddrinfo")

    def test_all_dead_false(self):
        self._dig({})
        with patch("time.sleep"), \
             patch("socket.getaddrinfo", side_effect=OSError("no dns")):
            ok, via = self.sc.domain_points_to_server("panel.example", "203.0.113.102")
        self.assertFalse(ok)
        self.assertEqual(via, "")

    def test_resolves_but_wrong_ip_false(self):
        # домен резолвится, но в ДРУГОЙ IP (A-запись не переведена) — честный False
        self._dig({"127.0.0.1": ["<ip>"]})
        with patch("time.sleep"), \
             patch("socket.getaddrinfo", side_effect=OSError("no dns")):
            ok, via = self.sc.domain_points_to_server("panel.example", "203.0.113.102")
        self.assertFalse(ok)

    def test_cname_filtered(self):
        # dig +short может отдать CNAME-цепочку до IP — точки-хвосты фильтруются
        self._dig({"127.0.0.1": ["panel.example.", "203.0.113.102"]})
        ok, via = self.sc.domain_points_to_server("panel.example", "203.0.113.102")
        self.assertTrue(ok)


# ─────────────────────────────────────────────────────────────────────────────
#  2. existing_cert_status — разбор сертификата
# ─────────────────────────────────────────────────────────────────────────────
class TestExistingCertStatus(unittest.TestCase):
    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.ssl_certbot as sc
        importlib.reload(sc)
        self.sc = sc

    def _status(self, openssl_out, date_out=None, cert_exists=True):
        core = self.core
        def fake_run(args, **kw):
            if args[0] == "openssl":
                return _cp(args, 0, openssl_out)
            if args[0] == "date" and date_out is not None:
                return _cp(args, 0, date_out)
            return _cp(args, 0, "")
        core._run = fake_run
        p = self.sc.Path("/tmp/fake-cert.pem") if hasattr(self.sc, "Path") else Path("/tmp/fake-cert.pem")
        with patch.object(Path, "exists", return_value=cert_exists):
            return self.sc.existing_cert_status(p)

    def test_letsencrypt_valid(self):
        out = ("issuer=C = US, O = Let's Encrypt, CN = YE2\n"
               "subject=CN=panel.example\n"
               "notAfter=Nov 26 12:00:00 2026 GMT\n")
        # date вернёт now + 90 дней
        import time as _t
        fut = str(int(_t.time()) + 90 * 86400)
        ex, ss, days, exp, iss = self._status(out, date_out=fut)
        self.assertTrue(ex)
        self.assertFalse(ss)
        self.assertTrue(days >= 89)
        self.assertIn("Let's Encrypt", iss)

    def test_selfsigned_by_marker(self):
        out = ("issuer=CN = panel.example, O = SelfSigned, C = US\n"
               "subject=CN = panel.example, O = SelfSigned, C = US\n"
               "notAfter=Aug 28 12:00:00 2027 GMT\n")
        import time as _t
        fut = str(int(_t.time()) + 300 * 86400)
        ex, ss, days, exp, iss = self._status(out, date_out=fut)
        self.assertTrue(ex)
        self.assertTrue(ss)  # маркер O=SelfSigned

    def test_selfsigned_by_issuer_eq_subject(self):
        out = ("issuer=CN = panel.example\n"
               "subject=CN = panel.example\n"
               "notAfter=Aug 28 12:00:00 2027 GMT\n")
        import time as _t
        fut = str(int(_t.time()) + 300 * 86400)
        ex, ss, days, exp, iss = self._status(out, date_out=fut)
        self.assertTrue(ex)
        self.assertTrue(ss)  # issuer == subject

    def test_no_file(self):
        ex, ss, days, exp, iss = self._status("", cert_exists=False)
        self.assertFalse(ex)

    def test_openssl_fail_no_crash(self):
        # битый PEM → пустые поля, self_signed=False (не мешаем fallback)
        ex, ss, days, exp, iss = self._status("", date_out=None)
        self.assertTrue(ex)
        self.assertFalse(ss)
        self.assertEqual(days, 0)


# ─────────────────────────────────────────────────────────────────────────────
#  3. obtain_ssl_cert — флоу выпуска (мок ядра + фейковый Path)
# ─────────────────────────────────────────────────────────────────────────────
class _FakeFS:
    def __init__(self):
        self.files = {}   # str path -> dict(exists=bool)

    def set(self, path, exists=True):
        self.files[path] = {"exists": exists}


class _FakePath:
    fs: _FakeFS = None

    def __init__(self, p):
        self.p = str(p)

    def __truediv__(self, other):
        return _FakePath(f"{self.p}/{other}")

    def __str__(self):
        return self.p

    def __fspath__(self):
        return self.p

    def __repr__(self):
        return f"_FakePath({self.p!r})"

    def exists(self):
        return type(self).fs.files.get(self.p, {}).get("exists", False)

    def mkdir(self, *a, **kw):
        type(self).fs.set(self.p)

    def write_text(self, *a, **kw):
        type(self).fs.set(self.p)

    def glob(self, pat):
        return list(type(self).fs.files.get(self.p, {}).get("glob", []))

    def chmod(self, *a, **kw):
        pass


class TestObtainSslCertFlow(unittest.TestCase):
    """Ключевые контракты флоу: force-renewal, reuse, самоподпис."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.ssl_certbot as sc
        importlib.reload(sc)
        self.sc = sc
        self.fs = _FakeFS()
        _FakePath.fs = self.fs
        self.calls = {"certbot": [], "openssl_req": [], "tar": []}
        self.warns = []
        self.successes = []
        self.infos = []
        self.died = []
        core = self.core
        core.PARAM_DOMAIN = "panel.example"
        core.PARAM_EMAIL = "root@panel.example"
        core.PROTOCOL_MODE = "B"
        core.CYAN = core.NC = core.GREEN = core.RED = core.YELLOW = ""
        core.info = lambda m: self.infos.append(m)
        core.warn = lambda m: self.warns.append(m)
        core.success = lambda m: self.successes.append(m)

        def _die(msg):
            self.died.append(msg)
            raise SystemExit(1)
        core.die = _die
        core._box_top = lambda *a, **kw: None
        core._box_row = lambda *a, **kw: None
        core._box_sep = lambda *a, **kw: None
        core._box_item = lambda *a, **kw: None
        core._box_bottom = lambda *a, **kw: None
        core.get_server_ip = lambda v: "203.0.113.102"
        self.gen_selfsigned = lambda d: self.calls["openssl_req"].append(d)
        core.generate_self_signed_cert = self.gen_selfsigned
        # DNS-проверка мокается по-тестово (юнит — выше)
        self._dns_result = (True, "локальный резолвер")
        self.sc.domain_points_to_server = lambda d, ip: self._dns_result

    def _fake_run(self, certbot_rc=0, cert_status=None):
        """cert_status: результат existing_cert_status для live-пути."""
        core = self.core
        calls = self.calls
        fs = self.fs
        def fake_run(args, **kw):
            if args[0] == "certbot":
                calls["certbot"].append(list(args))
                return _cp(args, certbot_rc, "", "rate limited" if certbot_rc else "")
            if args[0] == "openssl" and "x509" in args:
                # existing_cert_status по live-пути — только если файл «есть»
                live = "/etc/letsencrypt/live/panel.example/fullchain.pem"
                if cert_status is not None and fs.files.get(live, {}).get("exists"):
                    return _cp(args, 0, cert_status)
                return _cp(args, 1, "", "no cert")
            if args[0] == "date":
                import time as _t
                return _cp(args, 0, str(int(_t.time()) + 90 * 86400))
            return _cp(args, 0, "")
        core._run = fake_run
        return fake_run

    LE_FULLCHAIN = "/etc/letsencrypt/live/panel.example/fullchain.pem"
    LE_PRIVKEY = "/etc/letsencrypt/live/panel.example/privkey.pem"

    def _openssl_le(self):
        return ("issuer=C = US, O = Let's Encrypt, CN = YE2\n"
                "subject=CN=panel.example\n"
                "notAfter=Nov 26 12:00:00 2026 GMT\n")

    def _openssl_selfsigned(self):
        return ("issuer=CN = panel.example, O = SelfSigned, C = US\n"
                "subject=CN = panel.example, O = SelfSigned, C = US\n"
                "notAfter=Aug 28 12:00:00 2027 GMT\n")

    # --- force-renewal ---

    def test_fresh_install_no_force_renewal(self):
        # свежая установка: cert-файлов нет → certbot БЕЗ --force-renewal
        self._fake_run(certbot_rc=0)
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", side_effect=EOFError):
            self.sc.obtain_ssl_cert()
        self.assertEqual(len(self.calls["certbot"]), 1)
        self.assertNotIn("--force-renewal", self.calls["certbot"][0])
        self.assertEqual(self.calls["openssl_req"], [])  # self-signed не нужен

    def test_user_reissue_adds_force_renewal(self):
        # пользователь явно выбрал R → certbot С --force-renewal
        self.fs.set(self.LE_FULLCHAIN)
        self.fs.set(self.LE_PRIVKEY)
        self._fake_run(certbot_rc=0, cert_status=self._openssl_le())
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", return_value="r"):
            self.sc.obtain_ssl_cert()
        self.assertEqual(len(self.calls["certbot"]), 1)
        self.assertIn("--force-renewal", self.calls["certbot"][0])

    def test_user_use_existing_skips_certbot(self):
        # пользователь выбрал U → certbot вообще не вызывается
        self.fs.set(self.LE_FULLCHAIN)
        self.fs.set(self.LE_PRIVKEY)
        self._fake_run(certbot_rc=0, cert_status=self._openssl_le())
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", return_value="u"):
            self.sc.obtain_ssl_cert()
        self.assertEqual(self.calls["certbot"], [])

    # --- защита валидного LE при провале certbot (ЯДРО) ---

    def test_certbot_fail_valid_le_reused_not_destroyed(self):
        # rate-limit + валидный LE на диске → REUSE, самоподпис НЕ генерится
        self.fs.set(self.LE_FULLCHAIN)
        self.fs.set(self.LE_PRIVKEY)
        self._fake_run(certbot_rc=1, cert_status=self._openssl_le())
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", return_value="r"):
            self.sc.obtain_ssl_cert()
        self.assertEqual(self.calls["openssl_req"], [])
        self.assertTrue(any("валидный сертификат" in s for s in self.successes),
                        f"successes={self.successes}")
        # честный warn про certbot есть, но про «генерируем самоподписанный» — нет
        self.assertTrue(any("certbot не смог" in w for w in self.warns))
        self.assertFalse(any("самоподписанный" in w for w in self.warns))

    def test_certbot_fail_selfsigned_regenerated(self):
        # rate-limit + на диске самоподпис → самоподпис генерируется (легитимно)
        self.fs.set(self.LE_FULLCHAIN)
        self.fs.set(self.LE_PRIVKEY)
        self._fake_run(certbot_rc=1, cert_status=self._openssl_selfsigned())
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", return_value="r"):
            self.sc.obtain_ssl_cert()
        self.assertEqual(self.calls["openssl_req"], ["panel.example"])

    def test_certbot_fail_no_cert_selfsigned_generated(self):
        # свежая установка, certbot упал, файлов нет → самоподпис (старое поведение)
        self._fake_run(certbot_rc=1)
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", side_effect=EOFError):
            self.sc.obtain_ssl_cert()
        self.assertEqual(self.calls["openssl_req"], ["panel.example"])

    # --- DNS-проверка в флоу ---

    def test_dns_dead_no_prompt_die(self):
        # домен не резолвится НИГДЕ → честный warn + отказ (die) при «n»
        self._fake_run(certbot_rc=0)
        self._dns_result = (False, "")
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", return_value="n"), \
             self.assertRaises(SystemExit):
            self.sc.obtain_ssl_cert()
        self.assertTrue(any("НЕ резолвится" in w for w in self.warns))
        self.assertEqual(self.died, ["DNS не настроен корректно. "
                                     "Исправьте A-запись и запустите заново."])
        self.assertEqual(self.calls["certbot"], [])  # умерли ДО certbot

    def test_dns_external_ok_no_warn(self):
        # локальный мёртв, внешний подтвердил → НИ warn, НИ промпта
        self._fake_run(certbot_rc=0)
        self._dns_result = (True, "1.1.1.1")
        inputs = []
        def rec_input(prompt=""):
            inputs.append(prompt)
            raise EOFError  # любой input = провал теста
        with patch.object(self.sc, "Path", _FakePath), \
             patch("builtins.input", side_effect=rec_input):
            self.sc.obtain_ssl_cert()
        self.assertEqual(inputs, [])          # промпта DNS не было
        self.assertEqual(self.died, [])
        self.assertFalse(any("НЕ резолвится" in w for w in self.warns))
        self.assertTrue(any("DNS подтверждён через 1.1.1.1" in i for i in self.infos))


# ─────────────────────────────────────────────────────────────────────────────
#  4. generate_self_signed_cert — бэкап lineage (resources.py)
# ─────────────────────────────────────────────────────────────────────────────
class TestSelfSignedBackup(unittest.TestCase):
    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.resources as res
        importlib.reload(res)
        self.res = res
        core = self.core
        core.info = lambda m: None
        core.success = lambda m: None

    def test_backup_before_overwrite(self):
        calls = []
        def fake_run(args, **kw):
            calls.append(list(args))
            return _cp(args, 0, "")
        self.core._run = fake_run

        class FakeResPath(_FakePath):
            pass
        FakeResPath.fs = _FakeFS()
        # archive существует и glob возвращает pem-файлы (lineage живой)
        arch = "/etc/letsencrypt/archive/panel.example"
        FakeResPath.fs.files[arch] = {
            "exists": True,
            "glob": [FakeResPath(f"{arch}/fullchain1.pem")],
        }

        with patch.object(self.res, "Path", FakeResPath):
            self.res.generate_self_signed_cert("panel.example")
        tar_calls = [c for c in calls if c[0] == "tar"]
        self.assertEqual(len(tar_calls), 1, f"tar не вызван: {calls}")
        self.assertIn("czf", tar_calls[0])
        self.assertTrue(any("le-cert-backup" in str(a) for a in tar_calls[0]))
        # openssl всё ещё пишет (функция не сломана)
        self.assertTrue(any(c[0] == "openssl" for c in calls))

    def test_no_archive_no_backup(self):
        calls = []
        def fake_run(args, **kw):
            calls.append(list(args))
            return _cp(args, 0, "")
        self.core._run = fake_run
        FakeResPath = _FakePath
        FakeResPath.fs = _FakeFS()   # пустая ФС — archive нет
        with patch.object(self.res, "Path", FakeResPath):
            self.res.generate_self_signed_cert("panel.example")
        self.assertFalse(any(c[0] == "tar" for c in calls))
        self.assertTrue(any(c[0] == "openssl" for c in calls))


# ─────────────────────────────────────────────────────────────────────────────
#  5. Статические пины (контракт не разъезжается при рефакторинге)
# ─────────────────────────────────────────────────────────────────────────────
class TestStaticPins(unittest.TestCase):
    def test_no_unconditional_force_renewal_in_certbot_call(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "ssl_certbot.py").read_text()
        # --force-renewal появляется только как append по условию user_reissue
        self.assertIn("if user_reissue:", src)
        self.assertIn('certbot_cmd.append("--force-renewal")', src)
        # нет безусловного флага в литерале команды
        self.assertNotIn('"--force-renewal",\n', src)

    def test_reuse_guard_present(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "ssl_certbot.py").read_text()
        self.assertIn("existing_cert_status(cert_path)", src)
        self.assertIn("самоподписанный НЕ генерируем", src)

    def test_backup_present_in_resources(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "resources.py").read_text()
        self.assertIn("le-cert-backup", src)
        self.assertIn("archive_path.glob", src)

    def test_multi_path_dns_present(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "ssl_certbot.py").read_text()
        for marker in ('"1.1.1.1"', '"8.8.8.8"', '"77.88.8.8"',
                       "getaddrinfo", "_dig_a_records"):
            self.assertIn(marker, src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
