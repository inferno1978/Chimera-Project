#!/usr/bin/env python3
"""
tests/test_domain_external_check.py
───────────────────────────────────────────────────────────────────────────────
Регрессия живого кейса (окт. 2026, прод-юзер, скрин WARN):

Шаг «Внешняя проверка домена» (меню [9] и шаг 10/14 мастера полной
диагностики) на домене chimera-c.example.com:9443 показывал:

    [INFO]  [3/4] HTTPS TLS-рукопожатие ...
    [WARN]  HTTPS недоступен (returncode=7)
    [INFO]  [4/4] TCP доступность порта 9443 (через curl --connect-to) ...
    [OK]    Порт 9443 доступен снаружи

Шаг [3/4] стучал curl'ом на ДЕФОЛТНЫЙ 443 (https://{domain}/), а
VLESS/REALITY-сервис слушает на server_port=9443 (443 закрыт) → rc=7
«HTTPS недоступен» при живом сервисе — шаг противоречил сам себе.

Ожидаемое поведение после фикса:
  1. [3/4] идёт на server_port тем же --connect-to, что и [4/4];
  2. rc=35/60 (TLS хендшейк состоялся: SSL-ошибка / сертификат не
     проходит CA — норм для REALITY-камуфляжа/self-signed) → OK-строка
     «TLS на порту N отвечает», а НЕ WARN «недоступен»;
  3. rc=7 — по-прежнему честный WARN (порт реально не принимает);
  4. label [2/4] больше не обещает «HTTP 200» при фактическом 301.
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
from subprocess import CompletedProcess
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейк chimera._core в sys.modules (эталонный паттерн test_chain_relay)."""
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


_DOMAIN = "chimera-c.example.com"
_IP     = "203.0.113.102"
_PORT   = 9443


class _FakeRun:
    """Диспетчер curl/dig вызовов do_check_domain_external по содержимому argv.

    Шаги различаются по ключу -w:
      dig                                     → DNS (шаг 1)
      %{http_code} без https                  → HTTP/.well-known (шаг 2)
      '%{http_code} %{ssl_verify_result}'     → TLS-проба (шаг 3)
      %{errormsg}                             → TCP порта (шаг 4)
    """

    def __init__(self, tls_rc: int, tls_stdout: str = "",
                 tcp_rc: int = 60, http_code: str = "301"):
        self.calls: list[list[str]] = []
        self._tls_rc, self._tls_out = tls_rc, tls_stdout
        self._tcp_rc = tcp_rc
        self._http_code = http_code

    def __call__(self, args, **kw):
        self.calls.append(list(args))
        if args[0] == "dig":
            return CompletedProcess(args, 0, stdout=_IP + "\n", stderr="")
        if "-w" in args:
            w = args[args.index("-w") + 1]
            if w == "%{http_code}":
                return CompletedProcess(args, 0, stdout=self._http_code, stderr="")
            if w == "%{http_code} %{ssl_verify_result}":
                return CompletedProcess(args, self._tls_rc,
                                        stdout=self._tls_out, stderr="")
            if w == "%{errormsg}":
                return CompletedProcess(args, self._tcp_rc,
                                        stdout="", stderr="connect refused")
        return CompletedProcess(args, 1, stdout="", stderr="unexpected")

    def argv_of(self, marker: str) -> list[str]:
        """argv вызова, содержащего подстроку marker (последний из匹配)."""
        for c in reversed(self.calls):
            joined = " ".join(c)
            if marker in joined:
                return c
        return []


class TestDomainExternalHttpsPort(unittest.TestCase):
    """[3/4] HTTPS TLS-проба: сервисный порт + честная классификация rc."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._state_fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False)
        self._state_fh.write(json.dumps(
            {"domain": _DOMAIN, "server_port": _PORT}))
        self._state_fh.close()
        self._state_path = Path(self._state_fh.name)

    def tearDown(self):
        try:
            self._state_path.unlink(missing_ok=True)
        except Exception:
            pass

    def _run_check(self, fake_run):
        from chimera.modules.standalone_screens import do_check_domain_external
        out = io.StringIO()
        with redirect_stdout(out), \
             patch.object(self._fake_core, "STATE_FILE", self._state_path), \
             patch.object(self._fake_core, "_run", fake_run), \
             patch.object(self._fake_core, "log_to_file",
                          lambda *a, **kw: None):
            do_check_domain_external()
        return out.getvalue()

    def _tls_argv(self, fake_run) -> list[str]:
        return fake_run.argv_of("%{ssl_verify_result}")

    # ── 1. Проба идёт на server_port, а не на дефолтный 443 ──────────────
    def test_https_probe_targets_server_port(self):
        fr = _FakeRun(tls_rc=0, tls_stdout="200 0")
        out = self._run_check(fr)
        argv = self._tls_argv(fr)
        self.assertIn(f"https://{_DOMAIN}:{_PORT}/", argv,
                      "TLS-проба должна идти на server_port (9443)")
        self.assertIn("--connect-to", argv)
        ct = argv[argv.index("--connect-to") + 1]
        self.assertEqual(ct, f"{_DOMAIN}:{_PORT}:{_IP}:{_PORT}",
                         "connect-to: домен:порт → IP из шага 1:тот же порт")
        self.assertIn(f"(порт {_PORT})", out)

    def test_https_probe_not_default_443(self):
        fr = _FakeRun(tls_rc=0, tls_stdout="200 0")
        self._run_check(fr)
        argv = self._tls_argv(fr)
        self.assertNotIn(f"https://{_DOMAIN}/", argv,
                         "старая форма без порта (дефолт 443) запрещена")

    # ── 2. rc=7 — честный WARN (порт реально не отвечает) ────────────────
    def test_rc7_genuine_unreachable_warns(self):
        fr = _FakeRun(tls_rc=7)
        out = self._run_check(fr)
        self.assertIn(f"HTTPS недоступен на порту {_PORT} (returncode=7)", out)

    # ── 3. rc=60 (камуфляж/self-signed) — TLS отвечает, НЕ «недоступен» ──
    def test_rc60_camouflage_cert_is_ok_not_warn(self):
        """Живой кейс со скрина: REALITY на 9443, dest-сертификат/self-signed
        не проходит CA-проверку (rc=60) — порт отвечает TLS, WARN лгал."""
        fr = _FakeRun(tls_rc=60)
        out = self._run_check(fr)
        self.assertIn(f"TLS на порту {_PORT} отвечает", out)
        self.assertIn("REALITY-камуфляжа/self-signed", out)
        self.assertNotIn("HTTPS недоступен", out)

    def test_rc35_ssl_after_handshake_is_ok_not_warn(self):
        fr = _FakeRun(tls_rc=35)
        out = self._run_check(fr)
        self.assertIn(f"TLS на порту {_PORT} отвечает", out)
        # box-wrap может перенести строку посреди фразы — проверяем
        # оба фрагмента независимо
        self.assertIn("SSL-ошибка", out)
        self.assertIn("returncode=35", out)
        self.assertNotIn("HTTPS недоступен", out)

    # ── 4. rc=0 — прежняя строка с кодом и verify ────────────────────────
    def test_rc0_shows_code_and_verify(self):
        fr = _FakeRun(tls_rc=0, tls_stdout="200 0")
        out = self._run_check(fr)
        self.assertIn("HTTPS код: 200", out)
        self.assertIn("TLS verify: OK", out)

    def test_rc0_verify_fail_shows_error(self):
        fr = _FakeRun(tls_rc=0, tls_stdout="000 20")
        out = self._run_check(fr)
        self.assertIn("TLS verify: ОШИБКА", out)
        self.assertNotIn("HTTPS недоступен", out)

    # ── 5. Label [2/4] без хардкода «200» (на скрине: label 200, код 301) ─
    def test_http_step_label_has_no_hardcoded_200(self):
        fr = _FakeRun(tls_rc=0, tls_stdout="200 0", http_code="301")
        out = self._run_check(fr)
        self.assertIn("[2/4] HTTP на /.well-known/ (порт 80)", out)
        self.assertIn("HTTP доступен (код 301)", out)
        self.assertNotIn("HTTP 200 на /.well-known/", out)

    # ── 6. Служебный dig по-прежнему через 8.8.8.8, порт из state ────────
    def test_state_domain_and_port_used(self):
        fr = _FakeRun(tls_rc=0, tls_stdout="200 0")
        out = self._run_check(fr)
        # «Домен:» и значение разделены ANSI-цветом — проверяем порознь
        self.assertIn("Домен:", out)
        self.assertIn(_DOMAIN, out)
        self.assertIn("Порт:", out)
        self.assertIn(str(_PORT), out)
        dig = fr.argv_of("dig")
        self.assertIn("@8.8.8.8", dig)   # аргумент dig — «@8.8.8.8» с @


if __name__ == "__main__":
    unittest.main(verbosity=2)
