#!/usr/bin/env python3
"""v72.1: проверки scripts/enable-dns-ipv6.sh — структурные и функциональные.

Инцидент <node-2> (30.08): dns_alive был ОДНИМ системным getent без
settle-повторов — во время bootstrap AGH+dnscrypt после рестарта
(DoH/TLS handshake, prefetch сертификатов) это дало ложный
«AGH упал или DNS мёртв — ОТКАТ», а откат без reset-failed оставил AGH
в start-limit-hit («DNS мёртв даже после отката»).

Оба урока фиксируем тестами:
- структурно: reset-failed перед КАЖДЫМ рестартом, settle-повторы,
  лестница отката, .preIPv6.bak-бэкапы;
- функционально: python-блок UDP-пробы (вырезанный из скрипта как есть)
  против мок-DNS на ephemeral-порту — живой responder → exit 0,
  мёртвый порт → exit ≠ 0.
"""
import pathlib
import socket
import subprocess
import sys
import threading
import unittest

SH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "enable-dns-ipv6.sh"


def _probe_block() -> str:
    """Python-блок UDP-пробы из скрипта (байт-в-байт как в проде)."""
    text = SH.read_text(encoding="utf-8")
    start = text.index("import socket, sys")
    end = text.index("PYEOF", start)
    return text[start:end]


class TestScriptStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SH.read_text(encoding="utf-8")

    def test_bash_syntax(self):
        r = subprocess.run(["bash", "-n", str(SH)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_reset_failed_before_every_restart(self):
        """v57-паттерн: reset-failed перед КАЖДЫМ рестартом (start-limit).

        Двойной рестарт AGH за минуту без reset-failed ловит
        start-limit-hit — служба остаётся failed навсегда.
        """
        lines = self.text.splitlines()
        in_fn, fn_lines, outside = False, [], []
        for line in lines:
            if line.startswith("restart_svc()"):
                in_fn = True
                continue
            if in_fn and line.strip() == "}":
                in_fn = False
                continue
            (fn_lines if in_fn else outside).append(line)
        # restart_svc существует и внутри него reset-failed перед restart
        self.assertTrue(fn_lines, "restart_svc() не найден")
        self.assertTrue(any("reset-failed" in l for l in fn_lines))
        self.assertTrue(any("systemctl restart" in l for l in fn_lines))
        # вне restart_svc голых рестартов нет — все идут через него
        bare = [l for l in outside if "systemctl restart" in l]
        self.assertEqual(bare, [], f"рестарты мимо restart_svc: {bare}")

    def test_probe_direct_not_system_getent(self):
        """Проба — прямой запрос к AGH, не системный getent.

        Системный путь зависит от resolv.conf и даёт ложный «мёртв»
        (урок v60 из aghome_setup._system_dns_ok).
        """
        self.assertNotIn("getent hosts", self.text)
        self.assertIn("probe_dns_at", self.text)
        self.assertIn('probe_dns_at "127.0.0.1"', self.text)

    def test_settle_retries_in_dns_alive(self):
        """settle-повторы: bootstrap AGH/dnscrypt после рестарта не мгновенный."""
        self.assertRegex(self.text, r"for \(\(i=1; i<=4; i\+\+\)\)")
        self.assertIn("sleep 2", self.text)

    def test_rollback_ladder_present(self):
        """Лестница отката: AGH → dnscrypt → полный откат + журналы в выводе."""
        self.assertIn("Полный откат", self.text)
        self.assertGreaterEqual(self.text.count("journalctl -u"), 3)

    def test_backups_preIPv6(self):
        self.assertIn(".preIPv6.bak", self.text)
        self.assertIn("latest_bak", self.text)

    def test_listener_settle_step2(self):
        """Шаг 2: settle-ожидание слушателя [::1] (не мгновенная проверка ss)."""
        self.assertIn("DC_UP", self.text)


class TestProbeBlockFunctional(unittest.TestCase):
    """UDP-проба из скрипта против живого мок-DNS (ephemeral-порт)."""

    @classmethod
    def setUpClass(cls):
        cls.block = _probe_block()
        cls.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.sock.bind(("127.0.0.1", 0))
        cls.sock.settimeout(5)
        cls.port = cls.sock.getsockname()[1]
        threading.Thread(target=cls._responder, daemon=True).start()

    @classmethod
    def _responder(cls):
        while True:
            try:
                data, addr = cls.sock.recvfrom(512)
            except OSError:
                return
            # echo заголовка запроса = валидный DNS-ответ (длина ≥ 12)
            cls.sock.sendto(data[:12] + b"\x00" * 4, addr)

    def _run_block(self, srv: str, port) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-", srv, str(port)],
            input=self.block, capture_output=True, text=True, timeout=15)

    def test_probe_answer_means_alive(self):
        r = self._run_block("127.0.0.1", self.port)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_probe_dead_port_means_dead(self):
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))
        dport = dead.getsockname()[1]
        dead.close()
        r = self._run_block("127.0.0.1", dport)
        self.assertNotEqual(r.returncode, 0)

    def test_probe_ipv6_server_address(self):
        """Форма [v6]/голый v6: сокет выбирается AF_INET6 для ':' в адресе."""
        self.assertIn("AF_INET6", self.block)
        self.assertIn('if ":" in srv', self.block)


if __name__ == "__main__":
    unittest.main()
