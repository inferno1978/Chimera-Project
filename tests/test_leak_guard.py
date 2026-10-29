"""Unit-тесты scripts/leak_guard.py — гард гигиены репозитория.

Зачистка 2026-10 (заказ владельца): старые файлы содержали реальные IP
нод/клиентов; leak_guard их не ловил, потому что проверял только диф.
После зачистки полный аудит дерева включён в CI static-стадию, а эти
тесты фиксируют решающие блоки сканера:

  • IPv4: TEST-NET и allowlist проходят, произвольный публичный — LEAK;
    атрибуция фикстур ХИРУРГИЧЕСКАЯ (/32 на базовый адрес): сосед из
    того же диапазона провайдера — по-прежнему LEAK;
  • IPv6 (новое): doc-диапазоны/ULA/link-local — чисто; глобальный v6
    вне allowlist — LEAK (регрессия 2026-10: реальные клиентские/нодовые
    v6 из логов раньше не ловились вообще — сканер знал только IPv4;
    зачищенные семьи в allowlist НЕ внесены — тест проверяет синтетикой,
    чтобы сами токены не возвращались в репо);
  • v4-mapped, MAC, время, UUID — не дают v6-ложных срабатываний;
  • токены: ghp_/glpat-/PRIVATE KEY/TG-бот;
  • ssh-pass-inline: код вида `password = users_by_login.get(...)`
    (wpp_portal) — не LEAK, реальный инлайн-пароль — LEAK.

Полный аудит tracked-файлов здесь НЕ гоняется — он выполняется в CI
static отдельной стадией (scripts/ci_suite.sh, [5/5]).
"""
import importlib.util
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "leak_guard_under_test", _ROOT / "scripts" / "leak_guard.py")
lg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lg)


def _scan(text: str):
    """scan_text → (leaks, warns) с нейтральным origin."""
    leaks, warns = [], []
    lg.scan_text(text, "unit", leaks, warns)
    return leaks, warns


def _ip_leaks(text: str):
    return [what for _, what in _scan(text)[0] if "IP" in what]


class TestIpV4Allowlist(unittest.TestCase):
    """TEST-NET/приватные/DNS — чисто; произвольный публичный — LEAK."""

    def test_testnet_clean(self):
        for ip in ("192.0.2.20", "198.51.100.49", "203.0.113.238"):
            self.assertEqual(_ip_leaks(f"endpoint {ip}:443"), [])

    def test_private_clean(self):
        for ip in ("10.1.2.3", "172.16.91.3", "192.168.1.1",
                   "100.64.0.1", "127.0.0.1"):
            self.assertEqual(_ip_leaks(f"from {ip}:52359"), [])

    def test_public_dns_clean(self):
        for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            self.assertEqual(_ip_leaks(f"dns {ip}"), [])

    def test_arbitrary_public_leak(self):
        self.assertEqual(_ip_leaks("node 198.51.101.7"),  # leak-guard-sample
                         ["публичный IP 198.51.101.7"])  # leak-guard-sample

    def test_removed_fixture_mask_no_longer_exists(self):
        """Регрессия зачистки: IP_EXTRA_ALLOW — ТОЛЬКО строки-версии ПО
        (замаскированная под версию строка-клиентский-IP удалена);
        произвольный «версия-подобный» публичный адрес — LEAK."""
        self.assertEqual(lg.IP_EXTRA_ALLOW,
                         {"5.11.28.3", "5.0.1.5", "5.5.5.5",
                          "5.5.11.1", "5.5.11.2", "5.5.11.3"})
        self.assertIn("публичный IP 5.144.99.99", _ip_leaks("wl 5.144.99.99"))  # leak-guard-sample

    def test_version_strings_still_allowed(self):
        for tok in ("5.11.28.3", "5.0.1.5", "5.5.5.5",
                    "5.5.11.1", "5.5.11.2", "5.5.11.3"):
            self.assertEqual(_ip_leaks(f"v{tok}"), [])


class TestSurgicalAttribution(unittest.TestCase):
    """Атрибуция фикстур — точечные /32, не диапазоны."""

    def test_ipmask_example_bases_allowed(self):
        # канонические примеры масок ipmask (базовые адреса)
        for ip in ("176.9.0.0", "176.9.40.0", "176.9.5.5", "176.9.7.7",
                   "152.65.0.0", "189.122.0.0", "46.17.0.0", "176.0.0.0"):
            self.assertEqual(_ip_leaks(f"{ip}/16"), [],
                             f"{ip} должен быть атрибутирован")

    def test_ipmask_neighbor_still_leaks(self):
        # соседний адрес того же провайдера — НЕ база примера → LEAK
        self.assertIn("публичный IP 176.9.41.7", _ip_leaks("176.9.41.7"))  # leak-guard-sample
        self.assertIn("публичный IP 152.65.1.1", _ip_leaks("152.65.1.1"))  # leak-guard-sample

    def test_grchc_subnets_allowed(self):
        for ip in ("45.132.21.0", "45.157.4.0", "62.76.12.0", "194.32.72.0",
                   "5.253.100.0", "80.66.66.0", "185.242.246.0"):
            self.assertEqual(_ip_leaks(f"add xray_manual_ban {ip}/24"), [])

    def test_grchc_host_inside_leaks(self):
        # конкретный хост внутри ГРЧЦ-подсети — не базовый адрес → LEAK
        self.assertIn("публичный IP 45.132.21.7", _ip_leaks("45.132.21.7"))  # leak-guard-sample

    def test_gov_ru_case_study_allowed(self):
        self.assertEqual(_ip_leaks("www.gov.ru (95.173.128.90)"), [])


class TestIpV6Scanner(unittest.TestCase):
    """Новый IPv6-сканер: глобальный v6 вне allowlist — LEAK."""

    def test_doc_and_local_clean(self):
        for tok in ("2001:db8::1", "2001:db8:5a7:6214::/64", "3fff::1",
                    "2001:db8:1460:443::2", "fd66:66:91::4", "fe80::1",
                    "::1", "fc00::1", "ff02::1"):
            self.assertEqual(_ip_leaks(f"[{tok}]:443"), [], f"{tok}: чисто")

    def test_global_v6_leak(self):
        self.assertEqual(_ip_leaks("from [2606:4704:dead:beef::1]:443"),  # leak-guard-sample
                         ["публичный IPv6 2606:4704:dead:beef::1"])  # leak-guard-sample

    def test_unattributed_owner_class_v6_leak(self):
        """Регрессия зачистки: реальные v6-семьи нод/клиентов НЕ
        атрибутированы (в отличие от ГРЧЦ/Google/CF) — любой адрес
        таких префиксов обязан ловиться, если вернётся в репо."""
        for tok in ("2a03:1f00:1234:5678::1", "2a12:beef:abcd:12::2",  # leak-guard-sample
                    "2606:4704:dead:beef::1"):  # leak-guard-sample
            self.assertIn(f"публичный IPv6 {tok}", _ip_leaks(tok))

    def test_exact_network_constants_clean(self):
        for tok in ("2000::/3", "fec0::/10", "2a01::/32",
                    "2604:1380:1000::/40", "2600:1f00::/32"):
            self.assertEqual(_ip_leaks(tok), [], f"{tok}: константа/фикстура")

    def test_known_hosts_clean(self):
        for tok in ("2001:4860:4860::8888", "2606:4700:4700::1111",
                    "2a10:50c0::1:ff", "2a02:6b8::1", "2a12::1"):
            self.assertEqual(_ip_leaks(tok), [])

    def test_thirdparty_subnets_clean(self):
        for tok in ("2606:4700:110:8d87::", "2606:4700:3034::ac43:9014",
                    "2001:b28:f23c::/48", "2a00:7360::/32"):
            self.assertEqual(_ip_leaks(tok), [])

    def test_v6_mapped_v4_no_false_positive(self):
        """::ffff:TEST-NET — v4-внутренность проверяет IPv4-сканер,
        v6-сканер не должен матчить хвост '::ffff:'."""
        self.assertEqual(_ip_leaks("from [::ffff:192.0.2.20]:40123"), [])
        # а вот mapped РЕАЛЬНОГО публичного — ловится v4-частью
        self.assertIn("публичный IP 45.9.148.3",  # leak-guard-sample
                      _ip_leaks("from [::ffff:45.9.148.3]:443"))  # leak-guard-sample

    def test_non_address_tokens_no_false_positive(self):
        for text in ("12:34:56", "2026/10/27 03:53:45.890235",
                     "aa:bb:cc:dd:ee:ff",
                     "id d471e110-f003-47de-a27e-9e66dd2160f7"):
            self.assertEqual(_ip_leaks(text), [], f"ложное срабатывание: {text}")


class TestTokenPatterns(unittest.TestCase):
    """Токены/креды — LEAK."""

    def test_github_token(self):
        leaks = _scan("token ghp_" + "A" * 36)[0]
        self.assertTrue(any("github-token" in w for _, w in leaks))

    def test_gitlab_token(self):
        leaks = _scan("glpat-" + "x1y2z3w4q5e6r7t8y9")[0]
        self.assertTrue(any("gitlab-token" in w for _, w in leaks))

    def test_private_key(self):
        leaks = _scan("-----BEGIN RSA PRIVATE KEY-----")[0]  # leak-guard-sample
        self.assertTrue(any("private-key" in w for _, w in leaks))

    def test_tg_bot_token(self):
        leaks = _scan("123456789:AAFf-qwertyuiopASDFGHJKLzxcvbnm12345")[0]  # leak-guard-sample
        self.assertTrue(any("tg-bot-token" in w for _, w in leaks))


class TestSshPassInline(unittest.TestCase):
    """ssh-pass-inline: код-получатели пароля — не LEAK, литерал — LEAK."""

    def test_code_getter_not_flagged(self):
        """Регрессия: `password = users_by_login.get(login, "")` (wpp_portal)
        — чтение пароля из структуры, а не инлайн-секрет."""
        leaks = _scan('    password = users_by_login.get(login, "")')[0]
        self.assertFalse(any("ssh-pass-inline" in w for _, w in leaks))

    def test_inline_literal_flagged(self):
        leaks = _scan('password = Sup3rS3cretValue!')[0]  # leak-guard-sample
        self.assertTrue(any("ssh-pass-inline" in w for _, w in leaks))


class TestSampleMarker(unittest.TestCase):
    """Маркер-исключение: образцы утечек в самотесте сканера.

    Строка с SAMPLE_MARK пропускается; маркер разрешён ТОЛЬКО в этом
    файле (в любом другом — сам является LEAK), в режимах дифа/стейджа
    — молча пропускает строку (источник-файл неизвестен).
    """

    def test_marker_skips_sample_in_samples_file(self):
        line = "x = 45.9.148.3  " + lg.SAMPLE_MARK  # leak-guard-sample
        leaks, warns = [], []
        lg.scan_text(line, lg.SAMPLES_FILE, leaks, warns)
        self.assertEqual(leaks, [])

    def test_marker_is_leak_elsewhere(self):
        line = "x = 45.9.148.3  " + lg.SAMPLE_MARK  # leak-guard-sample
        leaks, warns = [], []
        lg.scan_text(line, "chimera/modules/fake.py", leaks, warns)
        self.assertTrue(any("маркер" in w for _, w in leaks))

    def test_marker_skips_in_staged_origin(self):
        line = "x = 45.9.148.3  " + lg.SAMPLE_MARK  # leak-guard-sample
        leaks, warns = [], []
        lg.scan_text(line, "STAGED (+lines)", leaks, warns)
        self.assertEqual(leaks, [])

    def test_unmarked_line_still_scanned_in_samples_file(self):
        leaks, warns = [], []
        lg.scan_text("x = 45.9.148.3", lg.SAMPLES_FILE, leaks, warns)  # leak-guard-sample
        self.assertEqual(len(leaks), 1)


if __name__ == "__main__":
    unittest.main()
