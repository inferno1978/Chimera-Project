#!/usr/bin/env python3
"""
tests/test_secure_bootstrap.py
───────────────────────────────────────────────────────────────────────────────
Тесты безопасной мульти-зеркальной установки (CHIMERA SECURE INSTALL).

Проверяется РЕАЛЬНЫЙ блок команды установки, извлечённый из README.md
(бит-в-бит то, что копируют пользователи). Криптография — настоящий
openssl + тестовый Ed25519-ключ (PEM из блока подменяется на тестовый).
Сеть — заглушка curl (map-файл), прод-серверы не затрагиваются.

Сценарии (ТЗ «Secure Multi-Mirror Bootstrap»):
  1.  Основное зеркало доступно, подпись верна → запуск (+args, +exit code).
  2.  Основное недоступно → переход на второе.
  3.  Первые два недоступны → переход на третье.
  4.  Все недоступны → понятная ошибка, rc=1, ничего не исполнено.
  5.  HTTP 404/500 (22), DNS (6), таймаут (28), обрыв (18) → переход.
  6.  Пустой файл / сверхбольшой файл → отброшен; все пустые → fail-closed.
  7.  Повреждённая подпись → не исполнено.
  8.  Изменённый скрипт при старой подписи → не исполнено.
  9.  Нет openssl → отказ ДО загрузки, rc=1.
  10. Подпись чужим ключом / подменённый файл → не исполнено.
  11. Ошибка проверки первого зеркала при недоступных остальных →
      корректный вердикт («не прошли проверку», НЕ «все недоступны»).
  12. Исполняется ровно проверенный файл (sha256 совпадает).
  13. Временные файлы удаляются (успех и ошибки).
  14. Аргументы и код возврата bootstrap сохраняются.
  15. Минимальное окружение (без python/git и прочих необязательных утилит).

Плюс консистентность: блок идентичен во всех документах; PEM блока ==
scripts/bootstrap-release/bootstrap.pub; bootstrap.sh.sig валиден;
порядок зеркал forgejo→gitlab→github; bash -n.
"""
import glob
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
README = _PROJECT_ROOT / "README.md"

M1 = "https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh"
M2 = "https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh"
M3 = "https://raw.githubusercontent.com/inferno1978/Chimera-Project/main/bootstrap.sh"

BLOCK_RE = re.compile(
    r"# >>> CHIMERA SECURE INSTALL.*?^# <<< CHIMERA SECURE INSTALL$", re.S | re.M)
PEM_RE = re.compile(
    r"-----BEGIN PUBLIC KEY-----\n[^\n]+\n-----END PUBLIC KEY-----")

CURL_STUB = r'''#!/bin/bash
# Заглушка curl для тестов secure bootstrap: НИКАКОЙ сети.
# Поведение из $CURL_STUB_DIR/map: строки "URL file:<path>" | "URL exit:<code>".
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in
        http*) url="$1" ;;
        -o)    out="$2"; shift ;;
    esac
    shift
done
echo "$url " >> "$CURL_STUB_DIR/calls.log"
line="$(grep -F "$url " "$CURL_STUB_DIR/map" | head -1)"
[ -z "$line" ] && exit 6
res="${line#* }"
case "$res" in
    file:*) src="${res#file:}"
            if [ -n "$out" ]; then cat "$src" > "$out"; else cat "$src"; fi
            exit 0 ;;
    exit:*) exit "${res#exit:}" ;;
esac
exit 6
'''

FIXTURE_OK = r'''#!/bin/bash
sha256sum "$0" | awk '{print $1}' > ran.sha256
echo "ARGS:[$*]"
exit "${CHIMERA_TEST_EXIT:-0}"
'''

FIXTURE_EVIL = r'''#!/bin/bash
echo "EVIL EXECUTED" > evil-ran
exit 0
'''


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def extract_block() -> str:
    """Канонический блок из README (вместе с маркерами)."""
    m = BLOCK_RE.search(_read(README))
    if not m:
        raise AssertionError("CHIMERA SECURE INSTALL не найден в README.md")
    return m.group(0)


class SecureBootstrapTestCase(unittest.TestCase):
    """Базовое окружение: тестовый ключ, фикстуры, sandbox с curl-заглушкой."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="secboot-test."))
        cls.bin_dir = cls.dir / "bin"
        cls.bin_dir.mkdir()
        (cls.bin_dir / "curl").write_text(CURL_STUB, encoding="utf-8")
        os.chmod(cls.bin_dir / "curl", 0o755)

        # Тестовый Ed25519-ключ (НЕ прод-ключ)
        cls.key = cls.dir / "test-ed25519.pem"
        cls.other_key = cls.dir / "other-ed25519.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                        "-out", str(cls.key)], check=True, capture_output=True)
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                        "-out", str(cls.other_key)], check=True, capture_output=True)
        cls.pub = subprocess.run(
            ["openssl", "pkey", "-in", str(cls.key), "-pubout"],
            check=True, capture_output=True).stdout.decode()
        # Однострочный вид для подмены в блоке
        cls.pub_oneline = cls.pub.strip()

        # Фикстуры
        cls.fixtures = cls.dir / "fixtures"
        cls.fixtures.mkdir()
        (cls.fixtures / "ok.sh").write_text(FIXTURE_OK, encoding="utf-8")
        (cls.fixtures / "evil.sh").write_text(FIXTURE_EVIL, encoding="utf-8")
        (cls.fixtures / "empty.sh").write_text("", encoding="utf-8")
        (cls.fixtures / "big.sh").write_bytes(b"# big\n" + b"x" * 600_000)
        cls.sigs = {}
        # Подписи фиксируются для непустых фикстур (пустые/oversized
        # отбрасываются size-чеком ДО проверки подписи — подписывать их не нужно;
        # openssl pkeyutl -rawin вообще не подписывает пустой вход).
        for name, key, src in [("ok", cls.key, "ok.sh"), ("evil", cls.key, "evil.sh"),
                               ("ok_by_other", cls.other_key, "ok.sh"),
                               ("evil_by_other", cls.other_key, "evil.sh")]:
            sig = cls.dir / f"{name}.sig"
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key),
                            "-rawin", "-in", str(cls.fixtures / src),
                            "-out", str(sig)], check=True, capture_output=True)
            cls.sigs[name] = sig

        # Блок команды установки с тестовым ключом вместо прод-ключа
        cls.block = PEM_RE.sub(lambda _: cls.pub_oneline, extract_block())
        (cls.dir / "block.sh").write_text(cls.block, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    # ── инфраструктура прогона ─────────────────────────────────────
    def run_block(self, mirror_map, args=(), env_extra=None,
                  exclude_openssl=False, minimal_path=False):
        """Прогнать блок. mirror_map: {url: ('file', path)|('exit', N)}.
        Возвращает (rc, stdout, stderr, workdir)."""
        work = Path(tempfile.mkdtemp(prefix="secboot-run.", dir=str(self.dir)))
        stub_dir = work / "stub"
        stub_dir.mkdir()
        env_extra = dict(env_extra or {})
        lines = []
        for url, beh in mirror_map.items():
            if beh[0] == "file":
                lines.append(f"{url} file:{beh[1]}")
            else:
                lines.append(f"{url} exit:{beh[1]}")
        (stub_dir / "map").write_text("\n".join(lines) + "\n", encoding="utf-8")

        if minimal_path:
            # Минимальный PATH: только то, что нужно блоку (+curl-заглушка).
            # Копии вместо symlink-ов — устойчивость к ограничениям окружения.
            minbin = work / "minbin"
            minbin.mkdir()
            for tool in ["bash", "cat", "wc", "mktemp", "rm", "chmod", "grep",
                         "head",           # нужен curl-заглушке
                         "sha256sum", "awk"]:  # нужны тестовой фикстуре ok.sh (не блоку)
                real = shutil.which(tool)
                assert real, f"{tool} не найден в системе"
                shutil.copy2(real, str(minbin / tool))
            shutil.copy2(shutil.which("openssl"), str(minbin / "openssl"))
            path = f"{self.bin_dir}:{minbin}"
        elif exclude_openssl:
            # PATH без openssl (bash/coreutils + заглушка curl)
            nobin = work / "nobin"
            nobin.mkdir()
            for tool in ["bash", "cat", "wc", "mktemp", "rm", "chmod", "grep"]:
                shutil.copy2(shutil.which(tool), str(nobin / tool))
            path = f"{self.bin_dir}:{nobin}"
        else:
            path = f"{self.bin_dir}:/usr/bin:/bin"

        env = dict(os.environ)
        env.update({
            "PATH": path,
            "CURL_STUB_DIR": str(stub_dir),
            "TMPDIR": str(work),
        })
        env.update(env_extra)

        pre = set(glob.glob("/tmp/chimera-bootstrap.*"))
        proc = subprocess.run(
            ["bash", str(self.dir / "block.sh"), *args],
            capture_output=True, text=True, env=env, cwd=str(work), timeout=120)
        post = set(glob.glob("/tmp/chimera-bootstrap.*"))
        self.assertEqual(pre, post,
                         f"утечка временных файлов: {sorted(post - pre)}")
        return proc.returncode, proc.stdout, proc.stderr, work

    def assert_ran(self, work, fixture="ok.sh"):
        self.assertTrue((work / "ran.sha256").exists(),
                        "проверенный bootstrap НЕ был запущен")
        expected = hashlib.sha256(
            (self.fixtures / fixture).read_bytes()).hexdigest()
        got = (work / "ran.sha256").read_text().strip()
        self.assertEqual(got, expected, "исполнен не тот файл, что проверен")

    def assert_not_ran(self, work):
        self.assertFalse((work / "ran.sha256").exists(),
                         "НЕПРОВЕРЕННЫЙ bootstrap был ИСПОЛНЁН — критический провал")
        self.assertFalse((work / "evil-ran").exists(), "исполнён evil-файл")

    # ── 1–3. happy path и fallback ────────────────────────────────
    def test_01_primary_ok_runs(self):
        rc, out, err, w = self.run_block({
            M1: ("file", str(self.fixtures / "ok.sh")),
            M1 + ".sig": ("file", str(self.sigs["ok"]))})
        self.assertEqual(rc, 0)
        self.assert_ran(w)

    def test_02_primary_down_second_ok(self):
        rc, out, err, w = self.run_block({
            M1: ("exit", 6),
            M2: ("file", str(self.fixtures / "ok.sh")),
            M2 + ".sig": ("file", str(self.sigs["ok"]))})
        self.assertEqual(rc, 0)
        self.assert_ran(w)

    def test_03_two_down_third_ok(self):
        rc, out, err, w = self.run_block({
            M1: ("exit", 28), M2: ("exit", 6),
            M3: ("file", str(self.fixtures / "ok.sh")),
            M3 + ".sig": ("file", str(self.sigs["ok"]))})
        self.assertEqual(rc, 0)
        self.assert_ran(w)

    def test_04_all_down(self):
        rc, out, err, w = self.run_block({
            M1: ("exit", 6), M2: ("exit", 6), M3: ("exit", 6)})
        self.assertEqual(rc, 1)
        self.assertIn("не удалось скачать bootstrap ни с одного зеркала", err)
        self.assert_not_ran(w)

    # ── 5. сетевые ошибки ──────────────────────────────────────────
    def test_05_http_404_fallback(self):
        for code in (22, 28, 18, 7):
            with self.subTest(curl_exit=code):
                rc, out, err, w = self.run_block({
                    M1: ("exit", code),
                    M2: ("file", str(self.fixtures / "ok.sh")),
                    M2 + ".sig": ("file", str(self.sigs["ok"]))})
                self.assertEqual(rc, 0)
                self.assert_ran(w)

    # ── 6. пустой/огромный файл ────────────────────────────────────
    def test_06a_empty_on_m1_falls_to_m2(self):
        rc, out, err, w = self.run_block({
            M1: ("file", str(self.fixtures / "empty.sh")),
            M2: ("file", str(self.fixtures / "ok.sh")),
            M2 + ".sig": ("file", str(self.sigs["ok"]))})  # .sig для M1 не запрашивается: пустой файл отбрасывается по размеру
        self.assertEqual(rc, 0)
        self.assert_ran(w)

    def test_06b_all_empty_fail_closed(self):
        rc, out, err, w = self.run_block({
            u: ("file", str(self.fixtures / "empty.sh")) for u in (M1, M2, M3)
        })  # .sig не запрашивается: пустой файл отбрасывается по размеру
        self.assertEqual(rc, 1)
        self.assertIn("не прошли проверку", err)
        self.assert_not_ran(w)

    def test_06c_all_oversized_fail_closed(self):
        rc, out, err, w = self.run_block({
            u: ("file", str(self.fixtures / "big.sh")) for u in (M1, M2, M3)
        })  # .sig не запрашивается: oversized отбрасывается по размеру
        self.assertEqual(rc, 1)
        self.assertIn("подозрительный размер", err)
        self.assert_not_ran(w)

    # ── 7. повреждённая подпись ────────────────────────────────────
    def test_07_corrupted_signature(self):
        rc, out, err, w = self.run_block({
            u: ("file", str(self.fixtures / "ok.sh")) for u in (M1, M2, M3)
        } | {u + ".sig": ("file", str(self.fixtures / "ok.sh"))  # sig-файл = сам скрипт (мусор)
             for u in (M1, M2, M3)})
        self.assertEqual(rc, 1)
        self.assertIn("не прошли проверку", err)
        self.assert_not_ran(w)

    def test_07b_wrong_sig_bytes(self):
        rc, out, err, w = self.run_block({
            u: ("file", str(self.fixtures / "ok.sh")) for u in (M1, M2, M3)
        } | {u + ".sig": ("file", str(self.sigs["evil"])) for u in (M1, M2, M3)})
        self.assertEqual(rc, 1)
        self.assertIn("ПОДПИСЬ НЕ ПРОШЛА", err)
        self.assert_not_ran(w)

    # ── 8. изменённый скрипт при старой подписи ────────────────────
    def test_08_modified_script_old_signature(self):
        # evil.sh + подпись, сделанная для ok.sh (stale signature)
        rc, out, err, w = self.run_block({
            u: ("file", str(self.fixtures / "evil.sh")) for u in (M1, M2, M3)
        } | {u + ".sig": ("file", str(self.sigs["ok"])) for u in (M1, M2, M3)})
        self.assertEqual(rc, 1)
        self.assertIn("ПОДПИСЬ НЕ ПРОШЛА", err)
        self.assert_not_ran(w)

    # ── 9. нет проверочного инструмента ────────────────────────────
    def test_09_no_openssl_fail_before_download(self):
        rc, out, err, w = self.run_block({
            M1: ("file", str(self.fixtures / "ok.sh")),
            M1 + ".sig": ("file", str(self.sigs["ok"]))},
            exclude_openssl=True)
        self.assertEqual(rc, 1)
        self.assertIn("не найден openssl", err)
        self.assert_not_ran(w)
        # curl вообще не должен вызываться (проверка инструмента — до загрузки)
        calls = w / "stub" / "calls.log"
        self.assertFalse(calls.exists() and calls.read_text().strip(),
                         "curl вызывался при отсутствии openssl")

    # ── 10. подменённый файл / чужой ключ ──────────────────────────
    def test_10_forged_by_attacker_key(self):
        # evil-файл, «валидно» подписанный ДРУГИМ (злоумышленника) ключом:
        # сиг структурно корректна, но закреплённый ключ её не принимает
        rc, out, err, w = self.run_block({
            u: ("file", str(self.fixtures / "evil.sh")) for u in (M1, M2, M3)
        } | {u + ".sig": ("file", str(self.sigs["evil_by_other"]))
             for u in (M1, M2, M3)})
        self.assertEqual(rc, 1)
        self.assertIn("ПОДПИСЬ НЕ ПРОШЛА", err)
        self.assert_not_ran(w)

    # ── 11. смешанный отказ: скачалось, но подпись не прошла ───────
    def test_11_downloaded_but_unverified_verdict(self):
        rc, out, err, w = self.run_block({
            M1: ("file", str(self.fixtures / "evil.sh")),
            M1 + ".sig": ("file", str(self.sigs["ok"])),  # mismatch
            M2: ("exit", 6), M3: ("exit", 28)})
        self.assertEqual(rc, 1)
        self.assertIn("не прошли проверку", err)
        self.assertNotIn("не удалось скачать bootstrap ни с одного зеркала", err)
        self.assertIn("ПОДПИСЬ НЕ ПРОШЛА", err)
        self.assert_not_ran(w)

    # ── 12. исполняется ровно проверенный файл ─────────────────────
    def test_12_verified_file_executed_as_is(self):
        rc, out, err, w = self.run_block({
            M1: ("file", str(self.fixtures / "ok.sh")),
            M1 + ".sig": ("file", str(self.sigs["ok"]))})
        self.assert_ran(w)  # sha256 запущенного == sha256 фикстуры

    # ── 13. очистка временных файлов ───────────────────────────────
    def test_13_tmp_cleanup_on_success_and_failure(self):
        # проверяется автоматически в каждом прогоне (pre/post glob);
        # здесь — явные кейсы успеха и полного отказа
        self.run_block({M1: ("file", str(self.fixtures / "ok.sh")),
                        M1 + ".sig": ("file", str(self.sigs["ok"]))})
        self.run_block({M1: ("exit", 6), M2: ("exit", 6), M3: ("exit", 6)})

    # ── 14. аргументы и код возврата ───────────────────────────────
    def test_14_args_and_exit_code_passthrough(self):
        rc, out, err, w = self.run_block(
            {M1: ("file", str(self.fixtures / "ok.sh")),
             M1 + ".sig": ("file", str(self.sigs["ok"]))},
            args=["--mode", "B", "extra"],
            env_extra={"CHIMERA_TEST_EXIT": "7"})
        self.assertEqual(rc, 7, "код возврата bootstrap не сохранён")
        self.assertIn("ARGS:[--mode B extra]", out)
        self.assert_ran(w)

    # ── 15. минимальное окружение ──────────────────────────────────
    def test_15_minimal_environment(self):
        rc, out, err, w = self.run_block(
            {M1: ("file", str(self.fixtures / "ok.sh")),
             M1 + ".sig": ("file", str(self.sigs["ok"]))},
            minimal_path=True)
        self.assertEqual(rc, 0)
        self.assert_ran(w)


class TestBlockConsistency(unittest.TestCase):
    """Статические инварианты блока и репозитория (без прогона)."""

    def setUp(self):
        self.block = extract_block()

    def test_block_bash_n(self):
        proc = subprocess.run(["bash", "-n", "/dev/stdin"],
                              input=self.block, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_mirror_order_forgejo_gitlab_github(self):
        i1 = self.block.index(M1)
        i2 = self.block.index(M2)
        i3 = self.block.index(M3)
        self.assertTrue(0 <= i1 < i2 < i3, "порядок зеркал нарушен")

    def test_block_identical_in_all_docs(self):
        blocks = {}
        for name in ["README.md", "INSTALL.md",
                     "docs/faq/VLESS_FAQ.md", "docs/faq/VK_BYPASS_FAQ.md"]:
            m = BLOCK_RE.search(_read(_PROJECT_ROOT / name))
            blocks[name] = m.group(0) if m else None
        self.assertTrue(all(blocks.values()),
                        f"блок отсутствует в: {[k for k, v in blocks.items() if not v]}")
        self.assertEqual(len(set(blocks.values())), 1,
                         "блок различается между документами")

    def test_pubkey_in_block_matches_repo_pub(self):
        pub_repo = _read(_PROJECT_ROOT / "scripts/bootstrap-release/bootstrap.pub").strip()
        m = PEM_RE.search(self.block)
        self.assertTrue(m, "PEM не найден в блоке")
        self.assertEqual(m.group(0), pub_repo.replace("\n", "\n").strip(),
                         "PEM в команде != scripts/bootstrap-release/bootstrap.pub")

    def test_repo_signature_valid(self):
        sig = _PROJECT_ROOT / "bootstrap.sh.sig"
        pub = _PROJECT_ROOT / "scripts/bootstrap-release/bootstrap.pub"
        bs = _PROJECT_ROOT / "bootstrap.sh"
        self.assertTrue(sig.exists(), "bootstrap.sh.sig отсутствует в репо")
        self.assertEqual(sig.stat().st_size, 64, "подпись не 64 байта")
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
             "-rawin", "-in", str(bs), "-sigfile", str(sig)],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0,
                         f"подпись в репо НЕ валидна: {proc.stdout}{proc.stderr}")

    def test_no_pipe_to_bash_commands_left(self):
        for name in ["README.md", "INSTALL.md", "docs/faq/VLESS_FAQ.md",
                     "docs/faq/VK_BYPASS_FAQ.md", "bootstrap.sh"]:
            text = _read(_PROJECT_ROOT / name)
            self.assertIsNone(
                re.search(r"bash <\(curl[^\n]*bootstrap\.sh", text),
                f"{name}: осталась pipe-команда установки bootstrap")

    def test_fail_closed_branches_present(self):
        # статическое наличие всех веток отказов (5 различимых причин)
        for marker in ["не найден openssl",              # нет инструмента
                       "не поддерживает Ed25519",         # ключ не поддерживается
                       "не удалось скачать bootstrap ни с одного зеркала",  # все недоступны
                       "не прошли проверку",              # скачалось, но не проверено
                       "ПОДПИСЬ НЕ ПРОШЛА"]:              # конкретная причина
            self.assertIn(marker, self.block, f"в блоке нет ветки: {marker}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
