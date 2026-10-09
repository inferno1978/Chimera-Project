#!/usr/bin/env python3
"""
tests/test_bootstrap_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты мульти-источникового bootstrap.sh (CHIMERA_MIRROR / CHIMERA_BRANCH).

Проверки (БЕЗ сети — только bash-выполнение конфиг-блока и парсинг):
  1. Дефолт без env: gitlab + ветка chimera-v5 + БИТ-В-БИТ старые URL —
     полная обратная совместимость (backward compat).
  2. CHIMERA_MIRROR=github: REPO_URL/ARCHIVE_URL/SHA256_URL/ветка main.
     CHIMERA_MIRROR=forgejo: свой Forgejo-хаб, ветка main, свои URL.
  3. Кастомное зеркало (https:// и ssh://, git@): только git clone
     (ARCHIVE_URL/SHA256_URL пустые), ветка chimera-v5.
  4. Порядок цепочки fallback: gitlab→forgejo→github; github→forgejo→gitlab;
     forgejo→gitlab→github; кастом→gitlab→forgejo→github.
  5. CHIMERA_BRANCH переопределяет ветку (URL'ы становятся branch-динамическими).
  6. Мусорный CHIMERA_MIRROR (не URL) → откат на gitlab-цепочку (WARN в лог).
  7. Структурные инварианты bootstrap.sh: unset-прокси guard, clone по $REPO_URL,
     integrity-проверка в обоих archive-путях, fallback-цикл, bash -n.
  8. bootstrap.sh.sha256 актуален (формат sha256sum -c, hash = hashlib).
"""
import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = _PROJECT_ROOT / "bootstrap.sh"
CHECKSUM = _PROJECT_ROOT / "bootstrap.sh.sha256"

# Заглушки логгеров — конфиг-блок должен работать в отрыве от остального скрипта.
_STUBS = """
ok()   { :; }
err()  { :; }
warn() { :; }
info() { :; }
"""

CUSTOM_HTTPS = "https://mirror.example.com/owner/chimera.git"
CUSTOM_SSH = "ssh://root@192.0.2.10/srv/git/chimera.git"
CUSTOM_GITAT = "git@mirror.example.com:owner/chimera.git"


def _mirror_block() -> str:
    """Конфиг-блок мульти-источника из bootstrap.sh (маркеры >>>/<<< CHIMERA MIRRORS)."""
    text = BOOTSTRAP.read_text(encoding="utf-8")
    m = re.search(r"# >>> CHIMERA MIRRORS.*?\n(.*?)# <<< CHIMERA MIRRORS", text, re.S)
    if not m:
        raise AssertionError("блок CHIMERA MIRRORS не найден в bootstrap.sh")
    return m.group(1)


def _run_block(env: dict, body: str) -> str:
    """Запуск конфиг-блока в bash с заданным env; body — код после source."""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(_STUBS + "\n" + _mirror_block() + "\n" + body)
        path = f.name
    try:
        run_env = {k: v for k, v in os.environ.items() if not k.startswith("CHIMERA_")}
        run_env.update(env)
        r = subprocess.run(["bash", path], capture_output=True, text=True,
                           env=run_env, timeout=30)
        if r.returncode != 0:
            raise AssertionError(f"bash упал ({r.returncode}): {r.stderr}")
        return r.stdout
    finally:
        os.unlink(path)


def _sources(env: dict) -> list:
    """[(SRC_LABEL, BRANCH, REPO_URL, ARCHIVE_URL, SHA256_URL), ...] по цепочке."""
    body = (
        "_build_source_chain\n"
        "for _s in \"${SOURCE_CHAIN[@]}\"; do\n"
        "    _src_setup \"$_s\"\n"
        "    echo \"${SRC_LABEL}|${BRANCH}|${REPO_URL}|${ARCHIVE_URL}|${SHA256_URL}\"\n"
        "done\n"
    )
    rows = []
    for line in _run_block(env, body).strip().splitlines():
        parts = line.split("|")
        assert len(parts) == 5, f"некорректная строка источника: {line!r}"
        rows.append(tuple(parts))
    return rows


# ============================================================================
#  1. ДЕФОЛТ (БЕЗ ENV) — ОБРАТНАЯ СОВМЕСТИМОСТЬ
# ============================================================================
class TestDefaultGitlabBackwardCompat(unittest.TestCase):
    """Дефолт без env — GitLab-источник первым, как до мульти-источника."""

    def test_chain_gitlab_forgejo_github(self):
        rows = _sources({})
        self.assertEqual([r[0] for r in rows], ["gitlab", "forgejo", "github"])

    def test_gitlab_row_bit_exact(self):
        gl_label, branch, repo, archive, sha256 = _sources({})[0]
        self.assertEqual(gl_label, "gitlab")
        self.assertEqual(branch, "chimera-v5")
        self.assertEqual(repo, "https://gitlab.com/netwalker071778/chimera-project")
        self.assertEqual(
            archive,
            "https://gitlab.com/netwalker071778/chimera-project/-/archive/"
            "chimera-v5/chimera-project-chimera-v5.tar.gz")
        self.assertEqual(
            sha256,
            "https://gitlab.com/netwalker071778/chimera-project/-/raw/"
            "chimera-v5/bootstrap.sh.sha256")

    def test_fallback_rows_in_default_chain(self):
        # rows[1] — forgejo (своё зеркало), rows[2] — github
        fj_label, fj_branch, fj_repo, fj_archive, fj_sha = _sources({})[1]
        self.assertEqual(fj_label, "forgejo")
        self.assertEqual(fj_branch, "main")
        self.assertEqual(fj_repo, "https://git.chimeraprodvpn.online/inferno1978/chimera.git")
        self.assertEqual(
            fj_archive,
            "https://git.chimeraprodvpn.online/inferno1978/chimera/archive/main.tar.gz")
        self.assertEqual(
            fj_sha,
            "https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh.sha256")
        gh_label, gh_branch, gh_repo, _, _ = _sources({})[2]
        self.assertEqual(gh_label, "github")
        self.assertEqual(gh_branch, "main")
        self.assertEqual(gh_repo, "https://github.com/inferno1978/Chimera-Project.git")


# ============================================================================
#  2. CHIMERA_MIRROR=github
# ============================================================================
class TestGithubMirror(unittest.TestCase):
    """GitHub как основной источник: ветка main + корректные URL."""

    def test_chain_github_forgejo_gitlab(self):
        rows = _sources({"CHIMERA_MIRROR": "github"})
        self.assertEqual([r[0] for r in rows], ["github", "forgejo", "gitlab"])

    def test_github_row_urls(self):
        _, branch, repo, archive, sha256 = _sources({"CHIMERA_MIRROR": "github"})[0]
        self.assertEqual(branch, "main")
        self.assertEqual(repo, "https://github.com/inferno1978/Chimera-Project.git")
        self.assertEqual(
            archive,
            "https://github.com/inferno1978/Chimera-Project/archive/refs/heads/main.tar.gz")
        self.assertEqual(
            sha256,
            "https://raw.githubusercontent.com/inferno1978/Chimera-Project/main/bootstrap.sh.sha256")

    def test_github_fallback_rows(self):
        fj_label, fj_branch, _, _, _ = _sources({"CHIMERA_MIRROR": "github"})[1]
        self.assertEqual(fj_label, "forgejo")
        self.assertEqual(fj_branch, "main")
        gl_label, gl_branch, _, _, _ = _sources({"CHIMERA_MIRROR": "github"})[2]
        self.assertEqual(gl_label, "gitlab")
        self.assertEqual(gl_branch, "chimera-v5")


# ============================================================================
#  2b. CHIMERA_MIRROR=forgejo (свой self-hosted хаб)
# ============================================================================
class TestForgejoMirror(unittest.TestCase):
    """Forgejo как основной источник: ветка main + корректные URL."""

    def test_chain_forgejo_gitlab_github(self):
        rows = _sources({"CHIMERA_MIRROR": "forgejo"})
        self.assertEqual([r[0] for r in rows], ["forgejo", "gitlab", "github"])

    def test_forgejo_row_urls(self):
        label, branch, repo, archive, sha256 = _sources({"CHIMERA_MIRROR": "forgejo"})[0]
        self.assertEqual(label, "forgejo")
        self.assertEqual(branch, "main")
        self.assertEqual(repo, "https://git.chimeraprodvpn.online/inferno1978/chimera.git")
        self.assertEqual(
            archive,
            "https://git.chimeraprodvpn.online/inferno1978/chimera/archive/main.tar.gz")
        self.assertEqual(
            sha256,
            "https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh.sha256")

    def test_forgejo_fallback_rows(self):
        rows = _sources({"CHIMERA_MIRROR": "forgejo"})
        self.assertEqual(rows[1][0], "gitlab")
        self.assertEqual(rows[1][1], "chimera-v5")
        self.assertEqual(rows[2][0], "github")
        self.assertEqual(rows[2][1], "main")

    def test_forgejo_with_branch_override(self):
        _, branch, _, archive, sha256 = _sources(
            {"CHIMERA_MIRROR": "forgejo", "CHIMERA_BRANCH": "dev"})[0]
        self.assertEqual(branch, "dev")
        self.assertIn("/archive/dev.tar.gz", archive)
        self.assertIn("/raw/branch/dev/bootstrap.sh.sha256", sha256)


# ============================================================================
#  3. КАСТОМНОЕ ЗЕРКАЛО
# ============================================================================
class TestCustomMirror(unittest.TestCase):
    """Кастомное зеркало: первым в цепочке, только git clone."""

    def _custom_row(self, url):
        rows = _sources({"CHIMERA_MIRROR": url})
        self.assertEqual(rows[0][0], "custom")
        return rows

    def test_chain_custom_first_https(self):
        labels = [r[0] for r in self._custom_row(CUSTOM_HTTPS)]
        self.assertEqual(labels, ["custom", "gitlab", "forgejo", "github"])

    def test_chain_custom_first_ssh(self):
        labels = [r[0] for r in self._custom_row(CUSTOM_SSH)]
        self.assertEqual(labels, ["custom", "gitlab", "forgejo", "github"])

    def test_chain_custom_first_gitat(self):
        labels = [r[0] for r in self._custom_row(CUSTOM_GITAT)]
        self.assertEqual(labels, ["custom", "gitlab", "forgejo", "github"])

    def test_custom_row_clone_only(self):
        for url in (CUSTOM_HTTPS, CUSTOM_SSH, CUSTOM_GITAT):
            _, branch, repo, archive, sha256 = self._custom_row(url)[0]
            self.assertEqual(branch, "chimera-v5", url)
            self.assertEqual(repo, url, url)               # URL передаётся как есть
            self.assertEqual(archive, "", url)             # tar.gz не предполагается
            self.assertEqual(sha256, "", url)              # .sha256 не предполагается

    def test_custom_fallback_rows(self):
        rows = self._custom_row(CUSTOM_HTTPS)
        self.assertEqual(rows[1][0], "gitlab")
        self.assertEqual(rows[1][1], "chimera-v5")
        self.assertEqual(rows[2][0], "forgejo")
        self.assertEqual(rows[2][1], "main")
        self.assertEqual(rows[3][0], "github")
        self.assertEqual(rows[3][1], "main")


# ============================================================================
#  4. CHIMERA_BRANCH
# ============================================================================
class TestBranchOverride(unittest.TestCase):
    """CHIMERA_BRANCH переопределяет ветку; URL'ы — branch-динамические."""

    def test_github_with_chimera_v5(self):
        _, branch, _, archive, sha256 = _sources(
            {"CHIMERA_MIRROR": "github", "CHIMERA_BRANCH": "chimera-v5"})[0]
        self.assertEqual(branch, "chimera-v5")
        self.assertIn("refs/heads/chimera-v5.tar.gz", archive)
        self.assertIn("/chimera-v5/bootstrap.sh.sha256", sha256)

    def test_custom_with_explicit_branch(self):
        _, branch, _, archive, _ = _sources(
            {"CHIMERA_MIRROR": CUSTOM_HTTPS, "CHIMERA_BRANCH": "dev"})[0]
        self.assertEqual(branch, "dev")
        self.assertEqual(archive, "")  # ветка не включает tar.gz для кастома

    def test_gitlab_with_branch_override(self):
        _, branch, _, archive, sha256 = _sources({"CHIMERA_BRANCH": "main"})[0]
        self.assertEqual(branch, "main")
        self.assertEqual(
            archive,
            "https://gitlab.com/netwalker071778/chimera-project/-/archive/"
            "main/chimera-project-main.tar.gz")
        self.assertIn("/raw/main/bootstrap.sh.sha256", sha256)

    def test_empty_branch_values_mean_default(self):
        # Пустые значения = «не задано» → авто-ветки
        # (gitlab: chimera-v5; forgejo/github: main)
        rows = _sources({"CHIMERA_MIRROR": "", "CHIMERA_BRANCH": ""})
        self.assertEqual(rows[0][1], "chimera-v5")
        self.assertEqual(rows[1][1], "main")
        self.assertEqual(rows[2][1], "main")


# ============================================================================
#  5. НЕВАЛИДНЫЙ CHIMERA_MIRROR
# ============================================================================
class TestInvalidMirror(unittest.TestCase):
    """Мусорное значение (не URL) → откат на gitlab-цепочку с WARN."""

    def test_garbage_falls_back_to_gitlab_chain(self):
        rows = _sources({"CHIMERA_MIRROR": "not-a-mirror"})
        self.assertEqual([r[0] for r in rows], ["gitlab", "forgejo", "github"])

    def test_garbage_logs_warning(self):
        body = (
            "warn() { echo \"WARN:$*\"; }\n"   # переопределяем заглушку сверху
            "_build_source_chain\n"
        )
        out = _run_block({"CHIMERA_MIRROR": "not-a-mirror"}, body)
        self.assertIn("WARN:", out)
        self.assertIn("gitlab", out)


# ============================================================================
#  6. СТРУКТУРНЫЕ ИНВАРИАНТЫ bootstrap.sh
# ============================================================================
class TestScriptStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = BOOTSTRAP.read_text(encoding="utf-8")

    def test_bash_syntax(self):
        r = subprocess.run(["bash", "-n", str(BOOTSTRAP)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_proxy_unset_guard_kept(self):
        # Anti-broken-env guard — НЕ удалять (см. требования к bootstrap).
        self.assertIn(
            "unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy",
            self.text)

    def test_set_euo_pipefail_kept(self):
        self.assertIn("set -euo pipefail", self.text)

    def test_clone_uses_repo_url_and_branch(self):
        self.assertIn(
            'git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"',
            self.text)

    def test_direct_pull_from_mirror(self):
        self.assertIn('git -C "$INSTALL_DIR" pull --quiet "$REPO_URL" "$BRANCH"',
                      self.text)

    def test_fallback_loop_present(self):
        self.assertIn('for _src in "${SOURCE_CHAIN[@]}"', self.text)
        self.assertIn("перехожу к следующему зеркалу", self.text)

    def test_integrity_check_wired_in_both_archive_paths(self):
        # определение + 2 места вызова (_archive_update и свежая установка)
        self.assertGreaterEqual(self.text.count("_verify_bootstrap_integrity"), 3)

    def test_per_source_urls_present(self):
        self.assertIn("https://github.com/inferno1978/Chimera-Project.git", self.text)
        self.assertIn("https://raw.githubusercontent.com/inferno1978/Chimera-Project/",
                      self.text)
        self.assertIn("https://gitlab.com/netwalker071778/chimera-project/-/raw/",
                      self.text)
        self.assertIn("https://git.chimeraprodvpn.online/inferno1978/chimera.git",
                      self.text)
        self.assertIn("https://git.chimeraprodvpn.online/inferno1978/chimera/archive/",
                      self.text)

    def test_forgejo_archive_dir_in_search_lists(self):
        # Forgejo-архив распаковывается в «chimera/» (имя репо, без суффикса ветки)
        self.assertIn('"${_staging}/chimera"', self.text)
        self.assertIn('"${_CLONE_STAGING}/chimera"', self.text)

    def test_custom_clone_only_messages(self):
        self.assertIn("только git clone", self.text)
        self.assertIn("не отдаёт tar.gz", self.text)


# ============================================================================
#  7. bootstrap.sh.sha256 АКТУАЛЕН
# ============================================================================
class TestSha256File(unittest.TestCase):
    """Чексумма соответствует текущему bootstrap.sh (забыл перегенерировать → FAIL)."""

    def test_format_sha256sum_c(self):
        content = CHECKSUM.read_text(encoding="utf-8")
        self.assertRegex(content, r"^[0-9a-f]{64}  bootstrap\.sh\n?$",
                         "формат: <64-hex>␣␣bootstrap.sh (sha256sum -c)")

    def test_hash_matches_bootstrap(self):
        expected = CHECKSUM.read_text(encoding="utf-8").split()[0]
        actual = hashlib.sha256(BOOTSTRAP.read_bytes()).hexdigest()
        self.assertEqual(
            expected, actual,
            "bootstrap.sh изменён без перегенерации bootstrap.sh.sha256 — "
            "запусти: bash scripts/generate_checksum.sh")


if __name__ == "__main__":
    unittest.main(verbosity=2)
