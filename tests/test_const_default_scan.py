#!/usr/bin/env python3
"""
tests/test_const_default_scan.py
───────────────────────────────────────────────────────────────────────────────
Самопроверка const-default сканера (scripts/const_default_scan.py) + ГЕЙТ:
дерево chimera/ + main.py должно быть чистым от класса «path-константа в
дефолт-аргументе» (cb461fa dpi_gate.load_model, 3783ee3 mask_gate,
7 экземпляров в telemt_fallback — все пойманы на живых нодах/аудитом).

Класс: def f(p: Path = STATE_FILE) вычисляет дефолт при импорте →
patch.object(mod, "STATE_FILE", tmp) в тестах не действует на прод-вызов.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "scripts"))

from const_default_scan import scan_source, scan_path  # noqa: E402


BAD_NAME_DEFAULT = '''
from pathlib import Path
STATE_FILE = Path("/var/lib/xray-installer/state.json")
MODEL_PATH = Path("/var/lib") / "model.json"

def load(p: Path = STATE_FILE):
    return p.read_text()

def load_model(m: Path = MODEL_PATH):
    return m.read_text()
'''

BAD_LITERAL_DEFAULT = '''
from pathlib import Path

def f(p: Path = Path("/etc/xray/config.json")):
    return p
'''

BAD_KW_DEFAULT = '''
from pathlib import Path
CFG = Path("/etc/telemt/telemt.toml")

def f(*, cfg: Path = CFG):
    return cfg
'''

GOOD_RUNTIME_RESOLVE = '''
from pathlib import Path
from typing import Optional
STATE_FILE = Path("/var/lib/xray-installer/state.json")

def load(p: Optional[Path] = None) -> str:
    p = Path(p) if p else STATE_FILE
    return p.read_text()
'''

GOOD_STR_CONST = '''
SERVICE_NAME = "telemt"

def f(service: str = SERVICE_NAME):
    return service
'''

GOOD_NON_PATH_CONST = '''
import re
PATTERN = re.compile(r"^test")

def f(pat=re.PATTERN_UNUSED if False else None):
    return pat
'''


class TestConstDefaultScanner(unittest.TestCase):
    def test_flags_name_default(self):
        """Name → module-level Path-константа: 2 находки (STATE_FILE и
        BinOp-склейка MODEL_PATH)."""
        findings = scan_source(BAD_NAME_DEFAULT, "synthetic.py")
        self.assertEqual(len(findings), 2, findings)
        self.assertIn("def load(…=STATE_FILE)", findings[0])
        self.assertIn("synthetic.py:", findings[0])

    def test_flags_path_literal_default(self):
        findings = scan_source(BAD_LITERAL_DEFAULT, "lit.py")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("Path(...)", findings[0])

    def test_flags_kwonly_default(self):
        findings = scan_source(BAD_KW_DEFAULT, "kw.py")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("=CFG", findings[0])

    def test_good_runtime_resolve_not_flagged(self):
        """Леченый паттерн Optional[Path]=None + резолв в теле — чисто."""
        self.assertEqual(scan_source(GOOD_RUNTIME_RESOLVE, "ok.py"), [])

    def test_good_str_const_not_flagged(self):
        """Правило узкое: str-константы в дефолтах легальны."""
        self.assertEqual(scan_source(GOOD_STR_CONST, "ok2.py"), [])

    def test_good_non_path_const_not_flagged(self):
        self.assertEqual(scan_source(GOOD_NON_PATH_CONST, "ok3.py"), [])

    def test_syntax_error_ignored(self):
        """Синтакс-ошибки — зона compileall-этапа CI, сканер молчит."""
        self.assertEqual(scan_source("def broken(:", "bad.py"), [])

    def test_gate_repo_tree_clean(self):
        """ГЕЙТ: прод-дерево чисто от класса. Новый экземпляр = красный CI.

        Если этот тест покраснел после добавления def f(p: Path = CONST) —
        лечится Optional[Path]=None + резолв в теле (уроки cb461fa,
        3783ee3, telemt_fallback-аудит 29.10.2026).
        """
        findings = []
        for target in (_PROJECT_ROOT / "chimera", _PROJECT_ROOT / "main.py"):
            findings.extend(scan_path(target))
        self.assertEqual(
            findings, [],
            "path-константы в дефолт-аргументах — лечить runtime-резолвом:\n"
            + "\n".join(findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
