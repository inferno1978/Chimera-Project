"""Пакет тестов Химеры.

При CHIMERA_TEST_ISOLATE=1 (режимы gate/full в scripts/ci_suite.sh) ставит
env-изоляцию прод-деревьев ДО импорта любого tests.test_* модуля:
живые пути ноды (/var/lib/xray-installer, /etc/xray, ...) становятся
невидимыми — тесты видят ту же «чистую среду», под которую писались.
См. tests/_env_isolation.py.
"""
import os as _os

if _os.environ.get("CHIMERA_TEST_ISOLATE", "") == "1":
    try:
        from . import _env_isolation as _env_isolation_mod
        _env_isolation_mod.install()
    except Exception:  # pragma: no cover — изоляция не должна ломать сбор тестов
        pass
