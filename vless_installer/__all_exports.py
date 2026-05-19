"""
vless_installer/__all_exports.py
=================================
Реэкспорт всего публичного API из _core.py.
Используется только если нужен программный доступ к функциям.
"""
from vless_installer._core import *  # noqa: F401, F403
