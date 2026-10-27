# tests/_ci_site/sitecustomize.py
"""
Сайт-хук для САБПРОЦЕССОВ тестов (ci_suite.sh добавляет этот каталог в
PYTHONPATH и экспортирует CHIMERA_TEST_ISOLATE=1). Python импортирует
sitecustomize автоматически при старте → внутренние скрипты, которые
тесты запускают через `python3 -c ...` / `python3 file.py` (например,
inner-скрипт tg-бота), получают ту же env-изоляцию прод-деревьев, что и
основной тестовый процесс.

Требования: корень репо в PYTHONPATH (его ставит ci_suite.sh вместе с этим
каталогом). Если импорт не удался — тихий no-op: изоляция основного
процесса (tests/__init__.py) продолжает работать.
"""
import os

if os.environ.get("CHIMERA_TEST_ISOLATE", "") == "1":
    try:
        from tests._env_isolation import install
        install()
    except Exception:
        pass
