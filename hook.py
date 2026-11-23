"""Вход PreToolUse-хука: подключайте его, а не guardian.py напрямую.

Любая ошибка — даже битый guardian.py или .env — блокирует действие (код 2), а не пропускает его.
Импорт модулем к тому же кэширует байткод: хук стартует быстрее.
"""
import sys

try:
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # хук запускается с -I: папку скрипта Python не добавляет
    import guardian

    guardian.hook()
except SystemExit:
    raise
except BaseException as e:
    print(f"TwoKey: хук не запустился ({type(e).__name__}: {e}). Действие заблокировано (fail-closed).", file=sys.stderr)
    sys.exit(2)
