"""Вход PreToolUse-хука Claude Code: подключайте его, а не guardian.py напрямую.

Любая ошибка — даже битый guardian.py или .env — блокирует действие (код 2), а не пропускает его.
Импорт модулем к тому же кэширует байткод: хук стартует быстрее.
"""
import sys

try:
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    import guardian

    guardian.hook()
except SystemExit:
    raise
except BaseException as e:
    print(f"TwoKey: хук не запустился ({type(e).__name__}: {e}). Действие заблокировано (fail-closed).", file=sys.stderr)
    sys.exit(2)
