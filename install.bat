@echo off
rem TwoKey — установщик: двойной клик. Нужен Python 3.10+ (python.org, галочка «Add python.exe to PATH»).
chcp 65001 >nul
cd /d "%~dp0"
where pyw >nul 2>nul && (start "" pyw -3 install.py & exit /b 0)
where pythonw >nul 2>nul && (start "" pythonw install.py & exit /b 0)
rem python.exe без установленного Python — заглушка Microsoft Store: проверяем, что это настоящий Python 3.10+
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && ((python install.py || pause) & exit /b 0)
echo Python 3.10+ не найден. Установите его с https://www.python.org/downloads/
echo (отметьте «Add python.exe to PATH») и запустите install.bat снова.
pause
