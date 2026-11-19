@echo off
rem TwoKey — демо для показа: агент по очереди пытается сделать 7 действий.
rem Безопасные проходят сразу, опасные приходят карточками в Telegram — нажимайте кнопки.
rem Нужен запущенный сервер TwoKey (ярлык TwoKey или: python guardian.py serve).
chcp 65001 >nul
title TwoKey demo
cd /d "%~dp0"
where python >nul 2>nul || (echo Python не найден. Установите Python 3.10+ с python.org & pause & exit /b 1)
python guardian.py demo
echo.
pause
