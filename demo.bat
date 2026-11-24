@echo off
rem TwoKey — демо для показа: агент по очереди пытается сделать 7 действий.
rem demo.bat         — имитация бота прямо в этом окне: Telegram, интернет и сервер не нужны, Enter — следующий шаг.
rem demo.bat --auto  — то же, шаги идут сами (для записи видео).
rem demo.bat live    — карточки в настоящий Telegram, нажимайте кнопки (нужен запущенный TwoKey).
chcp 65001 >nul
title TwoKey demo
cd /d "%~dp0"
where python >nul 2>nul || (echo Python не найден. Установите Python 3.10+ с python.org & pause & exit /b 1)
if /i "%~1"=="live" (python guardian.py demo) else (python demo.py %*)
echo.
pause
