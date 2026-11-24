@echo off
rem TwoKey — демо для показа: агент по очереди пытается сделать 7 действий.
rem demo.bat                — «ИИ-агент» шлёт команды в запущенный TwoKey: карточки в Telegram и в окне, решаете вы.
rem demo.bat offline        — имитация бота прямо в этом окне без сети, Enter — следующий шаг.
rem demo.bat offline --auto — то же, шаги идут сами (для записи видео).
chcp 65001 >nul
title TwoKey demo
cd /d "%~dp0"
where python >nul 2>nul || (echo Python не найден. Установите Python 3.10+ с python.org & pause & exit /b 1)
if /i "%~1"=="offline" (python demo.py %2 %3 %4) else (python demo.py --live)
echo.
pause
