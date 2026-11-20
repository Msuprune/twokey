#!/usr/bin/env python3
"""Установщик TwoKey: рабочая копия, защита Claude Code, ярлыки «TwoKey» и автозапуск.

  python install.py               окно установщика
  python install.py --yes         установить без окна (настройки по умолчанию)
  python install.py --uninstall   убрать хук и ярлыки (папка с настройками и журналом остаётся)
  python install.py --selftest    проверить слияние хуков на временных файлах (настоящие настройки не трогаются)
  --home DIR  --claude-settings FILE  --lang ru|en|kk  --no-shortcuts  --no-start     особые случаи и проверка
"""
import json, os, re, shutil, subprocess, sys, threading, time

SRC = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.join(os.path.expanduser("~"), ".twokey")  # рабочая копия: агенту сюда нельзя ни писать, ни заглядывать
CLAUDE_SETTINGS = os.path.join(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude"), "settings.json")
FILES = ["guardian.py", "hook.py", "ui.html", "app.pyw", "templates.json", "i18n.json"]
HOOK_TIMEOUT = 960  # максимум ожидания человека (900 с) + запас 60 с
NEED_CC = (2, 1, 295)  # с этой версии Claude Code понимает onFailure: "block"

T = {
    "ru": dict(
        title="Установка TwoKey", sub="Второй ключ для ИИ-агентов", lang="Язык",
        hook="Защищать Claude Code (все проекты)", desktop="Ярлык на рабочем столе", menu="Ярлык в меню «Пуск»",
        auto="Запускать вместе с Windows", open="Открыть TwoKey после установки", folder="Папка: {}",
        install="Установить", update="Обновить", remove="Удалить", close="Закрыть",
        copy="✓ Программа скопирована в {}", env_new="✓ Создан файл настроек .env", env_keep="✓ Настройки сохранены (.env не тронут)",
        hook_ok="✓ Защита подключена к Claude Code ({})", hook_gone="✓ Защита отключена от Claude Code",
        cc_old="⚠ Claude Code CLI {} не знает onFailure — при сбое хука действие пройдёт. Обновите: claude update",
        cc_ok="✓ Claude Code: {}", lnk="✓ Ярлык: {}", lnk_gone="✓ Ярлыки убраны", auto_on="✓ Автозапуск включён",
        auto_off="✓ Автозапуск выключен", restart="↻ Перезапускаю сервер TwoKey, чтобы применить новую версию…",
        other="⚠ На порту работает другая копия TwoKey ({}) — закройте её",
        old="⚠ Работает старая версия сервера TwoKey — закройте её окно (Ctrl+C) и откройте TwoKey ярлыком",
        done="Готово! TwoKey установлен.",
        done_rm="Готово. Хук и ярлыки убраны, папка {} осталась — её можно удалить вручную.", err="✗ Ошибка: {}",
        py_old="Нужен Python 3.10 или новее", confirm_rm="Отключить TwoKey от Claude Code и убрать ярлыки?",
        stopping="↻ Останавливаю сервер TwoKey…", old_rm="⚠ Работает старая версия сервера TwoKey — закройте её окно (Ctrl+C)",
        hook_none="• Хука TwoKey в {} не нашлось — отключать нечего",
        no_tk="Нет модуля tkinter. Запустите в консоли: python install.py --yes",
        hooks_off="⚠ В настройках Claude Code выключены все хуки — TwoKey не сработает. Включите хуки (/hooks) и запустите установку снова",
        store="⚠ Установка идёт на Python из Microsoft Store: ярлык в «Пуске» и автозапуск могут не появиться. Надёжнее — Python с python.org"),
    "en": dict(
        title="TwoKey setup", sub="The second key for AI agents", lang="Language",
        hook="Protect Claude Code (all projects)", desktop="Desktop shortcut", menu="Start menu shortcut",
        auto="Start with Windows", open="Open TwoKey when done", folder="Folder: {}",
        install="Install", update="Update", remove="Uninstall", close="Close",
        copy="✓ Program copied to {}", env_new="✓ Settings file .env created", env_keep="✓ Settings kept (.env untouched)",
        hook_ok="✓ Protection connected to Claude Code ({})", hook_gone="✓ Protection disconnected from Claude Code",
        cc_old="⚠ Claude Code CLI {} does not know onFailure — a crashed hook lets the action through. Update: claude update",
        cc_ok="✓ Claude Code: {}", lnk="✓ Shortcut: {}", lnk_gone="✓ Shortcuts removed", auto_on="✓ Autostart on",
        auto_off="✓ Autostart off", restart="↻ Restarting the TwoKey server to apply the new version…",
        other="⚠ Another TwoKey copy is running on the port ({}) — close it",
        old="⚠ An old TwoKey server version is running — close its window (Ctrl+C) and open TwoKey from the shortcut",
        done="Done! TwoKey is installed.",
        done_rm="Done. Hook and shortcuts removed; folder {} is kept — delete it by hand if you like.", err="✗ Error: {}",
        py_old="Python 3.10 or newer is required", confirm_rm="Disconnect TwoKey from Claude Code and remove shortcuts?",
        stopping="↻ Stopping the TwoKey server…", old_rm="⚠ An old TwoKey server version is running — close its window (Ctrl+C)",
        hook_none="• No TwoKey hook found in {} — nothing to disconnect",
        no_tk="tkinter is missing. Run in a console: python install.py --yes",
        hooks_off="⚠ All hooks are turned off in the Claude Code settings — TwoKey will not run. Turn hooks on (/hooks) and run setup again",
        store="⚠ Setup runs on Python from the Microsoft Store: the Start menu shortcut and autostart may not appear. Python from python.org is more reliable"),
    "kk": dict(
        title="TwoKey орнату", sub="ЖИ-агенттерге арналған екінші кілт", lang="Тіл",
        hook="Claude Code-ты қорғау (барлық жобалар)", desktop="Жұмыс үстеліндегі белгіше", menu="«Бастау» мәзіріндегі белгіше",
        auto="Windows-пен бірге іске қосу", open="Орнатқан соң TwoKey-ді ашу", folder="Қалта: {}",
        install="Орнату", update="Жаңарту", remove="Жою", close="Жабу",
        copy="✓ Бағдарлама {} қалтасына көшірілді", env_new="✓ .env баптау файлы жасалды", env_keep="✓ Баптаулар сақталды (.env өзгермеді)",
        hook_ok="✓ Қорғаныс Claude Code-қа қосылды ({})", hook_gone="✓ Қорғаныс Claude Code-тан ажыратылды",
        cc_old="⚠ Claude Code CLI {} onFailure-ды білмейді — хук құласа, әрекет өтіп кетеді. Жаңартыңыз: claude update",
        cc_ok="✓ Claude Code: {}", lnk="✓ Белгіше: {}", lnk_gone="✓ Белгішелер жойылды", auto_on="✓ Автоіске қосу қосулы",
        auto_off="✓ Автоіске қосу өшірулі", restart="↻ Жаңа нұсқа іске қосылуы үшін TwoKey серверін қайта қосамын…",
        other="⚠ Портта TwoKey-дің басқа көшірмесі жұмыс істеп тұр ({}) — оны жабыңыз",
        old="⚠ TwoKey серверінің ескі нұсқасы жұмыс істеп тұр — оның терезесін жабыңыз (Ctrl+C), содан кейін TwoKey-ді белгішеден ашыңыз",
        done="Дайын! TwoKey орнатылды.",
        done_rm="Дайын. Хук пен белгішелер жойылды, {} қалтасы қалды — оны қолмен жоюға болады.", err="✗ Қате: {}",
        py_old="Python 3.10 немесе жаңарақ нұсқасы керек", confirm_rm="TwoKey-ді Claude Code-тан ажыратып, белгішелерді жою керек пе?",
        stopping="↻ TwoKey серверін тоқтатамын…", old_rm="⚠ TwoKey серверінің ескі нұсқасы жұмыс істеп тұр — оның терезесін жабыңыз (Ctrl+C)",
        hook_none="• {} ішінде TwoKey хугы табылмады — ажырататын ештеңе жоқ",
        no_tk="tkinter модулі жоқ. Консольде іске қосыңыз: python install.py --yes",
        hooks_off="⚠ Claude Code баптауларында барлық хуктар өшірулі — TwoKey іске қосылмайды. Хуктарды қосып (/hooks), орнатуды қайта іске қосыңыз",
        store="⚠ Орнату Microsoft Store-дағы Python-да жүріп жатыр: «Бастау» мәзіріндегі белгіше мен автоіске қосу шықпауы мүмкін. python.org сайтындағы Python сенімдірек"),
}


def system_lang():
    try:
        import locale
        code = (locale.getlocale()[0] or "").lower()
        if os.name == "nt":
            import ctypes
            code = {0x19: "ru", 0x3f: "kk"}.get(ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3ff, code)
    except Exception:
        code = ""
    return "kk" if code.startswith(("kk", "kaz")) else "ru" if code.startswith(("ru", "russian")) else "en"


def in_store(exe):
    """Python из Microsoft Store: папка пакета с номером версии меняется при каждом обновлении Python, а запись
    в AppData уходит в его личную копию — ярлык «Пуска» и автозапуск могли бы оказаться не видны."""
    return "\\windowsapps\\" in exe.lower()


def python_for_hook():
    """python (не pythonw: хуку нужен stdout) по постоянному пути: у Python из Store — его псевдоним в WindowsApps."""
    folder, name = os.path.split(sys.executable)
    m = re.fullmatch(r"pythonw?([\d.]*)\.exe", name, re.I)
    found = []
    if m:
        want = f"python{m.group(1)}.exe"
        if in_store(sys.executable):
            found.append(os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", want))
        found += [os.path.join(folder, want), os.path.join(folder, "python.exe")]
    return next((p for p in found if os.path.exists(p)), sys.executable).replace("\\", "/")


def python_org():
    """Python 3.10+ с python.org (реестр PythonCore, не из Store), если установщик открыл Python из Microsoft Store:
    на нём установщик перезапускается. Иначе — пустая строка."""
    if os.name != "nt" or not in_store(sys.executable):
        return ""
    import winreg
    best = ((0, 0), "")
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            core = winreg.OpenKey(root, r"Software\Python\PythonCore")
        except OSError:
            continue
        with core:
            for i in range(winreg.QueryInfoKey(core)[0]):
                tag = winreg.EnumKey(core, i)
                m = re.fullmatch(r"(\d+)\.(\d+)", tag)
                try:
                    with winreg.OpenKey(core, tag + r"\InstallPath") as k:
                        try:
                            exe = winreg.QueryValueEx(k, "ExecutablePath")[0]
                        except OSError:
                            exe = os.path.join(winreg.QueryValueEx(k, "")[0], "python.exe")
                except OSError:
                    continue
                ver = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
                if ver >= (3, 10) and ver > best[0] and not in_store(exe) and os.path.exists(exe):
                    best = (ver, exe)
    return best[1]


HOOK_ARGS = ["-I", "-S"]  # хук без PYTHONPATH, .pth и sitecustomize: чужой код не запустится раньше защиты


def _hook_paths(h):
    """Аргументы хука: exec-форма (command + args) и строка оболочки, в том числе пути в кавычках."""
    out = [str(a) for a in h.get("args") or []]
    for q1, q2, bare in re.findall(r'"([^"]*)"|\'([^\']*)\'|(\S+)', str(h.get("command", ""))):
        out.append(q1 or q2 or bare)
    return [p.replace("\\", "/").rstrip("/").lower() for p in out]


def is_ours(h, home=""):
    """Хук TwoKey — запуск hook.py или guardian.py из папки этой установки (--home) или из папки с «twokey» в имени."""
    mine = home.replace("\\", "/").rstrip("/").lower()
    for p in _hook_paths(h):
        folder, _, name = p.rpartition("/")
        if name in ("hook.py", "guardian.py") and ("twokey" in folder.rpartition("/")[2] or folder == mine):
            return True
    return False


def edit_hooks(settings_path, home, add=True):
    """Убрать прежние хуки TwoKey и (если add) добавить свежий; вернуть, сколько прежних убрано.
    Резервная копия — рядом; файл меняется атомарно, права файла и ссылка на него (dotfiles) сохраняются."""
    path = os.path.realpath(settings_path)
    try:
        with open(path, encoding="utf-8-sig") as f:
            s = json.load(f)
    except FileNotFoundError:
        s = {}
    groups = s.setdefault("hooks", {}).setdefault("PreToolUse", [])
    removed = 0
    for g in groups:
        keep = [h for h in g.get("hooks") or [] if not (isinstance(h, dict) and is_ours(h, home))]
        removed += len(g.get("hooks") or []) - len(keep)
        g["hooks"] = keep
    groups[:] = [g for g in groups if g.get("hooks")]
    if add:
        groups.append({"matcher": "*", "hooks": [{"type": "command", "command": python_for_hook(),
                                                  "args": HOOK_ARGS + [os.path.join(home, "hook.py").replace("\\", "/")],
                                                  "timeout": HOOK_TIMEOUT, "onFailure": "block"}]})
    if not groups:
        del s["hooks"]["PreToolUse"]
        if not s["hooks"]:
            del s["hooks"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)
        f.write("\n")
    if os.path.exists(path):
        shutil.copy(path, path + ".twokey-backup")  # copy() переносит и права файла
        shutil.copymode(path, tmp)
    os.replace(tmp, path)
    return removed


def hooks_disabled(settings_path):
    """В настройках Claude Code выключены все хуки (disableAllHooks) — TwoKey подключён, но не сработает."""
    try:
        with open(settings_path, encoding="utf-8-sig") as f:
            return bool(json.load(f).get("disableAllHooks"))
    except (OSError, ValueError, AttributeError):
        return False


def copy_program(home, lang, say, t):
    os.makedirs(home, exist_ok=True)
    if os.name != "nt":
        os.chmod(home, 0o700)  # токен бота, билет панели и журнал — только владельцу
    for name in FILES:
        src = os.path.join(SRC, name)
        if os.path.exists(src) and os.path.abspath(src) != os.path.abspath(os.path.join(home, name)):
            shutil.copyfile(src, os.path.join(home, name + ".new"))
            os.replace(os.path.join(home, name + ".new"), os.path.join(home, name))
    with open(os.path.join(home, ".ignore"), "w", encoding="utf-8") as f:
        f.write("*\n")  # поиск Claude Code (ripgrep) не заглядывает в папку: там токен бота
    say(t["copy"].format(home))
    env = os.path.join(home, ".env")
    if os.path.exists(env):
        say(t["env_keep"])
    else:
        try:
            with open(os.path.join(SRC, ".env.example"), encoding="utf-8-sig") as f:
                text = f.read()
        except OSError:
            text = "TG_TOKEN=\nTG_CHAT_ID=\nTG_ADMINS=\nGUARDIAN_TIMEOUT=300\nGUARDIAN_JUDGE=off\n"
        text = re.sub(r"(?m)^GUARDIAN_LANG=.*\n?", "", text).rstrip("\n") + f"\nGUARDIAN_LANG={lang}\n"
        with open(env, "w", encoding="utf-8") as f:
            f.write(text)
        say(t["env_new"])
    if os.name != "nt":
        os.chmod(env, 0o600)


def load_guardian(home):
    sys.path.insert(0, home)
    import guardian
    return guardian


STARTUP_LNK = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "TwoKey.lnk")


def special_folder(csidl):
    import ctypes
    buf = ctypes.create_unicode_buffer(520)
    ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    return buf.value


def shortcut_paths():
    if os.name != "nt":
        return []
    return [os.path.join(special_folder(0x10), "TwoKey.lnk"), os.path.join(special_folder(0x02), "TwoKey.lnk")]  # стол, «Пуск»


def stop_server(g, say, t, restart=True):
    """Сервер этой копии останавливаем через его же панель: билет → токен → /api/shutdown.
    None — сервер не запущен, True — остановлен, False — порт занят старой или чужой копией (или остановить не вышло).
    restart=False — при удалении: сообщения без «перезапускаю» и без отсылки к ярлыку."""
    def get(path, body=None, token=""):
        req = g.urllib.request.Request(f"http://127.0.0.1:{g.PORT}{path}", data=None if body is None else json.dumps(body).encode(),
                                       headers={"Content-Type": "application/json", "X-TwoKey-Token": token})
        with g._NO_PROXY.open(req, timeout=5) as r:
            return json.load(r)
    try:
        h = get("/health")
    except Exception:
        return None
    if "home" not in h:  # версия до программы TwoKey: её останавливают только в её окне
        say(t["old"] if restart else t["old_rm"])
        return False
    if h["home"] != g.HOME_DIR:
        say(t["other"].format(h["home"]))
        return False
    say(t["restart"] if restart else t["stopping"])
    try:
        with open(g.TICKET_FILE, encoding="utf-8") as f:
            token = get("/api/login", {"ticket": f.read().strip()})["token"]
        get("/api/shutdown", {}, token)
    except Exception as e:
        say(t["err"].format(e))
        return False
    for _ in range(50):
        time.sleep(0.1)
        try:
            get("/health")
        except Exception:
            return True
    return False


def launch(g, home, *argv):
    """Процесс TwoKey без консоли и отдельно от установщика."""
    flags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS
    subprocess.Popen([g.pythonw(), *argv], cwd=home, creationflags=flags, close_fds=True, start_new_session=os.name != "nt",
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def install(opts, say):
    t = T[opts["lang"]]
    home = opts["home"]
    copy_program(home, opts["lang"], say, t)
    g = load_guardian(home)
    if opts["hook"]:
        edit_hooks(opts["settings"], home)
        say(t["hook_ok"].format(opts["settings"]))
        if hooks_disabled(opts["settings"]):
            say(t["hooks_off"])
    if os.name == "nt" and in_store(sys.executable):  # python.org не нашёлся — остались на Python из Store
        say(t["store"])
    cv = g.claude_versions()
    found = " · ".join(f"{k} {v}" for k, v in cv.items() if v)
    if found:
        say(t["cc_ok"].format(found))
    if cv.get("cli") and tuple(map(int, cv["cli"].split("."))) < NEED_CC:
        say(t["cc_old"].format(cv["cli"]))
    if os.name == "nt" and opts["shortcuts"]:
        for lnk, on in zip(shortcut_paths(), (opts["desktop"], opts["menu"])):
            if on:
                g.make_shortcut(lnk, g.pythonw(), f'"{os.path.join(home, "app.pyw")}"', t["sub"], workdir=home)
                say(t["lnk"].format(lnk))
            elif os.path.exists(lnk):
                os.remove(lnk)
        g.set_autostart(opts["auto"])
        say(t["auto_on"] if opts["auto"] else t["auto_off"])
    stopped = stop_server(g, say, t)  # пока порт занят старой копией, окно не открываем — оно сразу выдало бы ошибку
    if stopped is not False and opts["open"]:
        launch(g, home, os.path.join(home, "app.pyw"))
    elif stopped:  # окно не просили — поднимаем только сервер, как было до обновления
        launch(g, home, os.path.join(home, "guardian.py"), "serve", "--no-browser")
    say(t["done"])


def uninstall(opts, say):
    t = T[opts["lang"]]
    removed = edit_hooks(opts["settings"], opts["home"], add=False)
    say(t["hook_gone"] if removed else t["hook_none"].format(opts["settings"]))
    g = load_guardian(opts["home"]) if os.path.exists(os.path.join(opts["home"], "guardian.py")) else None
    if opts["shortcuts"]:  # ярлыки и автозапуск общие для пользователя; --no-shortcuts их не трогает
        for lnk in shortcut_paths():
            if os.path.exists(lnk):
                os.remove(lnk)
        if g and os.name == "nt":
            g.set_autostart(False)
        say(t["lnk_gone"])
    if g:
        stop_server(g, say, t, restart=False)
    say(t["done_rm"].format(opts["home"]))


def selftest():
    """Слияние хуков на временных файлах: чужие хуки целы, наш один, удаление чистое. Настоящие настройки не трогаются."""
    import tempfile

    def read(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def ours(p, home=""):
        return [h for grp in read(p)["hooks"]["PreToolUse"] for h in grp["hooks"] if is_ours(h, home)]
    with tempfile.TemporaryDirectory() as d:
        path, home = os.path.join(d, "settings.json"), os.path.join(d, "twokey")
        other = {"matcher": "Bash", "hooks": [  # чужие хуки, в том числе похожие на наш, — не трогаем
            {"type": "command", "command": "echo other"},
            {"type": "command", "command": "python", "args": [os.path.join(d, "twokey-lab", "format_hook.py")]},
            {"type": "command", "command": f'python "{os.path.join(d, "hooks", "audit_hook.py")}" --skip {home}'}]}
        old = [{"type": "command", "command": "python", "args": [os.path.join(home, "guardian.py"), "hook"], "timeout": 360},
               {"type": "command", "command": f'python "{os.path.join(d, "my twokey", "hook.py")}"'}]  # строка оболочки, путь с пробелом
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"model": "x", "hooks": {"PreToolUse": [other, {"matcher": "*", "hooks": old}]}}, f)
        assert edit_hooks(path, home) == 2 and edit_hooks(path, home) == 1  # повторная установка не плодит хуки
        s, mine = read(path), ours(path)
        assert s["model"] == "x" and other in s["hooks"]["PreToolUse"], s
        assert len(mine) == 1 and mine[0]["onFailure"] == "block" and mine[0]["timeout"] == HOOK_TIMEOUT, mine
        assert mine[0]["args"] == HOOK_ARGS + [os.path.join(home, "hook.py").replace("\\", "/")], mine
        assert os.path.exists(path + ".twokey-backup")
        assert edit_hooks(path, home, add=False) == 1  # удаление
        assert read(path) == {"model": "x", "hooks": {"PreToolUse": [other]}}, read(path)
        elsewhere = os.path.join(d, "tools", "guard")  # --home без «twokey» в имени папки: хук всё равно узнаём
        edit_hooks(path, elsewhere)
        edit_hooks(path, elsewhere)
        assert len(ours(path, elsewhere)) == 1, read(path)
        assert edit_hooks(path, elsewhere, add=False) == 1 and read(path) == {"model": "x", "hooks": {"PreToolUse": [other]}}
        os.remove(path)
        assert edit_hooks(path, home, add=False) == 0 and read(path) == {}  # настроек ещё нет — удаление не падает
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"disableAllHooks": True}, f)
        edit_hooks(path, home)  # выключенные хуки не трогаем, но предупреждаем
        assert hooks_disabled(path) and not hooks_disabled(os.path.join(d, "none.json")), read(path)
    print("install.py: самопроверка пройдена")


# ------------------------------------------------------------------ окно ---
BG, SURFACE, FG, MUTED, ACCENT, LOGBG = "#0E151D", "#16202B", "#E9EEF3", "#9AA7B4", "#FF6B2C", "#070B10"


def gui(opts):
    import tkinter as tk
    from tkinter import messagebox, ttk
    root = tk.Tk()
    root.configure(bg=BG)
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=FG, font=("Segoe UI", 10))
    style.configure("TCheckbutton", background=BG, foreground=FG, indicatorbackground=SURFACE, indicatorforeground=ACCENT)
    style.map("TCheckbutton", background=[("active", BG)], indicatorbackground=[("selected", SURFACE)])
    style.configure("TButton", background=SURFACE, foreground=FG, bordercolor="#2A3847", padding=(14, 8))
    style.map("TButton", background=[("active", "#1D2935")])
    style.configure("Accent.TButton", background=ACCENT, foreground=BG, font=("Segoe UI", 10, "bold"))
    style.map("Accent.TButton", background=[("active", "#FF8550"), ("disabled", "#7a4a33")])
    style.configure("TCombobox", fieldbackground=SURFACE, background=SURFACE, foreground=FG, arrowcolor=FG)
    style.map("TCombobox", fieldbackground=[("readonly", SURFACE)], foreground=[("readonly", FG)],  # clam красит readonly
              selectbackground=[("readonly", SURFACE)], selectforeground=[("readonly", FG)])  # светлым: текст сливался
    root.option_add("*TCombobox*Listbox.background", SURFACE)
    root.option_add("*TCombobox*Listbox.foreground", FG)

    head = tk.Frame(root, bg=BG)
    head.pack(fill="x", padx=24, pady=(20, 4))
    tk.Label(head, text="Two", bg=BG, fg=FG, font=("Segoe UI", 26, "bold")).pack(side="left")
    tk.Label(head, text="Key", bg=BG, fg=ACCENT, font=("Segoe UI", 26, "bold")).pack(side="left")
    sub = tk.Label(root, bg=BG, fg=MUTED, font=("Segoe UI", 11), anchor="w")
    sub.pack(fill="x", padx=24)

    body = tk.Frame(root, bg=BG)
    body.pack(fill="x", padx=24, pady=12)
    lang_row = tk.Frame(body, bg=BG)
    lang_row.pack(fill="x", pady=(0, 8))
    lang_label = tk.Label(lang_row, bg=BG, fg=FG)
    lang_label.pack(side="left")
    names = {"ru": "Русский", "en": "English", "kk": "Қазақша"}
    lang_var = tk.StringVar(value=names[opts["lang"]])
    combo = ttk.Combobox(lang_row, textvariable=lang_var, values=list(names.values()), state="readonly", width=14)
    combo.pack(side="left", padx=10)
    keys = ["hook", "desktop", "menu", "auto", "open"]
    vars_ = {k: tk.BooleanVar(value=opts[k]) for k in keys}
    checks = {k: ttk.Checkbutton(body, variable=vars_[k]) for k in keys}
    for k in keys:
        if os.name == "nt" or k in ("hook", "open"):
            checks[k].pack(anchor="w", pady=3)
    folder = tk.Label(body, bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=580)
    folder.pack(fill="x", pady=(8, 0))

    buttons = tk.Frame(root, bg=BG)  # кнопки — первыми в порядке упаковки: в маленьком окне сжимается журнал, а не они
    buttons.pack(side="bottom", fill="x", padx=24, pady=(0, 20), before=head)
    b_install = ttk.Button(buttons, style="Accent.TButton")
    b_remove = ttk.Button(buttons)
    b_close = ttk.Button(buttons, command=root.destroy)
    b_install.pack(side="left")
    b_remove.pack(side="left", padx=10)
    b_close.pack(side="right")

    log = tk.Text(root, height=8, bg=LOGBG, fg=FG, relief="flat", font=("Cascadia Mono", 9), wrap="word",
                  highlightthickness=1, highlightbackground="#2A3847", padx=10, pady=8)
    log.pack(fill="both", expand=True, padx=24, pady=(4, 12))
    log.configure(state="disabled")

    def lang():
        return next(k for k, v in names.items() if v == lang_var.get())

    def texts(*_):
        t = T[lang()]
        root.title(t["title"])
        sub.configure(text=t["sub"])
        lang_label.configure(text=t["lang"])
        for k in keys:
            checks[k].configure(text=t[k])
        folder.configure(text=t["folder"].format(opts["home"]))
        b_install.configure(text=t["update"] if os.path.exists(os.path.join(opts["home"], "guardian.py")) else t["install"])
        b_remove.configure(text=t["remove"])
        b_close.configure(text=t["close"])
    combo.bind("<<ComboboxSelected>>", lambda e: (combo.selection_clear(), texts()))
    texts()
    root.update_idletasks()  # размер окна — по содержимому (шрифты зависят от масштаба экрана), но не выше экрана
    w, h = max(640, root.winfo_reqwidth()), min(root.winfo_reqheight(), root.winfo_screenheight() - 80)
    root.geometry(f"{w}x{h}")
    root.minsize(min(w, 560), min(h, h - log.winfo_reqheight() + 60))  # уменьшается только за счёт журнала

    def say(line):
        def add():
            log.configure(state="normal")
            log.insert("end", line + "\n")
            log.see("end")
            log.configure(state="disabled")
        root.after(0, add)

    def run(fn):
        o = dict(opts, lang=lang(), **{k: v.get() for k, v in vars_.items()})
        for b in (b_install, b_remove):
            b.state(["disabled"])

        def work():
            try:
                fn(o, say)
            except Exception as e:
                say(T[o["lang"]]["err"].format(e))
            root.after(0, lambda: ([b.state(["!disabled"]) for b in (b_install, b_remove)], texts()))
        threading.Thread(target=work, daemon=True).start()

    b_install.configure(command=lambda: run(install))
    b_remove.configure(command=lambda: messagebox.askyesno("TwoKey", T[lang()]["confirm_rm"]) and run(uninstall))
    root.mainloop()


def main():
    args = sys.argv[1:]
    val = lambda flag, default: args[args.index(flag) + 1] if flag in args and args.index(flag) + 1 < len(args) else default
    opts = {"home": os.path.abspath(val("--home", HOME)), "settings": os.path.abspath(val("--claude-settings", CLAUDE_SETTINGS)),
            "lang": val("--lang", system_lang()), "hook": True, "desktop": True, "menu": True,
            "auto": os.name == "nt" and os.path.exists(STARTUP_LNK),  # обновление не выключает автозапуск, включённый раньше
            "open": "--no-start" not in args, "shortcuts": "--no-shortcuts" not in args}
    if opts["lang"] not in T:
        opts["lang"] = "en"
    if sys.version_info < (3, 10):
        fatal(T[opts["lang"]]["py_old"])
    alt = python_org()
    if alt:  # открыл Python из Store — тот же установщик с теми же флагами на python.org
        if {"--yes", "--uninstall", "--selftest"} & set(args):
            sys.exit(subprocess.call([alt, os.path.abspath(__file__), *args]))
        w = os.path.join(os.path.dirname(alt), "pythonw.exe")
        subprocess.Popen([w if os.path.exists(w) else alt, os.path.abspath(__file__), *args], close_fds=True)
        return
    if {"--yes", "--uninstall", "--selftest"} & set(args):
        for stream in (sys.stdout, sys.stderr):
            if stream:
                stream.reconfigure(encoding="utf-8", errors="replace")
        if "--selftest" in args:
            return selftest()
        (uninstall if "--uninstall" in args else install)(opts, print)
        return
    try:
        gui(opts)
    except ImportError:  # нет tkinter: в консоли ставим без окна, без консоли — объясняем, что делать
        if not sys.stdout:
            fatal(T[opts["lang"]]["no_tk"])
        install(opts, print)
    except Exception as e:  # окно не открылось (нет дисплея и т. п.)
        fatal(T[opts["lang"]]["err"].format(e))


def fatal(text):
    """Сообщение, которое человек увидит и без консоли (pyw): stderr, иначе окно tkinter, иначе MessageBox Windows."""
    if sys.stderr:
        sys.exit(text)
    try:
        import tkinter
        from tkinter import messagebox
        tkinter.Tk().withdraw()
        messagebox.showerror("TwoKey", text)
    except Exception:
        if os.name == "nt":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, text, "TwoKey", 0x10)
    sys.exit(1)


if __name__ == "__main__":
    main()
