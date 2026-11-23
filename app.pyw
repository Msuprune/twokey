"""TwoKey — окно программы. Запускает сервер в фоне (если он ещё не запущен) и открывает панель отдельным окном.

Окно: pywebview, если он установлен (pip install pywebview); иначе Microsoft Edge или Google Chrome в режиме
приложения — своё окно без вкладок и адресной строки; иначе обычный браузер.
"""
import json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import guardian as g  # noqa: E402  тот же порт, та же папка, тот же python, что у сервера


def health():
    try:
        with g._NO_PROXY.open(f"http://127.0.0.1:{g.PORT}/health", timeout=2) as r:
            return json.load(r)
    except Exception:
        return None


def ensure_server():
    """Сервер этой копии TwoKey уже работает — хорошо; нет — запускаем его без окна и ждём."""
    h = health()
    if h:
        return h
    flags = 0x08000000 | 0x00000008 if os.name == "nt" else 0  # CREATE_NO_WINDOW | DETACHED_PROCESS
    with open(os.path.join(HERE, "server.log"), "a", encoding="utf-8") as logfile:  # причина сбоя запуска останется в журнале
        subprocess.Popen([g.pythonw(), os.path.join(HERE, "guardian.py"), "serve", "--no-browser"], cwd=HERE, creationflags=flags,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=logfile, close_fds=True,
                         env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    for _ in range(75):
        time.sleep(0.2)
        h = health()
        if h:
            return h
    return None


def read_ticket():
    for _ in range(25):  # сервер пишет свежий билет при старте и после каждого входа
        try:
            with open(g.TICKET_FILE, encoding="utf-8") as f:
                t = f.read().strip()
            if t:
                return t
        except OSError:
            pass
        time.sleep(0.2)
    return ""


def app_browsers():
    pf, pf86, la = (os.environ.get(k, "") for k in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"))
    return [os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"), os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(pf, r"Google\Chrome\Application\chrome.exe"), os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(la, r"Google\Chrome\Application\chrome.exe")]


def open_window(url):
    try:
        import webview  # pywebview — настоящее окно программы
        webview.create_window("TwoKey", url, width=1200, height=820, min_size=(720, 560))
        webview.start()
        return
    except ImportError:
        pass
    for exe in app_browsers():
        if os.path.exists(exe):  # отдельный профиль: своё окно и значок в панели задач, без вкладок и адресной строки
            subprocess.Popen([exe, f"--app={url}", f"--user-data-dir={os.path.join(HERE, '.window')}", "--window-size=1200,820",
                              "--no-first-run", "--no-default-browser-check"])
            return
    import webbrowser
    webbrowser.open(url)


def fail(text):
    try:
        import tkinter.messagebox
        tkinter.messagebox.showerror("TwoKey", text)
    except Exception:
        print(text, file=sys.stderr)
    sys.exit(1)


def main():
    h = ensure_server()
    if not h:
        fail(g.tr("Сервер TwoKey не запустился. Подробности: {path}").format(path=os.path.join(HERE, "server.log")))
    if h.get("home") != g.HOME_DIR:
        fail(g.tr("На порту {port} работает другая копия TwoKey ({home}). Закройте её и запустите снова.").format(port=g.PORT, home=h.get("home")))
    ticket = read_ticket()
    if not ticket:
        fail(g.tr("Не удалось получить доступ к панели. Перезапустите TwoKey."))
    open_window(f"http://127.0.0.1:{g.PORT}/#ticket={ticket}")


if __name__ == "__main__":
    main()
