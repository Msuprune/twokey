"""TwoKey — демо без настоящего бота.

Агент по очереди пробует 7 действий из сценария (guardian.DEMO). Их проверяют настоящие правила TwoKey, карточка
«бота» показывается прямо в этом окне, а кнопки нажимаются по сценарию. Telegram, интернет и сервер не нужны:
ничего не выполняется и никуда не отправляется.

  python demo.py                    Enter — следующий шаг (удобно на сцене)
  python demo.py --auto             шаги идут сами, пауза 2,5 с (для записи видео)
  python demo.py --auto --delay 0   быстрый прогон с проверкой итога: код 1, если что-то пошло не так
"""
import html, os, re, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import guardian as g  # noqa: E402

NOTE = "сначала бэкап, удали только тестовых"
PLAN = ["d", ("s", NOTE), "d", "d", "d"]  # что «нажимает человек» на опасных действиях сценария, по порядку
COLOR = sys.stdout.isatty()
C = {k: (v if COLOR else "") for k, v in dict(dim="\033[2m", b="\033[1m", ok="\033[32m", no="\033[31m",
                                                 tg="\033[38;5;208m", ag="\033[36m", x="\033[0m").items()}


def plain(text):
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def main():
    auto = "--auto" in sys.argv
    delay = float(sys.argv[sys.argv.index("--delay") + 1]) if "--delay" in sys.argv else 2.5
    if os.name == "nt":
        os.system("")  # включает цвета в консоли Windows

    def wait(what):
        if auto:
            time.sleep(delay)
        else:
            input(f"{C['dim']}   Enter — {what}{C['x']}")

    with tempfile.TemporaryDirectory(prefix="twokey-demo-", ignore_cleanup_errors=True) as tmp:
        os.makedirs(os.path.join(tmp, "src"))
        with open(os.path.join(tmp, "src", "payments.js"), "w", encoding="utf-8") as f:
            f.write("// учебный файл: его копию TwoKey снимет до решения человека\n")
        g.TG_TOKEN, g.TG_CHAT_ID, g.TG_ADMINS = "demo", "demo", set()
        g.JUDGE, g.BACKUP, g.TIMEOUT, g.LANG = "off", "auto", 300, "ru"
        g.AUDIT, g.ALLOW_FILE, g.BACKUP_DIR = os.devnull, os.path.join(tmp, "allow.json"), os.path.join(tmp, "backups")
        g.ALLOW.clear()
        g.tg = lambda method, **p: {"message_id": 1}  # настоящий Telegram не нужен: карточку показываем здесь
        g.log = lambda msg: None

        print(f"{C['b']}TwoKey · демо без Telegram{C['x']} {C['dim']}(имитация бота по сценарию, ничего не выполняется){C['x']}")
        results, plan = [], list(PLAN)
        for n, (tool, inp) in enumerate(g.DEMO, 1):
            if n > 1:
                wait("следующее действие агента")
            print(f"\n{C['ag']}{C['b']}{n}/{len(g.DEMO)} · Агент хочет:{C['x']} {tool}: {g.shown(inp)[:110]}")
            out = {}
            t = threading.Thread(target=lambda: out.update(g.decide({"tool": tool, "input": inp, "cwd": tmp, "agent": "demo-agent"})),
                                 daemon=True)
            t.start()
            while t.is_alive() and not g.PENDING:
                time.sleep(0.02)
            if g.PENDING:
                rid, p = next(iter(g.PENDING.items()))
                time.sleep(0.3)  # копия файлов успевает попасть в карточку
                print(f"{C['tg']}📱 Карточка TwoKey — так она приходит в Telegram{C['x']}")
                card = plain(g.card_text(p)).replace(g.BACKUP_DIR, "<папка TwoKey>\\backups").replace(tmp, r"C:\work\shop")
                for line in card.splitlines():
                    print(f"{C['tg']}│{C['x']} {line}")
                print(f"{C['tg']}│{C['x']} " + "  ".join(f"[{b['text']}]" for row in p["rows"] for b in row))
                step = plan.pop(0) if plan else "d"
                choice, text = step if isinstance(step, tuple) else (step, "")
                label = next(b["text"] for row in p["rows"] for b in row if b["callback_data"].startswith(choice + ":"))
                wait(f"нажать «{label}»")
                print(f"{C['tg']}👆 Нажато: {label}{C['x']}")
                if text:
                    print(f"{C['tg']}✍️  Ваше решение: {text}{C['x']}")
                g.resolve(rid, choice, who="Вы", text=text)
            t.join(30)
            results.append(out)
            if out.get("decision") == "allow":
                print(f"{C['ok']}✅ Безопасно — выполнено без вопросов{C['x']}")
            else:
                print(f"{C['no']}⛔ Не выполнено.{C['x']} Агент получает: {str(out.get('reason', ''))[:220]}")

    passed = sum(r.get("decision") == "allow" for r in results)
    ok = passed == 2 and len(results) == len(g.DEMO) and any(NOTE in str(r.get("reason", "")) for r in results)
    print(f"\n{C['b']}Итог:{C['x']} {passed} действия прошли сами, {len(results) - passed} остановлены, опасное не выполнилось."
          + ("" if ok else f" {C['no']}Сценарий отработал не так, как ожидалось.{C['x']}"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
