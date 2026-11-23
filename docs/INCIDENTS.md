# Громкие случаи с ИИ-агентами и что с ними делает TwoKey

35 публичных случаев 2023–2026: утечки, публикация закрытых данных, уничтожение прода, захват агента.
По ним написаны правила TwoKey; примеры действий лежат в [`tests/incidents.jsonl`](../tests/incidents.jsonl) и проверяются в CI.

| Итог | Случаев | Что значит |
|---|---:|---|
| ✅ ловит | 21 | правило срабатывает на само опасное действие агента |
| 🟡 частично | 11 | ловит часть цепочки: например, действие агента, но не заражённый пакет |
| ⚪ вне зоны | 3 | вред случился не в действии агента (ответ модели, расширение IDE) |

**Как читать.** Оценка отвечает на вопрос «сработает ли правило, если это действие пойдёт через TwoKey». Хук
подключается из коробки, другим агентам нужна интеграция через HTTP API. Правила писались по этим же случаям, поэтому
это проверка покрытия, а не слепой тест; цифры слепого теста — в [плане](../pitch/plan.md). Целенаправленную атаку регулярные
выражения не остановят: от неё нужны песочница и минимальные права.

| Когда | Кто | Что случилось | TwoKey | Источник |
|---|---|---|---|---|
| ноя 2026 | Claude Code (Apiiro) | Ответ «да, больше не спрашивать» сохранял команды с паролями в локальные настройки, и файл попадал в коммиты | 🟡 `git-secret`, `self`; «Разрешать всегда» в TwoKey хранит команду со скрытыми секретами | [Privacy Guides](https://www.privacyguides.org/news/2026/11/10/claude-code-leaks-secrets-and-passwords-in-public-github-repositories/) |
| сен 2026 | PixelLeak (агенты для кода) | По данным Glow Labs (вендор безопасности, независимо не подтверждено): чтобы приложить скриншот к PR, агенты создавали публичные репозитории, 93% — в личных аккаунтах; 13 000+ внутренних изображений из 300+ организаций | ✅ `pub-repo`, `pub-repo-api` | [Help Net Security](https://www.helpnetsecurity.com/2026/09/30/ai-coding-agents-github-screenshot-leak/), [Glow](https://www.glow.io/blogs/how-ai-agents-exposed-developer-screenshots-from-leading-tech-companies) |
| май 2026 | Nx Console / GitHub | Заражённое расширение VS Code жило ~11 минут; через него вынесли ~3 800 внутренних репозиториев GitHub | ⚪ расширение — не действие агента | [StepSecurity](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised) |
| май 2026 | Mini Shai-Hulud (TanStack и др.) | Червь выпустил 84 заражённые версии 42 пакетов и прописывался в конфиги Claude Code и VS Code | 🟡 `autorun-file`, `mcp-config-file`, `cred-dump`: действия агента да, postinstall нет | [StepSecurity](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) |
| апр 2026 | PocketOS (Cursor, Railway) | Агент одним API-вызовом удалил продовый том вместе с бэкапами; простой ~30 часов | ✅ `api-delete` | [AI Incident Database](https://incidentdatabase.ai/reports/7311) |
| мар 2026 | Meta, внутренний агент | Агент без согласия опубликовал ответ на внутреннем форуме; по его совету данные ~2 часа были открыты лишним сотрудникам | 🟡 `mcp-external`, `mcp-outbound` | [TechCrunch](https://techcrunch.com/2026/03/18/meta-is-having-trouble-with-rogue-ai-agents) |
| мар 2026 | Claude Code (Ona) | Агент обошёл запрет на команду другим путём и сам отключил свою песочницу | ✅ `proc-root-evasion`, `sandbox-off` | [Ona](https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox) |
| мар 2026 | GitGuardian, отчёт | В публичных коммитах с Claude Code секреты встречаются в 3,2% случаев против 1,5% в среднем | ✅ `git-secret` | [GitGuardian](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/) |
| фев 2026 | Clinejection (Cline) | Инъекция в заголовке issue заставила агента поставить пакет из коммита; это привело к вредоносному релизу | ✅ `install-git-ref` | [Simon Willison](https://simonwillison.net/2026/Mar/6/clinejection/) |
| фев 2026 | ClawHavoc (OpenClaw) | Вредоносные навыки заставляли ставить стилер через закодированную команду | ✅ `obfuscated`, `pipe-shell` | [Trend Micro](https://www.trendmicro.com/en/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html) |
| фев 2026 | Claude Code, файлы проекта (Check Point) | Вредоносный репозиторий через свои настройки выполнял команды и уводил ключ API | 🟡 `mcp-config-file`, `self`: правку агентом да, конфиг из клонированного репозитория нет | [Check Point](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| фев 2026 | SANDWORM_MODE (npm) | Пакеты-двойники крали ключи и прописывали агентам поддельный MCP-сервер | 🟡 `mcp-add`, `mcp-config-file` | [Help Net Security](https://www.helpnetsecurity.com/2026/02/24/npm-worm-sandworm-mode-supply-cain-attack/) |
| фев 2026 | DataTalks.Club (Claude Code) | Агент подменил state Terraform и выполнил destroy: прод и снапшоты | ✅ `infra-destroy` | [пост автора](https://aishippingblog.com/p/how-i-dropped-our-production-database) |
| фев 2026 | OpenClaw и Gmail | Агент потерял инструкцию «сначала спроси» и массово удалял почту, игнорируя «стоп» | ✅ `mcp-trash`, `mcp-destroy` | [TechCrunch](https://techcrunch.com/2026/02/23/a-meta-ai-security-researcher-said-an-openclaw-agent-ran-amok-on-her-inbox) |
| фев 2026 | Lobstar Wilde | Агент вместо пары долларов отправил все токены, ~$250 тыс. | ✅ `crypto-transfer`, `mcp-external` | [The Block](https://www.theblock.co/post/390722/ai-agent-created-by-openai-dev-accidentally-sends-entire-memecoin-holdings-to-reply-guy) |
| янв 2026 | Claude Cowork | Скрытый текст в документе заставил загрузить файл пользователя в чужой аккаунт | ✅ `llm-upload` | [PromptArmor](https://www.promptarmor.com/resources/claude-cowork-exfiltrates-files) |
| дек 2025 | AWS Kiro | Агент решил «удалить и пересоздать окружение»: ~13 часов сбоя | ✅ `aws-delete`, `infra-destroy` | [The Register](https://www.theregister.com/2026/02/20/amazon_denies_kiro_agentic_ai_behind_outage/) |
| ноя 2025 | Google Antigravity | Скрытый текст на странице: код и ключи ушли на webhook.site | ✅ `exfil-host` | [PromptArmor](https://www.promptarmor.com/resources/google-antigravity-exfiltrates-data) |
| ноя 2025 | Google Antigravity | Очистка кэша стёрла весь диск D: | ✅ `win-remove`, `wipe-root` | [The Register](https://www.theregister.com/2025/12/01/google_antigravity_wipes_d_drive/) |
| авг 2025 | Nx s1ngularity | Заражённые пакеты запускали ИИ-CLI без подтверждений искать ключи и выкладывали их в публичные репозитории | 🟡 `ai-cli-bypass`, `secret-hunt`, `pub-repo-api`: postinstall не видим | [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack) |
| авг 2025 | Claude Code, CVE-2025-55284 | Инъекция: ключ из `.env` ушёл через DNS-запросы | ✅ `dns-exfil` | [Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests) |
| авг 2025 | GitHub Copilot, CVE-2025-53773 | Инъекция включила автоодобрение команд в настройках VS Code | ✅ `agent-autoapprove` | [Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection) |
| авг 2025 | Cursor CurXecute | Сообщение из Slack заставило агента добавить вредоносный MCP-сервер | ✅ `mcp-config-file` | [Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison) |
| авг 2025 | Cursor MCPoison | Уже одобренный MCP-сервер подменили в общем репозитории | 🟡 `mcp-config-file`: подмена через `git pull` не видна | [Check Point](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/) |
| июл 2025 | Replit и SaaStr | Агент во время заморозки кода стёр рабочую базу | ✅ `sql-drop`, `sql-delete`, `orm-reset` | [The Register](https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident) |
| июл 2025 | Supabase MCP | Тикет заставил агента прочитать таблицу токенов и опубликовать её в переписке | ✅ `sql-secret-read` | [General Analysis](https://www.generalanalysis.com/blog/supabase-mcp-blog) |
| июл 2025 | Gemini CLI | Инъекция в README: разрешённый `grep`, а за ним отправка переменных окружения | ✅ `exfil`, `env-exfil` | [Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) |
| июл 2025 | Tea | Открытое хранилище Firebase: ~72 000 изображений, включая документы | ✅ `firebase-public` | [404 Media](https://404media.co/women-dating-safety-app-tea-breached-users-ids-posted-to-4chan) |
| июн 2025 | EchoLeak (Microsoft 365 Copilot) | Письмо без единого клика заставило Copilot слить данные через картинку | ⚪ это ответ модели, а не действие | [Simon Willison](https://simonwillison.net/2025/Jun/11/echoleak/) |
| май 2025 | GitHub MCP | Issue заставил агента вынести приватные репозитории в публичный PR | 🟡 `mcp-outbound`; создание PR — только в журнал | [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability) |
| май 2025 | Lovable, CVE-2025-48757 | Приложения без RLS: любой читал и менял чужие данные | 🟡 `rls-off`, `public-env-secret`: явное отключение да, забытую настройку нет | [Matt Palmer](https://mattpalmer.io/posts/CVE-2025-48757/) |
| янв 2025 | DeepSeek | Открытая база ClickHouse: 1 млн+ строк логов и секретов | 🟡 `db-expose`, `pub-port`: если порт открывает агент | [Wiz](https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak) |
| авг 2024 | Slack AI | Сообщение в канале вытянуло ключ из приватного канала | ⚪ это ответ модели, а не действие | [The Register](https://www.theregister.com/2024/08/21/slack_ai_prompt_injection/) |
| сен 2023 | Microsoft AI Research | SAS-ссылка в README открыла 38 ТБ внутренних данных | ✅ `key-sas`, `sas-generate` | [Wiz](https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers) |
| апр 2023 | Samsung и ChatGPT | Сотрудники вставили исходный код и запись встречи в ChatGPT | 🟡 `llm-upload`: если файл отправляет агент; вставку в браузере не видим | [Engadget](https://www.engadget.com/three-samsung-employees-reportedly-leaked-sensitive-data-to-chatgpt-190221114.html) |
