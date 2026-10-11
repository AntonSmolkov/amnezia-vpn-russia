# Гайд мейнтейнера

Как устроена автоматизация, что один раз настроить на GitHub и как с этим жить дальше.

## Как всё работает

```
Заявка «Добавить сайт в список» ──► submission.yml ──► проверка автора ──► проверка доменов ──► PR от бота
                                                         │ не прошёл          │ ошибки / всё уже покрыто
                                                         ▼                    ▼
                                                  комментарий + закрыть   комментарий + needs-changes
                                                                          (автор правит заявку → перепроверка)
                                                                          или already-covered + закрыть

Любой PR ──► update-list.yml / «Проверка»: тесты, проверка новых доменов, пробная сборка
Мерж в main ──► update-list.yml / «Сборка»: пересобирает tunneling-list.json и коммитит его
Каждый понедельник ──► update-list.yml / «Сборка»: обновляет IP-адреса, отчёт о мёртвых доменах в Summary
```

Проверки домена (`scripts/domain_checks.py`):

| Проверка | Если не прошла |
| :--- | :--- |
| Корректное имя, ещё нет в `sources/domains.txt` | отказ |
| Не заблокирован в РФ (реестр РКН, antifilter.download) | отказ: мимо VPN он не откроется |
| Есть A-записи | отказ: домен не существует или заброшен |
| Есть российские IP (российский блок, российский ASN или DDoS-Guard/Qrator/StormWall) | отказ: сайт только на Cloudflare/AWS и т.п. |
| Все российские IP уже покрыты `ru-subnets.txt` | не ошибка: «уже идёт мимо VPN», заявка закрывается с советами |
| Есть в списке itdog «из РФ нужен VPN» или реестр РКН недоступен | не ошибка: PR получает метку `needs-manual-review` |

Проверка автора (`scripts/trust.py`, пороги в `.github/submission-policy.toml`):
- аккаунту не меньше 14 дней (кроме тех, у кого уже есть смёрженный PR здесь);
- не больше 2 открытых заявок и 5 заявок за 30 дней;
- не в `blocked_users`;
- мейнтейнеры (владелец и коллабораторы с правом записи) проходят без проверок.

| Файл | Зачем |
| :--- | :--- |
| `.github/ISSUE_TEMPLATE/add-domain.yml` | Форма заявки. Категории должны совпадать с заголовками в `sources/domains.txt` — это проверяет тест |
| `.github/submission-policy.toml` | Пороги, лимиты, блок-листы |
| `.github/workflows/submission.yml` | Запуск бота на событиях issues |
| `.github/workflows/update-list.yml` | Проверка PR, сборка и еженедельное обновление списка |
| `scripts/submission.py` | Заявка → проверки → PR |
| `scripts/domain_checks.py` | Проверки доменов (бот и CI) |
| `scripts/trust.py` | Проверка автора заявки |
| `scripts/build.py` | Сборка `tunneling-list.json` |

---

## Разовая настройка

Всё ниже делается в репозитории `kozlovartem20201/amnezia-vpn-russia` на github.com. Сначала запушьте изменения в `main`: бот на событиях issues всегда берёт workflow из ветки по умолчанию.

### Шаг 1. Метки — обязательно

GitHub **молча выбрасывает** метки формы, которых нет в репозитории, а бот реагирует только на issue с меткой `submission`. Без этого шага бот не запустится ни разу.

Проще всего через [GitHub CLI](https://cli.github.com/) (после `gh auth login`):

```bash
R=kozlovartem20201/amnezia-vpn-russia
gh label create submission          -R $R -c 0E8A16 -d "Заявка на добавление сайта (обрабатывает бот)"
gh label create maintainer-approved -R $R -c 5319E7 -d "Мейнтейнер снял проверки автора — бот перепроверит заявку"
gh label create needs-changes       -R $R -c FBCA04 -d "Бот нашёл проблемы, автор должен поправить заявку"
gh label create pr-opened           -R $R -c 1D76DB -d "Бот открыл pull request"
gh label create already-covered     -R $R -c C2E0C6 -d "Сайт уже идёт мимо VPN"
gh label create trust-check-failed  -R $R -c B60205 -d "Автор не прошёл проверки"
gh label create needs-manual-review -R $R -c D93F0B -d "Нужна внимательная ручная проверка"
gh label create new-domains         -R $R -c 0E8A16 -d "PR бота с новыми доменами"
gh label create site-problem        -R $R -c D73A4A -d "Сайт из списка не работает"
```

Или вручную: **Issues → Labels → New label**, те же имена.

### Шаг 2. Настройки Actions

**Settings → Actions → General:**

1. **Actions permissions:** «Allow all actions and reusable workflows» (или разрешите `actions/*`).
2. **Fork pull request workflows from outside collaborators:** «Require approval for all external contributors». Чужие PR не будут запускать CI без вашего одобрения.
3. **Workflow permissions:** «Read repository contents and packages permissions». Нужные права workflow запрашивают сами в блоке `permissions:`.
4. **«Allow GitHub Actions to create and approve pull requests»:**
   - **включите**, если пропускаете шаг 3 (без GitHub App бот открывает PR от имени `github-actions`);
   - **выключите**, если настроили GitHub App.

### Шаг 3. GitHub App для бота — рекомендуется

Без App бот тоже работает, но у GitHub есть ограничение: PR, открытые через `GITHUB_TOKEN`, **не запускают CI**. Проверка «Проверка» на них не появится; запустить её можно, закрыв и сразу открыв PR. С App всё работает как в trading-awesome: PR от бота сразу проверяются CI.

Приложение из trading-awesome принадлежит аккаунту `lentrade` и установлено только туда, поэтому для этого репозитория нужно отдельное, на аккаунте `kozlovartem20201`.

1. Войдите в GitHub под `kozlovartem20201`. **Settings (профиля) → Developer settings → GitHub Apps → New GitHub App.**
2. **GitHub App name:** например `amnezia-vpn-russia-bot`. **Homepage URL:** адрес репозитория.
3. **Webhook:** снимите галочку **Active**.
4. **Repository permissions:**
   - Contents: **Read and write**
   - Issues: **Read and write**
   - Pull requests: **Read and write**
   - Metadata: Read-only (ставится автоматически)
5. **Where can this GitHub App be installed?** — **Only on this account.**
6. **Create GitHub App**. На странице приложения:
   - скопируйте **Client ID**;
   - внизу **Private keys → Generate a private key** — скачается файл `.pem`.
7. Слева **Install App → Install** → **Only select repositories** → `amnezia-vpn-russia`.
8. В репозитории: **Settings → Secrets and variables → Actions**:
   - вкладка **Secrets → New repository secret**: имя `BOT_PRIVATE_KEY`, значение — всё содержимое `.pem`, включая строки `-----BEGIN…` и `-----END…`;
   - вкладка **Variables → New repository variable**: имя `BOT_CLIENT_ID`, значение — Client ID.
9. Удалите `.pem` с компьютера.

Workflow сами увидят `BOT_CLIENT_ID` и переключатся на App. Секреты не передаются в workflow из чужих форков.

### Шаг 4. Защита ветки main — по желанию

Сначала убедитесь, что App работает (шаг 6), и что проверка `Проверка` хотя бы раз запускалась на каком-нибудь PR: иначе её не найти в поиске при настройке правил.

**Settings → Rules → Rulesets → New ruleset → New branch ruleset:**

- **Ruleset Name:** `main`, **Enforcement status:** Active;
- **Bypass list:**
  - ваше GitHub App — режим **Always**: иначе еженедельная сборка не сможет закоммитить `tunneling-list.json`;
  - роль **Repository admin** — режим **Always**, если вы и дальше пушите в `main` напрямую, или **For pull requests only**, если хотите всё вести через PR;
- **Target branches:** Add target → **Include default branch**;
- **Restrict deletions** и **Block force pushes**;
- **Require a pull request before merging**: 1 approval, **Dismiss stale pull request approvals when new commits are pushed**, **Require review from Code Owners** (файл `.github/CODEOWNERS` уже есть);
- **Require status checks to pass**: `Проверка`; «Require branches to be up to date» не включайте — PR бота устаревают после каждого автообновления списка.

> ⚠️ Не включайте «Require a pull request» и «Require status checks» без GitHub App из шага 3: `GITHUB_TOKEN` не может обходить правила, и автообновление списка перестанет коммитить.

### Шаг 5. Прочие настройки

- **Settings → General → Pull Requests:** включите **Automatically delete head branches** — ветки `submission/issue-N` будут удаляться после мержа.
- **Settings → Advanced Security (Code security):** включите **Dependabot alerts**, **Secret scanning** и **Push protection**. Dependabot раз в неделю предлагает обновить закреплённые версии actions (`.github/dependabot.yml`).
- **Главная страница репозитория → шестерёнка About:** темы `amnezia`, `amneziawg`, `split-tunneling`, `vpn`, `russia`, `roskomnadzor`.

### Шаг 6. Проверка, что всё работает

1. **Actions → Обновление списка → Run workflow** — сборка должна пройти зелёной, отчёт появится в Summary.
2. **Issues → New issue → «Добавить сайт в список»**, домен `e-disclosure.ru`, любая категория. Через 1–2 минуты бот оставит комментарий с таблицей и откроет PR `Добавить сайт: e-disclosure.ru`. Если не нужен — закройте PR и issue.
3. Ещё одна тестовая заявка с `meduza.io`: бот должен ответить «заблокирован в РФ» и поставить `needs-changes`.

Если бот молчит, смотрите раздел «Если что-то не так».

---

## Повседневная работа

**PR от бота.** Проверьте категорию и раздел «Требует внимания»: метка `needs-manual-review` ставится на молодые аккаунты и на домены из списка itdog «из РФ нужен VPN» (часто это зарубежные сервисы, которым в списке не место). Мелочи можно поправить прямо в PR. После мержа список пересоберётся сам, а issue закроется.

**Одобрить заявку вручную.** Если честный автор не прошёл проверку (например, свежий аккаунт), поставьте на issue метку `maintainer-approved`. Бот переоткроет заявку и проверит домены без проверок автора. Метка учитывается, только если её поставил человек с правом записи.

**Блокировка спама.** Добавьте логин в `blocked_users` или домен в `blocked_domains` в `.github/submission-policy.toml`. Там же меняются пороги.

**Еженедельный отчёт.** **Actions → Обновление списка → последний запуск → Summary.** В нём домены, которые умерли (удалите их из `sources/domains.txt`) и которые переехали на зарубежные CDN (они автоматически выпадают из списка).

**Правки руками.** Можно по-прежнему коммитить в `sources/` напрямую или через PR — CI проверит новые домены теми же правилами, что и бот. `tunneling-list.json` руками не правьте: его перезапишет сборка.

## Запуск локально

```bash
python -m unittest discover -s tests                     # тесты, без сети
python scripts/domain_checks.py example.ru other.ru       # проверить домены
python scripts/build.py --report build-report.md          # собрать список
python scripts/submission.py --event event.json --dry-run # прогнать бота на сохранённом событии issues
```

## Если что-то не так

| Симптом | Причина и решение |
| :--- | :--- |
| Бот не реагирует на заявку | Нет метки `submission` в репозитории (шаг 1) — создайте её и поставьте на issue руками. Либо изменения ещё не в `main`. Либо Actions выключены |
| `Resource not accessible by integration` при создании PR | Без App: не включено «Allow GitHub Actions to create and approve pull requests» (шаг 2.4) |
| На PR бота нет проверки «Проверка» | PR открыт через `GITHUB_TOKEN`. Закройте и откройте PR или настройте App (шаг 3) |
| Сборка падает на `git push` | `main` защищён правилами, а App не в списке исключений или не настроено (шаг 4) |
| Ошибка создания токена App | Неверный `BOT_CLIENT_ID`, ключ вставлен не целиком или App не установлено в репозиторий |
| «Реестр блокировок РКН был недоступен» | antifilter.download не ответил. Заявка проходит с меткой `needs-manual-review` — проверьте домен сами |
