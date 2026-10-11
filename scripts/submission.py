#!/usr/bin/env python3
"""Бот заявок: issue-форма «Добавить сайт в список» → проверки → pull request.

Запускается из .github/workflows/submission.yml на событиях issues. Текст
issue — недоверенные данные: он разбирается здесь, в Python, и никогда не
попадает в shell.

Порядок:
  1. Проверка автора: возраст аккаунта, лимиты, блок-лист (.github/submission-policy.toml).
  2. Проверка формы: домены, категория, подтверждения.
  3. Проверка каждого домена (scripts/domain_checks.py): существует, не дубликат,
     не заблокирован в РФ, имеет российские IP, ещё не покрыт списком.
  4. Подходящие домены дописываются в нужную категорию sources/domains.txt
     в ветке submission/issue-<N>, и открывается (или обновляется) pull request.
     Мерджит всегда человек; после мержа список пересобирает update-list.yml.

Окружение: GITHUB_EVENT_PATH, GITHUB_REPOSITORY, GH_TOKEN.
Локальный прогон без записи в GitHub (сетевые проверки доменов выполняются):
    python scripts/submission.py --event event.json --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import build
from domain_checks import Checker, DomainCheck, normalize, read_published, report, split_domains
from domains_file import categories, insert_domains
from github_api import GitHub, GitHubError, neutralize
from trust import TrustResult, assess, label_applied_by_maintainer

TEMPLATE = build.ROOT / ".github" / "ISSUE_TEMPLATE" / "add-domain.yml"
POLICY = build.ROOT / ".github" / "submission-policy.toml"
DOMAINS_PATH = "sources/domains.txt"
MARKER = "<!-- amnezia-vpn-russia-bot:submission -->"
SUBMISSION_LABEL = "submission"
OVERRIDE_LABEL = "maintainer-approved"

# Поля формы add-domain.yml в порядке следования: id → label (тест сверяет с шаблоном).
FIELDS = {
    "domains": "Домены",
    "category": "Категория",
    "problem": "Что не работает через VPN",
    "confirmations": "Подтверждения",
}
CONFIRMATIONS = [
    "Это российский сайт или сервис",
    "Без VPN этот сайт открывается — он не заблокирован в России",
]
NO_RESPONSE = "_No response_"
CHECKBOX_RE = re.compile(r"^- \[([ xX])\] (.+)$")
README_URL = "https://github.com/kozlovartem20201/amnezia-vpn-russia#readme"


# ---------------------------------------------------------------- форма

def parse_form(body: str) -> dict:
    """Разбирает Markdown, который GitHub генерирует из issue-формы.

    Заголовки «### Поле» принимаются один раз и только в порядке шаблона,
    поэтому строка «### Домены» внутри ответа не перезапишет поле.
    """
    order = list(FIELDS.values())
    sections: dict[str, list[str]] = {}
    current, position = None, -1
    for line in (body or "").replace("\r\n", "\n").split("\n"):
        m = re.match(r"^### (.+?)\s*$", line)
        if m and m.group(1) in order and order.index(m.group(1)) > position:
            current, position = m.group(1), order.index(m.group(1))
            sections[current] = []
        elif current is not None:
            sections[current].append(line)

    values: dict[str, object] = {}
    for fid, label in FIELDS.items():
        raw = "\n".join(sections.get(label, [])).strip()
        values[fid] = "" if raw == NO_RESPONSE else raw
    checked = {}
    for line in str(values["confirmations"]).split("\n"):
        m = CHECKBOX_RE.match(line.strip())
        if m:
            checked[m.group(2).strip()] = m.group(1).lower() == "x"
    values["confirmations"] = {opt: checked.get(opt, False) for opt in CONFIRMATIONS}
    return values


def load_policy() -> dict:
    with open(POLICY, "rb") as f:
        return tomllib.load(f)


def blocked_by_policy(domain: str, policy: dict) -> bool:
    blocked = {d.lower() for d in policy.get("blocked_domains", [])}
    labels = domain.split(".")
    return any(".".join(labels[i:]) in blocked for i in range(len(labels) - 1))


@dataclass
class Outcome:
    category: str = ""
    errors: list[str] = field(default_factory=list)
    checks: list[DomainCheck] = field(default_factory=list)

    @property
    def accepted(self) -> list[DomainCheck]:
        return [c for c in self.checks if c.accepted]

    @property
    def covered(self) -> list[DomainCheck]:
        return [c for c in self.checks if c.ok and c.covered]

    @property
    def rejected(self) -> list[DomainCheck]:
        return [c for c in self.checks if not c.ok]


def evaluate(form: dict, policy: dict, domains_text: str, make_checker: Callable[[], Callable]) -> Outcome:
    out = Outcome(category=str(form["category"]))
    raws, seen = [], set()
    for raw in split_domains(str(form["domains"])):
        key = normalize(raw) or raw
        if key not in seen:
            seen.add(key)
            raws.append(raw)

    max_domains = int(policy.get("max_domains_per_issue", 10))
    if not raws:
        out.errors.append("**Домены**: укажите хотя бы один домен.")
    elif len(raws) > max_domains:
        out.errors.append(f"**Домены**: не больше {max_domains} в одной заявке, сейчас {len(raws)}.")
    if out.category not in categories(domains_text):
        out.errors.append("**Категория** должна быть одной из предложенных.")
    if not str(form["problem"]).strip():
        out.errors.append("**Что не работает через VPN**: опишите, что происходит.")
    if not all(form["confirmations"].values()):
        out.errors.append("Отметьте оба пункта в **Подтверждениях**.")
    if out.errors:
        return out

    out.checks = make_checker()(raws)
    for c in out.checks:
        if c.ok and blocked_by_policy(c.domain, policy):
            c.errors.append("этот домен нельзя добавлять в список")
    return out


# ---------------------------------------------------------------- тексты

def trust_failure_comment(trust: TrustResult) -> str:
    reasons = "\n".join(f"- {r}" for r in trust.errors)
    return ("### Заявка не принята\n\n"
            f"{reasons}\n\n"
            "Эти правила защищают список от спама. Если это ошибка, напишите ниже — "
            "мейнтейнер может одобрить заявку вручную.")


def problems_comment(out: Outcome) -> str:
    lines = ["### Нужно исправить", ""]
    lines += [f"- {e}" for e in out.errors]
    if out.checks:
        lines += ["Ни один домен не прошёл проверку:", "", report(out.checks)]
    lines += ["", "Отредактируйте заявку — проверка запустится заново автоматически."]
    return "\n".join(lines)


def covered_comment(out: Outcome) -> str:
    return "\n".join([
        "### Эти сайты уже идут мимо VPN",
        "",
        report(out.checks),
        "",
        "Все их адреса уже есть в списке, поэтому добавлять нечего. Что можно сделать:",
        "1. Скачайте **свежий** `tunneling-list.json` и импортируйте его через «Заменить список с сайтами» "
        "при отключённом VPN.",
        "2. Проверьте на https://yandex.ru/internet, что с включённым VPN виден IP вашего провайдера.",
        "3. Если это мобильное приложение, оно может определять сам факт включённого VPN — тогда поможет "
        f"раздельное туннелирование приложений (см. [README]({README_URL})).",
        "",
        "Если ничего не помогло, создайте issue «Сайт из списка не работает».",
    ])


def success_comment(out: Outcome, pull_number: int) -> str:
    lines = [f"### Проверки пройдены — pull request #{pull_number}", "", report(out.checks), ""]
    if out.rejected or out.covered:
        lines.append("В pull request попали только домены с ✅. Отредактируйте заявку, чтобы исправить остальные.")
        lines.append("")
    lines.append("Мейнтейнер посмотрит его в ближайшее время. Правки этой заявки обновляют pull request.")
    return "\n".join(lines)


def pr_body(out: Outcome, issue_number: int, author: str, trust: TrustResult) -> str:
    lines = [
        f"Добавляет в категорию «{neutralize(out.category)}» домены из заявки #{issue_number} (@{author}).",
        "",
        report(out.accepted),
        "",
        "#### Автоматические проверки",
        "",
        "- Автор заявки: " + ("мейнтейнер" if trust.maintainer else
                              "проверки сняты мейнтейнером" if any("мейнтейнер" in f for f in trust.flags) else
                              "пройдено"),
        "- Имя, дубликаты, реестр РКН, DNS, российские IP: пройдено",
    ]
    review = [f"`{c.domain}`: {'; '.join(c.notes)}" for c in out.accepted if c.needs_review]
    review += [f"Автор: {f}" for f in trust.flags]
    if review:
        lines += ["", "#### Требует внимания", "", *[f"- {neutralize(r)}" for r in review]]
    if trust.facts:
        lines += ["", "<details><summary>Об авторе</summary>", ""]
        lines += [f"- {k}: {v}" for k, v in trust.facts.items()]
        lines += ["", "</details>"]
    lines += ["", "После мержа GitHub Actions пересоберёт `tunneling-list.json`.", "", f"Closes #{issue_number}"]
    return "\n".join(lines)


# ---------------------------------------------------------------- GitHub

def branch_for(issue_number: int) -> str:
    return f"submission/issue-{issue_number}"


def close_stale_pull(gh: GitHub, issue_number: int) -> None:
    pull = gh.open_pull_for(branch_for(issue_number))
    if pull:
        gh.close_pull(pull["number"])


def open_pull_request(gh: GitHub, out: Outcome, issue: dict, trust: TrustResult, base: str) -> dict:
    number, author = issue["number"], issue["user"]["login"]
    domains = [c.domain for c in out.accepted]
    branch = branch_for(number)
    base_sha = gh.branch_sha(base)
    text = gh.file_at(DOMAINS_PATH, base_sha)
    if text is None:
        raise GitHubError(404, f"{DOMAINS_PATH} не найден в {base}")
    new_text = insert_domains(text, out.category, domains, f"issue #{number}")
    title = "Добавить сайт: " + ", ".join(domains[:3]) + (" и др." if len(domains) > 3 else "")
    message = (f"{title}\n\nЗаявка #{number}.\n\n"
               f"Co-authored-by: {author} <{issue['user']['id']}+{author}@users.noreply.github.com>")
    gh.commit_files(branch, base_sha, {DOMAINS_PATH: new_text}, message, create=gh.branch_sha(branch) is None)
    body = pr_body(out, number, author, trust)
    pull = gh.open_pull_for(branch)
    if pull:
        gh.update_pull(pull["number"], title, body)
    else:
        pull = gh.create_pull(branch, base, title, body)
    labels = ["new-domains"]
    if trust.flags or any(c.needs_review for c in out.accepted):
        labels.append("needs-manual-review")
    gh.add_labels(pull["number"], labels)
    return pull


def run(event: dict, gh: GitHub | None, *, dry_run: bool, make_checker: Callable[[], Callable]) -> int:
    issue = event.get("issue") or {}
    if "pull_request" in issue:
        return 0
    labels = {label["name"] for label in issue.get("labels", [])}
    if SUBMISSION_LABEL not in labels:
        print("Это не заявка; пропускаю.")
        return 0
    action = event.get("action")
    if action == "labeled" and (event.get("label") or {}).get("name") != OVERRIDE_LABEL:
        return 0

    number, author = issue["number"], issue["user"]["login"]
    policy = load_policy()
    override = OVERRIDE_LABEL in labels and gh is not None and label_applied_by_maintainer(gh, number, OVERRIDE_LABEL)
    if issue.get("state") == "closed":
        if not (action == "labeled" and override):
            print("Issue закрыт; пропускаю.")
            return 0
        if not dry_run:
            gh.set_state(number, "open")

    if override:
        trust = TrustResult(login=author, flags=["проверки автора сняты мейнтейнером"])
    elif gh is None:
        trust = TrustResult(login=author, flags=["локальный прогон: проверки автора пропущены"])
    else:
        trust = assess(gh, policy, author, issue.get("author_association", "NONE"), exclude_issue=number)
    if not trust.ok:
        print("Проверка автора не пройдена:", *trust.errors, sep="\n- ")
        if not dry_run:
            gh.upsert_comment(number, MARKER, trust_failure_comment(trust))
            gh.add_labels(number, ["trust-check-failed"])
            gh.set_state(number, "closed", "not_planned")
        return 0

    domains_text = (build.ROOT / DOMAINS_PATH).read_text(encoding="utf-8")
    out = evaluate(parse_form(issue.get("body") or ""), policy, domains_text, make_checker)

    if out.errors or not out.accepted:
        all_covered = not out.errors and out.covered and not out.rejected
        comment = covered_comment(out) if all_covered else problems_comment(out)
        print(comment)
        if not dry_run:
            close_stale_pull(gh, number)
            gh.upsert_comment(number, MARKER, comment)
            gh.remove_label(number, "pr-opened")
            if all_covered:
                gh.add_labels(number, ["already-covered"])
                gh.set_state(number, "closed", "completed")
            else:
                gh.add_labels(number, ["needs-changes"])
        return 0

    print("Проверки пройдены:\n" + report(out.checks))
    if dry_run:
        print(pr_body(out, number, author, trust))
        return 0
    base = (event.get("repository") or {}).get("default_branch", "main")
    pull = open_pull_request(gh, out, issue, trust, base)
    gh.remove_label(number, "needs-changes")
    gh.add_labels(number, ["pr-opened"])
    gh.upsert_comment(number, MARKER, success_comment(out, pull["number"]))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--event", default=os.environ.get("GITHUB_EVENT_PATH"), help="путь к JSON события")
    parser.add_argument("--dry-run", action="store_true", help="ничего не писать в GitHub")
    args = parser.parse_args()
    if not args.event:
        parser.error("нужен --event или GITHUB_EVENT_PATH")
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    gh = None if args.dry_run else GitHub(os.environ.get("GITHUB_REPOSITORY", "kozlovartem20201/amnezia-vpn-russia"))

    def make_checker() -> Checker:
        existing = set(build.load_domains(build.SOURCES / "domains.txt"))
        return Checker(existing, read_published())

    try:
        return run(event, gh, dry_run=args.dry_run, make_checker=make_checker)
    except GitHubError as exc:
        print(f"Ошибка GitHub API: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
