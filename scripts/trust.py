"""Проверка автора заявки.

Жёсткие ошибки (errors) останавливают бота. Мягкие сигналы (flags) пропускают
заявку, но помечают PR для внимательной ручной проверки.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from github_api import GitHub

MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
MAINTAINER_ROLES = {"admin", "maintain", "write"}


@dataclass
class TrustResult:
    login: str
    maintainer: bool = False
    errors: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    facts: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors


def assess(gh: GitHub, policy: dict, login: str, association: str, *,
           exclude_issue: int | None = None, now: dt.datetime | None = None) -> TrustResult:
    now = now or dt.datetime.now(dt.timezone.utc)
    result = TrustResult(login=login)

    if login.lower() in {u.lower() for u in policy.get("blocked_users", [])}:
        result.errors.append("Этому аккаунту запрещено присылать заявки.")
        return result

    if association in MAINTAINER_ASSOCIATIONS or gh.permission(login) in MAINTAINER_ROLES:
        result.maintainer = True
        return result

    user = gh.user(login)
    if user.get("type") != "User":
        result.errors.append("Заявки принимаются только от личных аккаунтов GitHub, не от ботов и организаций.")
        return result

    created = dt.datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
    age = (now - created).days
    repos = int(user.get("public_repos", 0))
    result.facts.update({"аккаунт создан": created.date().isoformat(), "публичных репозиториев": repos})

    merged, _ = gh.search_count(f"repo:{gh.repo} is:pr is:merged author:{login}")
    result.facts["смёржено PR здесь"] = merged

    min_age = int(policy.get("min_account_age_days", 14))
    if merged == 0 and age < min_age:
        allowed_from = (created + dt.timedelta(days=min_age)).date().isoformat()
        result.errors.append(
            f"Вашему аккаунту GitHub {age} дн., а заявки принимаются от аккаунтов старше {min_age} дн. "
            f"Попробуйте снова с {allowed_from} или дождитесь, пока заявку одобрит мейнтейнер.")

    _, open_items = gh.search_count(f"repo:{gh.repo} is:issue is:open label:submission author:{login}")
    open_others = [i for i in open_items if i.get("number") != exclude_issue]
    max_open = int(policy.get("max_open_submissions", 2))
    if len(open_others) >= max_open:
        refs = ", ".join(f"#{i['number']}" for i in open_others[:5])
        result.errors.append(f"У вас уже {len(open_others)} открытых заявок ({refs}). "
                             f"Дождитесь, пока их рассмотрят.")
    since = (now - dt.timedelta(days=30)).date().isoformat()
    recent, _ = gh.search_count(f"repo:{gh.repo} is:issue label:submission author:{login} created:>={since}")
    max_recent = int(policy.get("max_submissions_per_30_days", 5))
    if recent > max_recent:
        result.errors.append(f"За последние 30 дней вы прислали {recent} заявок (лимит {max_recent}).")

    if age < int(policy.get("young_account_days", 60)) and repos == 0:
        result.flags.append("молодой аккаунт без публичных репозиториев")
    return result


def label_applied_by_maintainer(gh: GitHub, issue_number: int, label: str) -> bool:
    """True, если последней метку поставил человек с правом записи."""
    actor = None
    for event in gh.issue_events(issue_number):
        if event.get("event") == "labeled" and event.get("label", {}).get("name") == label:
            actor = (event.get("actor") or {}).get("login")
    return bool(actor) and gh.permission(actor) in MAINTAINER_ROLES
