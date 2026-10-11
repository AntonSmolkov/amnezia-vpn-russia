"""Работа с категориями sources/domains.txt.

Категория начинается с блока
    # ==========
    # 2. Госуслуги и госорганы
    # ==========
и тянется до следующего такого блока. Названия категорий в форме заявки
должны совпадать с этими заголовками (это проверяет тест).
"""

from __future__ import annotations

import re

HEADER_RE = re.compile(r"^# (\d+)\. (.+?)\s*$")
RULE_RE = re.compile(r"^# ={10,}\s*$")


def _headers(lines: list[str]) -> list[tuple[int, str]]:
    """[(индекс строки-заголовка, «N. Название»)]"""
    found = []
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if m and i > 0 and RULE_RE.match(lines[i - 1]):
            found.append((i, f"{m.group(1)}. {m.group(2)}"))
    return found


def categories(text: str) -> list[str]:
    return [title for _, title in _headers(text.splitlines())]


def insert_domains(text: str, category: str, domains: list[str], comment: str) -> str:
    """Добавляет домены в конец категории с комментарием (например, «issue #12»)."""
    lines = text.splitlines()
    headers = _headers(lines)
    titles = [t for _, t in headers]
    if category not in titles:
        raise ValueError(f"нет категории «{category}»")
    pos = titles.index(category)
    if pos + 1 < len(headers):
        end = headers[pos + 1][0] - 1  # строка "# ====" перед следующим заголовком
    else:
        end = len(lines)
    while end > 0 and not lines[end - 1].strip():
        end -= 1
    new = [f"{d.ljust(20)} # {comment}" for d in domains]
    lines[end:end] = new
    return "\n".join(lines) + "\n"
