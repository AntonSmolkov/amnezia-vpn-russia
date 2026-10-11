#!/usr/bin/env python3
"""Проверки доменов-кандидатов. Общие для бота заявок и CI pull request'ов.

Домен принимается в sources/domains.txt, если:
  - имя корректно и такого домена в списке ещё нет;
  - он не заблокирован в РФ (реестр РКН по данным antifilter.download):
    мимо VPN заблокированный сайт не откроется;
  - у него есть A-записи;
  - хотя бы часть его IP — российские (те же правила, что в build.py).
    Сайты только на Cloudflare, AWS и других зарубежных CDN исключать нельзя:
    на тех же IP живут тысячи чужих сайтов, в том числе заблокированных.

Если все российские IP домена уже покрыты опубликованным ru-subnets.txt,
добавлять домен незачем: сайт и так идёт мимо VPN.

Запуск в CI для pull request'а — проверить домены, добавленные относительно базы:
    python scripts/domain_checks.py --base-ref origin/main
Проверить произвольные домены:
    python scripts/domain_checks.py example.ru another.ru
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field

import build

# Реестр РКН: домены, заблокированные в РФ. Жёсткий отказ.
BLOCKED_IN_RU_URL = "https://antifilter.download/list/domains.lst"
# Домены, которым из РФ нужен VPN (в том числе зарубежные сервисы, не пускающие
# российских пользователей). Мягкий сигнал: решает мейнтейнер.
NEEDS_VPN_URL = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst"


@dataclass
class DomainCheck:
    raw: str
    domain: str = ""
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    ru_ips: list[str] = field(default_factory=list)
    foreign_ips: list[str] = field(default_factory=list)
    covered: bool = False
    needs_review: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def accepted(self) -> bool:
        """Домен проходит проверки и действительно что-то меняет в списке."""
        return self.ok and not self.covered


def normalize(raw: str) -> str:
    """https://www.Sberbank.ru/path → sberbank.ru; *.x.ru → x.ru."""
    d = raw.strip().strip("`'\"<>").lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#]", d, maxsplit=1)[0]
    d = d.rsplit("@", 1)[-1]
    d = re.sub(r":\d+$", "", d).rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("www."):
        d = d[4:]  # вариант www. build.py проверяет сам
    return d


def split_domains(text: str) -> list[str]:
    """Домены из свободного текста: по строкам, запятым и пробелам, без пустых и повторов."""
    seen, out = set(), []
    for token in re.split(r"[\s,;]+", text or ""):
        token = token.strip().lstrip("-*•").strip()
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return out


def match_list(url: str, domains: list[str]) -> dict[str, str] | None:
    """{домен: совпавшая запись} по домену и всем его родителям.

    Файл читается потоком, в память попадают только кандидаты.
    None — список недоступен.
    """
    wanted: dict[str, str] = {}
    for d in domains:
        labels = build.to_ascii(d).split(".")
        for i in range(len(labels) - 1):
            wanted.setdefault(".".join(labels[i:]), d)
    found: dict[str, str] = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": build.USER_AGENT})
        with urllib.request.urlopen(req, timeout=120) as resp:
            for raw in resp:
                entry = raw.decode("utf-8", "ignore").strip().strip('"').lstrip(".").lower()
                if entry in wanted:
                    found.setdefault(wanted[entry], entry)
    except OSError as exc:
        build.log(f"Список {url} недоступен: {exc}")
        return None
    return found


class Checker:
    """Проверяет домены. Загрузка RIPEstat-данных выполняется один раз."""

    def __init__(self, existing: set[str], published: list[ipaddress.IPv4Network] | None):
        _, asns, protection_asns, manual_cidrs = build.load_sources()
        self.existing = existing
        self.published = build.NetSet(published) if published else None
        self.classifier = build.IpClassifier(build.fetch_asn_nets(asns), manual_cidrs, protection_asns)

    def __call__(self, raws: list[str]) -> list[DomainCheck]:
        checks = [DomainCheck(raw=r, domain=normalize(r)) for r in raws]
        for c in checks:
            if not c.domain or not build.valid_domain(c.domain):
                c.errors.append("это не похоже на доменное имя")
            elif c.domain in self.existing:
                c.errors.append("уже есть в списке")
        candidates = [c.domain for c in checks if c.ok]
        if not candidates:
            return checks

        blocked = match_list(BLOCKED_IN_RU_URL, candidates)
        needs_vpn = match_list(NEEDS_VPN_URL, candidates)
        resolved = build.resolve_domains(candidates)
        all_ips = set().union(*(ips for _, ips in resolved.values()))
        widen, exact = self.classifier.classify(all_ips)
        allowed = widen | exact

        for c in checks:
            if not c.ok:
                continue
            if blocked is None:
                c.needs_review = True
                c.notes.append("реестр блокировок РКН был недоступен — мейнтейнер проверит вручную")
            elif c.domain in blocked:
                c.errors.append(f"заблокирован в РФ (`{blocked[c.domain]}` в реестре РКН): "
                                f"без VPN он не откроется")
                continue
            if needs_vpn and c.domain in needs_vpn:
                c.needs_review = True
                c.notes.append(f"`{needs_vpn[c.domain]}` числится среди сайтов, которым из РФ нужен VPN")

            status, ips = resolved[c.domain]
            if not ips:
                c.errors.append({
                    "nxdomain": "такого домена не существует",
                    "servfail": "DNS домена не отвечает — похоже, он заброшен",
                    "error": "не удалось проверить DNS, попробуйте позже",
                }.get(status, "у домена нет IPv4-адресов"))
                continue
            c.ru_ips = sorted(ips & allowed, key=ipaddress.IPv4Address)
            c.foreign_ips = [self.classifier.describe(ip)
                             for ip in sorted(ips - allowed, key=ipaddress.IPv4Address)]
            if not c.ru_ips:
                c.errors.append("все IP-адреса зарубежные (" + ", ".join(c.foreign_ips[:4]) + "). Обычно это "
                                "Cloudflare или другой зарубежный CDN: их адреса делят тысячи сайтов, "
                                "в том числе заблокированных, поэтому исключать их из VPN нельзя")
                continue
            if c.foreign_ips:
                c.notes.append("зарубежные адреса в список не попадут: " + ", ".join(c.foreign_ips[:4]))
            if self.published and all(ip in self.published for ip in c.ru_ips):
                c.covered = True
        return checks


def read_published() -> list[ipaddress.IPv4Network]:
    path = build.ROOT / "ru-subnets.txt"
    if not path.exists():
        return []
    return [ipaddress.IPv4Network(line) for line in build.read_lines(path)]


def domains_at(ref: str) -> list[str]:
    text = subprocess.run(["git", "show", f"{ref}:sources/domains.txt"], check=True,
                          capture_output=True, text=True, encoding="utf-8").stdout
    return [line.split("#", 1)[0].strip().lower() for line in text.splitlines()
            if line.split("#", 1)[0].strip()]


def display_name(c: DomainCheck) -> str:
    """Имя для таблицы. Сырой ввод пользователя очищается: без упоминаний, HTML и разметки."""
    if c.domain and build.valid_domain(c.domain):
        return c.domain
    return re.sub(r"[^\w.\-:/]", "", c.raw)[:80] or "?"


def report(checks: list[DomainCheck]) -> str:
    lines = ["| Домен | Результат | Российские IP |", "| :--- | :--- | :--- |"]
    for c in checks:
        if c.errors:
            verdict = "❌ " + "; ".join(c.errors)
        elif c.covered:
            verdict = "☑️ уже идёт мимо VPN — все адреса покрыты списком"
        else:
            verdict = "✅ подходит"
        if c.notes:
            verdict += "<br>ℹ️ " + "; ".join(c.notes)
        ips = ", ".join(c.ru_ips[:6]) + (" …" if len(c.ru_ips) > 6 else "")
        lines.append(f"| `{display_name(c)}` | {verdict} | {ips or '—'} |")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domains", nargs="*", help="домены для проверки")
    p.add_argument("--base-ref", help="проверить домены, добавленные в sources/domains.txt относительно ref")
    args = p.parse_args()

    current = build.load_domains(build.SOURCES / "domains.txt")
    if args.base_ref:
        base = set(domains_at(args.base_ref))
        candidates = [d for d in current if d not in base]
        existing = base
    else:
        candidates = args.domains
        existing = set(current)
    if not candidates:
        print("Новых доменов нет.")
        return 0

    checks = Checker(existing, read_published())(candidates)
    text = report(checks)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("## Проверка новых доменов\n\n" + text + "\n")
    # В pull request'е «уже покрыт» — не ошибка, а повод задуматься; падаем только на ошибках.
    return 1 if any(c.errors for c in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
