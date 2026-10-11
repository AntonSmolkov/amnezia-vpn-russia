#!/usr/bin/env python3
"""Сборка tunneling-list.json для раздельного туннелирования Amnezia VPN.

Зачем IP-адреса. Клиент Amnezia при ИМПОРТЕ json не резолвит домены — резолв
выполняется только при ручном добавлении сайта. Для AmneziaWG/WireGuard (и для
любых протоколов на Android/iOS) маршруты строятся только из IP и подсетей, а
запись {"hostname": "sberbank.ru", "ip": ""} не исключает из туннеля ничего.
Если IP нет ни у одной записи, клиент молча отключает раздельное
туннелирование и пускает весь трафик через VPN.

Поэтому скрипт:
  1. резолвит домены из sources/domains.txt (+ вариант www.) через DoH;
  2. оставляет только российские IP: из блоков, зарегистрированных за РФ,
     или анонсируемые российскими ASN. Адреса российских анти-DDoS сервисов
     с зарубежной регистрацией (sources/protection-asn.txt) берутся точечно.
     Общие зарубежные CDN (Cloudflare, AWS, Akamai) отбрасываются: на тех же
     IP живут тысячи других сайтов, в том числе заблокированных в РФ;
  3. добавляет анонсируемые подсети ASN крупных компаний (sources/asn.txt) и
     ручные подсети (sources/cidr.txt) — они устойчивы к смене IP;
  4. пишет json, понятный Amnezia 4.8.x (поле "ip") и 5.x (поле "ips"),
     плюс отдельные записи-подсети, которые работают в любой версии.

Только стандартная библиотека Python 3.9+.
"""

from __future__ import annotations

import argparse
import bisect
import concurrent.futures
import http.client
import ipaddress
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "sources"

USER_AGENT = "amnezia-vpn-russia-builder/1.0 (+https://github.com/kozlovartem20201/amnezia-vpn-russia)"

# Подсеть российского провайдера для EDNS Client Subnet: GeoDNS отдаёт адреса
# так, как их увидел бы пользователь из России, даже если сборка идёт в CI за рубежом.
DEFAULT_ECS = "95.165.0.0/24"

# Подсети шире этой из ASN не берём — защита от случайного добавления
# магистрального провайдера целиком.
MIN_ASN_PREFIXLEN = 12


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def http_json(url: str, *, headers: dict | None = None, timeout: int = 30, retries: int = 3):
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (OSError, ValueError, http.client.HTTPException) as e:  # сеть, HTTP-ошибки, битый JSON
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{url}: {last_err}")


def write_file(path: Path, text: str) -> None:
    """UTF-8 с LF на любой ОС, чтобы сборка на Windows и в CI давала одинаковый файл."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


# ---------------------------------------------------------------- источники

def read_lines(path: Path) -> list[str]:
    """Строки файла без комментариев (# ...) и пустых строк."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def to_ascii(domain: str) -> str:
    """IDN (например, госуслуги.рф) -> punycode для DNS-запроса."""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def valid_domain(domain: str) -> bool:
    ascii_name = to_ascii(domain)
    if not ascii_name or "." not in ascii_name or len(ascii_name) > 253:
        return False
    labels = ascii_name.split(".")
    if not labels[-1].isalpha() and not labels[-1].startswith("xn--"):
        return False
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
    return True


def load_domains(path: Path) -> list[str]:
    domains, seen, errors = [], set(), []
    for line in read_lines(path):
        d = line.lower().rstrip(".")
        for prefix in ("https://", "http://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
        d = d.split("/", 1)[0]
        if not valid_domain(d):
            errors.append(line)
            continue
        if d in seen:
            log(f"  дубликат в domains.txt: {d}")
            continue
        seen.add(d)
        domains.append(d)
    if errors:
        raise SystemExit(f"Некорректные домены в {path.name}: {', '.join(errors)}")
    return domains


def load_asns(path: Path) -> list[int]:
    asns = []
    for line in read_lines(path):
        token = line.split()[0].upper().removeprefix("AS")
        if not token.isdigit():
            raise SystemExit(f"Некорректный ASN в {path.name}: {line}")
        asns.append(int(token))
    return sorted(set(asns))


def load_cidrs(path: Path) -> list[ipaddress.IPv4Network]:
    nets = []
    for line in read_lines(path):
        try:
            nets.append(ipaddress.IPv4Network(line.split()[0], strict=False))
        except ValueError:
            raise SystemExit(f"Некорректная подсеть в {path.name}: {line}")
    return nets


# ---------------------------------------------------------------- DNS

def doh_google(name: str, ecs: str) -> tuple[str, set[str]]:
    q = urllib.parse.urlencode({"name": name, "type": "A", "edns_client_subnet": ecs})
    data = http_json(f"https://dns.google/resolve?{q}")
    return _parse_doh(data)


def doh_cloudflare(name: str) -> tuple[str, set[str]]:
    q = urllib.parse.urlencode({"name": name, "type": "A"})
    data = http_json(f"https://cloudflare-dns.com/dns-query?{q}", headers={"Accept": "application/dns-json"})
    return _parse_doh(data)


def _parse_doh(data: dict) -> tuple[str, set[str]]:
    status = data.get("Status")
    if status == 3:
        return "nxdomain", set()
    if status != 0:
        # SERVFAIL/REFUSED: сломанное делегирование у мёртвого домена, а не сбой сети
        return "servfail", set()
    ips = set()
    for ans in data.get("Answer", []) or []:
        if ans.get("type") == 1:
            try:
                ips.add(str(ipaddress.IPv4Address(ans["data"])))
            except ValueError:
                pass
    return "ok", ips


def resolve(name: str, ecs: str) -> tuple[str, set[str]]:
    """Объединяет ответы двух резолверов: у крупных сервисов пул адресов
    ротируется, и так в список попадает больше адресов."""
    ascii_name = to_ascii(name)
    statuses, ips = [], set()
    for fn in (lambda: doh_google(ascii_name, ecs), lambda: doh_cloudflare(ascii_name)):
        try:
            st, found = fn()
        except RuntimeError:
            st, found = "error", set()
        statuses.append(st)
        ips |= found
    if ips:
        return "ok", ips
    if all(s == "error" for s in statuses):
        return "error", set()
    if "nxdomain" in statuses:
        return "nxdomain", set()
    if "servfail" in statuses:
        return "servfail", set()
    return "nodata", set()


# ---------------------------------------------------------------- RIPEstat

def ru_resources() -> tuple[list[ipaddress.IPv4Network], set[int]]:
    """IPv4-блоки и ASN, зарегистрированные RIR за Россией."""
    data = http_json(
        "https://stat.ripe.net/data/country-resource-list/data.json?resource=RU&v4_format=prefix",
        timeout=90,
    )["data"]["resources"]
    nets = [ipaddress.IPv4Network(p) for p in data["ipv4"]]
    asns = {int(a) for a in map(str, data["asn"]) if a.isdigit()}
    if len(nets) < 1000 or len(asns) < 1000:
        raise SystemExit(f"RIPEstat вернул подозрительно мало российских ресурсов: {len(nets)} блоков, {len(asns)} ASN")
    return nets, asns


def asn_prefixes(asn: int) -> list[ipaddress.IPv4Network]:
    data = http_json(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}", timeout=60)
    nets = []
    for p in data["data"]["prefixes"]:
        if ":" in p["prefix"]:
            continue
        net = ipaddress.IPv4Network(p["prefix"])
        if net.prefixlen < MIN_ASN_PREFIXLEN:
            log(f"  AS{asn}: пропускаю слишком широкую подсеть {net}")
            continue
        nets.append(net)
    return nets


def origin_asns(ip: str) -> set[int]:
    """ASN, из которых анонсируется адрес (пустое множество при ошибке)."""
    try:
        data = http_json(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=30)
        return {int(a) for a in data["data"].get("asns", [])}
    except (RuntimeError, ValueError, KeyError):
        return set()


class NetSet:
    """Быстрая проверка принадлежности IP набору подсетей."""

    def __init__(self, nets):
        merged = ipaddress.collapse_addresses(nets)
        ranges = [(int(n.network_address), int(n.broadcast_address)) for n in merged]
        self.starts = [r[0] for r in ranges]
        self.ends = [r[1] for r in ranges]

    def __contains__(self, ip) -> bool:
        x = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(self.starts, x) - 1
        return i >= 0 and x <= self.ends[i]


def fetch_asn_nets(asns: list[int]) -> dict[int, list[ipaddress.IPv4Network]]:
    result = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for asn, nets in zip(asns, pool.map(asn_prefixes, asns)):
            result[asn] = nets
            if not nets:
                log(f"  AS{asn}: нет анонсируемых IPv4-подсетей")
    return result


# ---------------------------------------------------------------- сборка

def build(args) -> int:
    domains = load_domains(SOURCES / "domains.txt")
    asns = load_asns(SOURCES / "asn.txt")
    protection_asns = set(load_asns(SOURCES / "protection-asn.txt"))
    manual_cidrs = load_cidrs(SOURCES / "cidr.txt")
    log(f"Доменов: {len(domains)}, ASN: {len(asns)}, ASN защиты: {len(protection_asns)}, подсетей: {len(manual_cidrs)}")

    log("Загружаю российские IPv4-блоки и ASN (RIPEstat)…")
    ru_nets, ru_asns = ru_resources()
    ru_blocks = NetSet(ru_nets)

    log("Загружаю подсети ASN…")
    asn_nets = fetch_asn_nets(asns)
    own_nets = NetSet([n for v in asn_nets.values() for n in v] + manual_cidrs)
    protection = NetSet([n for v in fetch_asn_nets(sorted(protection_asns)).values() for n in v])

    names = []
    for d in domains:
        names.append(d)
        if not d.startswith("www."):
            names.append("www." + d)

    log(f"Резолвлю {len(names)} имён через DoH…")
    results: dict[str, tuple[str, set[str]]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(resolve, n, args.ecs): n for n in names}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            results[futures[fut]] = fut.result()
            if i % 300 == 0:
                log(f"  {i}/{len(names)}")

    errors = [n for n, (st, _) in results.items() if st == "error"]
    if len(errors) > len(names) * 0.1:
        raise SystemExit(f"Не удалось резолвить {len(errors)} имён — похоже на сбой сети, файл не записан")

    domain_ips: dict[str, set[str]] = {}
    for d in domains:
        ips = set(results[d][1])
        if not d.startswith("www."):
            ips |= results["www." + d][1]
        domain_ips[d] = ips

    # Российский адрес — тот, что лежит в российском блоке, в подсетях наших
    # ASN или анонсируется российским ASN; такие расширяем до /widen.
    # Адреса российских анти-DDoS сервисов с зарубежной регистрацией берём
    # без расширения: в соседних адресах живут чужие сайты.
    all_ips = set().union(*domain_ips.values())
    unknown = [ip for ip in all_ips if ip not in ru_blocks and ip not in own_nets and ip not in protection]
    log(f"Проверяю происхождение {len(unknown)} адресов вне российских блоков…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        origin = dict(zip(unknown, pool.map(origin_asns, unknown)))

    widen_ips, exact_ips = set(), set()
    for ip in all_ips:
        if ip in ru_blocks or ip in own_nets or origin.get(ip, set()) & ru_asns:
            widen_ips.add(ip)
        elif ip in protection or origin.get(ip, set()) & protection_asns:
            exact_ips.add(ip)
    allowed = widen_ips | exact_ips

    report = {"nxdomain": [], "nodata": [], "servfail": [], "error": [], "foreign_only": [], "foreign_dropped": {}}
    entries = []
    for d in domains:
        ips = domain_ips[d]
        if not ips:
            report[results[d][0] if results[d][0] in report else "nodata"].append(d)
            continue
        kept = sorted(ips & allowed, key=ipaddress.IPv4Address)
        dropped = sorted(ips - allowed, key=ipaddress.IPv4Address)
        if dropped:
            report["foreign_dropped"][d] = [
                f"{ip} (AS{','.join(map(str, sorted(origin.get(ip, set())))) or '?'})" for ip in dropped
            ]
        if not kept:
            report["foreign_only"].append(d)
            continue
        entries.append({"hostname": d, "ip": kept[0], "ips": kept})

    nets = [ipaddress.IPv4Network(f"{ip}/{args.widen}", strict=False) for ip in widen_ips]
    nets += [ipaddress.IPv4Network(f"{ip}/32") for ip in exact_ips]
    for v in asn_nets.values():
        nets.extend(v)
    nets.extend(manual_cidrs)
    collapsed = list(ipaddress.collapse_addresses(nets))

    entries.sort(key=lambda e: e["hostname"])
    entries.extend(
        {"hostname": str(n) if n.prefixlen < 32 else str(n.network_address), "ip": ""} for n in collapsed
    )

    write_file(ROOT / args.output, json.dumps(entries, ensure_ascii=False, indent=2) + "\n")
    write_file(ROOT / args.subnets, "".join(f"{n}\n" for n in collapsed))

    total_ips = sum(n.num_addresses for n in collapsed)
    summary = [
        f"Доменов в списке: {len(entries) - len(collapsed)} из {len(domains)}",
        f"Подсетей: {len(collapsed)} (≈{total_ips:,} адресов)".replace(",", " "),
        f"Нет A-записей (NXDOMAIN/NODATA): {len(report['nxdomain']) + len(report['nodata'])}",
        f"Сломанное DNS-делегирование (SERVFAIL): {len(report['servfail'])}",
        f"Только зарубежные IP, исключены: {len(report['foreign_only'])}",
        f"Ошибки резолва: {len(report['error'])}",
    ]
    log("\n".join(summary))

    if args.report:
        lines = ["# Отчёт сборки", "", *[f"- {s}" for s in summary], ""]
        for title, keys in (
            ("Нет A-записей — домен умер или переехал", ("nxdomain", "nodata")),
            ("SERVFAIL — домен, скорее всего, заброшен", ("servfail",)),
            ("Только зарубежные IP (Cloudflare, AWS и т.п.) — в список не попали", ("foreign_only",)),
            ("Ошибки резолва", ("error",)),
        ):
            found = sorted(d for k in keys for d in report[k])
            if found:
                lines += [f"## {title}", "", *[f"- `{d}`" for d in found], ""]
        partial = {d: v for d, v in report["foreign_dropped"].items() if d not in report["foreign_only"]}
        if partial:
            lines += ["## Отброшенные зарубежные IP у российских доменов", ""]
            lines += [f"- `{d}`: {', '.join(v)}" for d, v in sorted(partial.items())]
            lines.append("")
        write_file(ROOT / args.report, "\n".join(lines))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output", default="tunneling-list.json")
    p.add_argument("--subnets", default="ru-subnets.txt", help="плоский список подсетей (по одной на строку)")
    p.add_argument("--report", default="", help="куда записать markdown-отчёт (необязательно)")
    p.add_argument("--ecs", default=DEFAULT_ECS, help="EDNS Client Subnet для Google DoH")
    p.add_argument("--widen", type=int, default=24,
                   help="расширять российские адреса доменов до подсети /N (32 — не расширять)")
    p.add_argument("--workers", type=int, default=16)
    args = p.parse_args()
    if not 16 <= args.widen <= 32:
        p.error("--widen должен быть от 16 до 32")
    return build(args)


if __name__ == "__main__":
    sys.exit(main())


