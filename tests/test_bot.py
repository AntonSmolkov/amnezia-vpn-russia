"""Офлайн-тесты бота заявок: python -m unittest discover -s tests"""

import io
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build  # noqa: E402
from domain_checks import DomainCheck, normalize, report, split_domains  # noqa: E402
from domains_file import categories, insert_domains  # noqa: E402
from submission import CONFIRMATIONS, FIELDS, TEMPLATE, evaluate, load_policy, parse_form, run  # noqa: E402

DOMAINS_TEXT = (build.SOURCES / "domains.txt").read_text(encoding="utf-8")
CATEGORY = "2. Госуслуги и госорганы"


def issue_body(domains="zakupki-test.ru", category=CATEGORY, problem="Капча", confirmations=CONFIRMATIONS):
    """Тело issue так, как его генерирует GitHub из формы."""
    boxes = "\n".join(f"- [{'X' if o in confirmations else ' '}] {o}" for o in CONFIRMATIONS)
    values = {"domains": domains, "category": category, "problem": problem, "confirmations": boxes}
    return "\n\n".join(f"### {FIELDS[k]}\n\n{v or '_No response_'}" for k, v in values.items())


class FakeChecker:
    """Подменяет сетевые проверки: домены из `covered` уже покрыты, из `bad` — с ошибкой."""

    def __init__(self, covered=(), bad=()):
        self.covered, self.bad, self.calls = set(covered), set(bad), []

    def __call__(self, raws):
        self.calls.append(raws)
        out = []
        for r in raws:
            c = DomainCheck(raw=r, domain=normalize(r), ru_ips=["95.167.245.92"])
            if c.domain in self.bad:
                c.errors.append("все IP-адреса зарубежные")
                c.ru_ips = []
            c.covered = c.domain in self.covered
            out.append(c)
        return out


class TemplateSyncTest(unittest.TestCase):
    template = TEMPLATE.read_text(encoding="utf-8")

    def test_field_labels_match_template(self):
        labels = re.findall(r"^\s+label: (.+?)\s*$", self.template, re.M)
        self.assertEqual([l for l in labels if l in FIELDS.values()], list(FIELDS.values()))

    def test_confirmations_match_template(self):
        for option in CONFIRMATIONS:
            self.assertIn(f"- label: {option}\n", self.template)

    def test_categories_match_domains_file(self):
        options = re.findall(r"^\s+- (\d+\. .+?)\s*$", self.template, re.M)
        self.assertEqual(options, categories(DOMAINS_TEXT))
        self.assertEqual(len(options), 11)


class ParsingTest(unittest.TestCase):
    def test_round_trip(self):
        form = parse_form(issue_body(domains="a.ru\nb.ru"))
        self.assertEqual(form["domains"], "a.ru\nb.ru")
        self.assertEqual(form["category"], CATEGORY)
        self.assertTrue(all(form["confirmations"].values()))

    def test_injected_heading_cannot_overwrite_earlier_field(self):
        body = issue_body(problem="текст\n### Домены\n\nevil.example")
        self.assertEqual(parse_form(body)["domains"], "zakupki-test.ru")

    def test_unchecked_confirmation(self):
        form = parse_form(issue_body(confirmations=CONFIRMATIONS[:1]))
        self.assertFalse(all(form["confirmations"].values()))

    def test_normalize(self):
        self.assertEqual(normalize("https://www.Sberbank.ru/path?x=1"), "sberbank.ru")
        self.assertEqual(normalize("*.yandex.ru"), "yandex.ru")
        self.assertEqual(normalize("lk.zakupki.gov.ru:443"), "lk.zakupki.gov.ru")
        self.assertEqual(normalize("`госуслуги.рф`"), "госуслуги.рф")

    def test_split_domains(self):
        self.assertEqual(split_domains("a.ru, b.ru\n- c.ru\n\na.ru"), ["a.ru", "b.ru", "c.ru"])

    def test_report_sanitizes_raw_input(self):
        text = report([DomainCheck(raw="<b>@everyone</b>|x", domain="", errors=["плохо"])])
        self.assertNotIn("@", text)
        self.assertNotIn("<b>", text)


class DomainsFileTest(unittest.TestCase):
    def test_insert_into_middle_category(self):
        text = insert_domains(DOMAINS_TEXT, CATEGORY, ["new-gov.ru"], "issue #99")
        lines = text.splitlines()
        i = lines.index("new-gov.ru           # issue #99")
        next_header = next(j for j, l in enumerate(lines) if l.startswith("# 3. "))
        self.assertLess(i, next_header)
        self.assertGreater(i, next(j for j, l in enumerate(lines) if l.startswith("# 2. ")))
        self.assertTrue(lines[i - 1].strip())  # без пустой строки перед вставкой

    def test_insert_into_last_category(self):
        text = insert_domains(DOMAINS_TEXT, categories(DOMAINS_TEXT)[-1], ["plant.ru"], "issue #1")
        self.assertTrue(text.rstrip("\n").endswith("plant.ru             # issue #1"))

    def test_inserted_file_still_loads(self):
        text = insert_domains(DOMAINS_TEXT, CATEGORY, ["new-gov.ru"], "issue #99")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "domains.txt"
            path.write_text(text, encoding="utf-8")
            self.assertIn("new-gov.ru", build.load_domains(path))

    def test_unknown_category(self):
        with self.assertRaises(ValueError):
            insert_domains(DOMAINS_TEXT, "99. Нет такой", ["x.ru"], "c")


class EvaluateTest(unittest.TestCase):
    policy = load_policy()

    def test_valid_submission_reaches_checker(self):
        checker = FakeChecker()
        out = evaluate(parse_form(issue_body(domains="a.ru\nhttps://www.a.ru/\nb.ru")), self.policy,
                       DOMAINS_TEXT, lambda: checker)
        self.assertEqual(out.errors, [])
        self.assertEqual(checker.calls, [["a.ru", "b.ru"]])  # дубль после нормализации отброшен
        self.assertEqual([c.domain for c in out.accepted], ["a.ru", "b.ru"])

    def test_form_errors_skip_network(self):
        checker = FakeChecker()
        body = issue_body(category="Нет такой", confirmations=[], problem="")
        out = evaluate(parse_form(body), self.policy, DOMAINS_TEXT, lambda: checker)
        self.assertEqual(len(out.errors), 3)
        self.assertEqual(checker.calls, [])

    def test_too_many_domains(self):
        many = "\n".join(f"d{i}.ru" for i in range(self.policy["max_domains_per_issue"] + 1))
        out = evaluate(parse_form(issue_body(domains=many)), self.policy, DOMAINS_TEXT, FakeChecker)
        self.assertTrue(any("не больше" in e for e in out.errors))

    def test_policy_blocked_domain(self):
        policy = dict(self.policy, blocked_domains=["evil.ru"])
        out = evaluate(parse_form(issue_body(domains="shop.evil.ru")), policy, DOMAINS_TEXT, FakeChecker)
        self.assertEqual(out.accepted, [])
        self.assertTrue(out.rejected)


class RunTest(unittest.TestCase):
    def event(self, body, labels=("submission",), action="opened"):
        return {"action": action, "repository": {"default_branch": "main"}, "issue": {
            "number": 7, "state": "open", "body": body, "author_association": "NONE",
            "user": {"login": "someone", "id": 1}, "labels": [{"name": n} for n in labels]}}

    def run_bot(self, event, checker):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run(event, None, dry_run=True, make_checker=lambda: checker)
        return code, buf.getvalue()

    def test_not_a_submission(self):
        checker = FakeChecker()
        code, out = self.run_bot(self.event(issue_body(), labels=("bug",)), checker)
        self.assertEqual((code, checker.calls), (0, []))

    def test_accepted_prints_pr_body(self):
        code, out = self.run_bot(self.event(issue_body(domains="a.ru")), FakeChecker())
        self.assertEqual(code, 0)
        self.assertIn("Closes #7", out)

    def test_all_covered(self):
        code, out = self.run_bot(self.event(issue_body(domains="a.ru")), FakeChecker(covered={"a.ru"}))
        self.assertIn("уже идут мимо VPN", out)
        self.assertNotIn("Closes #7", out)

    def test_all_rejected(self):
        code, out = self.run_bot(self.event(issue_body(domains="cf.ru")), FakeChecker(bad={"cf.ru"}))
        self.assertIn("Нужно исправить", out)

    def test_other_label_events_ignored(self):
        event = self.event(issue_body(), action="labeled")
        event["label"] = {"name": "bug"}
        checker = FakeChecker()
        self.assertEqual(self.run_bot(event, checker)[0], 0)
        self.assertEqual(checker.calls, [])


if __name__ == "__main__":
    unittest.main()
