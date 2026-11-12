#!/usr/bin/env python3
"""CardFerry - a read-only vCard preflight gate whose report never prints a contact value.

Audits one or more .vcf files as one set before they are imported
anywhere: per-card structure and required-property checks, plus
cross-card findings (exact duplicates, duplicate UIDs, shared
phones/emails, name collisions). Findings identify cards only by
position and SHA-256 fingerprint. Stdlib only, no network.
"""
import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import date

VERSION = "1.0.0"
KNOWN_VERSIONS = {"2.1", "3.0", "4.0"}
SINGLETONS = ("VERSION", "FN", "UID")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EXT_RE = re.compile(r"(?i)(?:;ext=\d+|\s+(?:x|ext\.?)\s*\d+)\s*$")


def fingerprint(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def normalize_phone(raw, country_code):
    v = raw.strip()
    if v.lower().startswith("tel:"):
        v = v[4:]
    v = EXT_RE.sub("", v).strip()
    plus = v.startswith("+")
    digits = re.sub(r"\D", "", v)
    if not digits:
        return ""
    if plus:
        return "+" + digits
    if digits.startswith("00") and len(digits) > 2:
        return "+" + digits[2:]
    if len(digits) == 10 and country_code:
        return "+" + country_code + digits
    if country_code and len(digits) == 10 + len(country_code) and digits.startswith(country_code):
        return "+" + digits
    return digits


def normalize_email(raw):
    v = raw.strip()
    if v.lower().startswith("mailto:"):
        v = v[7:]
    return v.strip().casefold()


def normalize_name(raw):
    return re.sub(r"\s+", " ", raw.strip()).casefold()


def valid_bday(v):
    v = v.strip()
    m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", v) or re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", v)
    if m:
        try:
            date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return True
        except ValueError:
            return False
    m = re.fullmatch(r"--(\d{2})(\d{2})", v) or re.fullmatch(r"--(\d{2})-(\d{2})", v)
    if m:
        mo, da = int(m.group(1)), int(m.group(2))
        return 1 <= mo <= 12 and 1 <= da <= 31
    return False


class Card:
    def __init__(self, number, label, index_in_file):
        self.number = number
        self.label = label
        self.index_in_file = index_in_file
        self.props = []  # list of (name, value)

    def values(self, name):
        return [v for (n, v) in self.props if n == name]

    def payload(self):
        lines = sorted(
            "%s=%s" % (n, re.sub(r"\s+", " ", v.strip()))
            for (n, v) in self.props
        )
        return "\n".join(lines)

    @property
    def fp(self):
        return fingerprint(self.payload())

    def ref(self):
        return "card #%d in %s (fp %s)" % (self.number, self.label, self.fp)


def parse_file(label, text, country_code, findings, cards, start_number):
    """Parse one file. findings: list of dicts. Returns next card number."""
    physical = re.split(r"\r\n|\n|\r", text)
    # Unfold, tracking the starting physical line (1-based) and long lines.
    logical = []  # (line_text, start_line_no)
    for i, raw in enumerate(physical, start=1):
        if len(raw.encode("utf-8")) > 75:
            logical_long = i  # attributed later by position scan
        if raw[:1] in (" ", "\t") and logical:
            prev, start = logical[-1]
            logical[-1] = (prev + raw[1:], start)
        else:
            logical.append((raw, i))
    long_lines = [i for i, raw in enumerate(physical, start=1)
                  if len(raw.encode("utf-8")) > 75]

    number = start_number
    current = None
    card_line_starts = []  # (card, [physical lines inside])
    seen_any_card = False

    def add(severity, code, card, message, value_fp=None):
        f = {"severity": severity, "code": code, "message": message}
        if card is not None:
            f["card"] = card.number
            f["file"] = card.label
            f["card_fp"] = card.fp if card.props else None
        else:
            f["file"] = label
        if value_fp:
            f["value_fp"] = value_fp
        findings.append(f)

    for line, start in logical:
        stripped = line.strip()
        upper = stripped.upper()
        if current is None:
            if not stripped:
                continue
            if upper == "BEGIN:VCARD":
                current = Card(number, label, number - start_number + 1)
                seen_any_card = True
                continue
            if upper == "END:VCARD":
                add("error", "structure", None,
                    "END:VCARD with no open card at line %d" % start)
                continue
            add("error", "outside-card", None,
                "content outside a VCARD at line %d" % start)
            continue
        # inside a card
        if upper == "END:VCARD":
            cards.append(current)
            number += 1
            current = None
            continue
        if upper == "BEGIN:VCARD":
            add("error", "structure", current,
                "BEGIN:VCARD inside a card at line %d" % start)
            continue
        if ":" not in line:
            add("error", "malformed-line", current,
                "line %d has no ':' separator" % start)
            continue
        left, value = line.split(":", 1)
        name = left.split(";", 1)[0].strip().upper()
        if "." in name:
            name = name.rsplit(".", 1)[-1]
        current.props.append((name, value))
    if current is not None:
        add("error", "structure", current, "file ends inside a VCARD")
        cards.append(current)
        number += 1
    if not seen_any_card:
        add("error", "no-cards", None, "file contains no VCARD")
    # long-line warnings: attribute by counting cards is not reliable post-hoc;
    # report at file level with the physical line number.
    for ln in long_lines:
        findings.append({"severity": "warning", "code": "long-line",
                         "file": label,
                         "message": "physical line %d exceeds 75 octets" % ln})
    return number


def check_card(card, country_code, findings):
    def add(severity, code, message, value_fp=None):
        f = {"severity": severity, "code": code, "card": card.number,
             "file": card.label, "card_fp": card.fp, "message": message}
        if value_fp:
            f["value_fp"] = value_fp
        findings.append(f)

    versions = card.values("VERSION")
    if not versions:
        add("warning", "missing-version", "%s has no VERSION" % card.ref())
    elif versions[0].strip() not in KNOWN_VERSIONS:
        add("warning", "unknown-version", "%s has an unrecognized VERSION" % card.ref())
    for name in SINGLETONS:
        if len(card.values(name)) > 1:
            add("warning", "duplicate-singleton",
                "%s repeats the %s property" % (card.ref(), name))
    fns = [v for v in card.values("FN") if v.strip()]
    if not fns:
        add("error", "missing-fn", "%s has no non-empty FN" % card.ref())
    tels = card.values("TEL")
    emails = card.values("EMAIL")
    if not tels and not emails:
        add("warning", "no-channel", "%s has no TEL and no EMAIL" % card.ref())
    for v in emails:
        nv = normalize_email(v)
        if not EMAIL_RE.match(nv):
            add("warning", "malformed-email",
                "%s has a malformed EMAIL (value fp %s)" % (card.ref(), fingerprint(nv)),
                value_fp=fingerprint(nv))
    for v in tels:
        nv = normalize_phone(v, country_code)
        if len(re.sub(r"\D", "", nv)) < 7:
            add("warning", "suspicious-phone",
                "%s has a TEL with fewer than 7 digits (value fp %s)" % (card.ref(), fingerprint(nv)),
                value_fp=fingerprint(nv))
    for v in card.values("BDAY"):
        if not valid_bday(v):
            add("warning", "malformed-bday", "%s has a malformed BDAY" % card.ref())


def cross_card(cards, country_code, findings):
    groups = []

    def group_finding(severity, code, members, message, value_fp=None):
        f = {"severity": severity, "code": code,
             "cards": [c.number for c in members],
             "card_fps": [c.fp for c in members],
             "file": members[0].label,
             "message": message}
        if value_fp:
            f["value_fp"] = value_fp
        groups.append((members[0].number, code, f))

    by_payload = defaultdict(list)
    for c in cards:
        by_payload[c.payload()].append(c)
    exact_member_ids = set()
    for payload, members in by_payload.items():
        if len(members) > 1:
            exact_member_ids.update(id(c) for c in members)
            group_finding("error", "exact-duplicate", members,
                          "cards %s are exact duplicates (fp %s)" % (
                              ", ".join("#%d" % c.number for c in members),
                              members[0].fp))

    def is_exact_group(members):
        return len({c.payload() for c in members}) == 1 and len(members) > 1

    by_uid = defaultdict(list)
    for c in cards:
        for v in c.values("UID"):
            by_uid[v.strip()].append(c)
    for uid, members in by_uid.items():
        uniq = list({id(c): c for c in members}.values())
        uniq.sort(key=lambda c: c.number)
        if len(uniq) > 1 and not is_exact_group(uniq):
            group_finding("error", "duplicate-uid", uniq,
                          "cards %s share a UID (value fp %s)" % (
                              ", ".join("#%d" % c.number for c in uniq),
                              fingerprint(uid)),
                          value_fp=fingerprint(uid))

    by_phone = defaultdict(list)
    by_email = defaultdict(list)
    for c in cards:
        seen_p, seen_e = set(), set()
        for v in c.values("TEL"):
            nv = normalize_phone(v, country_code)
            if nv and nv not in seen_p:
                by_phone[nv].append(c)
                seen_p.add(nv)
        for v in c.values("EMAIL"):
            nv = normalize_email(v)
            if nv and nv not in seen_e:
                by_email[nv].append(c)
                seen_e.add(nv)
    shared_pairs = set()
    for nv, members in by_phone.items():
        if len(members) > 1 and not is_exact_group(members):
            group_finding("error", "shared-phone", members,
                          "cards %s share a phone (value fp %s)" % (
                              ", ".join("#%d" % c.number for c in members),
                              fingerprint(nv)),
                          value_fp=fingerprint(nv))
            for a in members:
                for b in members:
                    if a.number < b.number:
                        shared_pairs.add((a.number, b.number))
    for nv, members in by_email.items():
        if len(members) > 1 and not is_exact_group(members):
            group_finding("error", "shared-email", members,
                          "cards %s share an email (value fp %s)" % (
                              ", ".join("#%d" % c.number for c in members),
                              fingerprint(nv)),
                          value_fp=fingerprint(nv))
            for a in members:
                for b in members:
                    if a.number < b.number:
                        shared_pairs.add((a.number, b.number))

    by_name = defaultdict(list)
    for c in cards:
        fns = [v for v in c.values("FN") if v.strip()]
        if fns:
            by_name[normalize_name(fns[0])].append(c)
    for nv, members in by_name.items():
        if len(members) < 2 or is_exact_group(members):
            continue
        linked = any((a.number, b.number) in shared_pairs
                     for i, a in enumerate(members) for b in members[i + 1:])
        if not linked:
            group_finding("warning", "name-collision", members,
                          "cards %s share a name but no phone or email "
                          "(value fp %s)" % (
                              ", ".join("#%d" % c.number for c in members),
                              fingerprint(nv)),
                          value_fp=fingerprint(nv))

    groups.sort(key=lambda t: (t[0], t[1]))
    findings.extend(g for _, _, g in groups)


def audit(labels_and_texts, country_code):
    findings = []
    cards = []
    number = 1
    for label, text in labels_and_texts:
        number = parse_file(label, text, country_code, findings, cards, number)
    # Per-card checks run after parsing so fingerprints cover full cards.
    # Parse-time findings were recorded before props were complete for
    # structure errors on the open card; that is acceptable: they carry
    # card_fp=None when the card had no props at that point.
    per_card = []
    for c in cards:
        check_card(c, country_code, per_card)
    # Order: file/parse findings first (in discovery order), then per-card,
    # then cross-card - deterministic for a fixed input set.
    all_findings = findings + per_card
    cross_card(cards, country_code, all_findings)
    return cards, all_findings


def cap_findings(findings, max_examples):
    counts = {}
    order = []
    for f in findings:
        key = (f["severity"], f["code"])
        if key not in counts:
            counts[key] = 0
            order.append(key)
        counts[key] += 1
    shown = []
    seen = defaultdict(int)
    for f in findings:
        key = (f["severity"], f["code"])
        if seen[key] < max_examples:
            shown.append(f)
        seen[key] += 1
    suppressed = {k: counts[k] - min(counts[k], max_examples) for k in counts}
    return shown, counts, order, suppressed


def main(argv=None):
    p = argparse.ArgumentParser(prog="cardferry",
                                description="Read-only vCard preflight gate; "
                                            "reports never print contact values.")
    p.add_argument("--version", action="version", version="cardferry " + VERSION)
    sub = p.add_subparsers(dest="cmd")
    chk = sub.add_parser("check")
    chk.add_argument("files", nargs="+")
    chk.add_argument("--json", action="store_true")
    chk.add_argument("--max-examples", type=int, default=10)
    chk.add_argument("--default-country-code", default="1")
    args = p.parse_args(argv)
    if args.cmd != "check":
        p.print_help()
        return 2
    if args.max_examples < 0:
        print("cardferry: --max-examples must be >= 0", file=sys.stderr)
        return 2
    if not re.fullmatch(r"\d{1,3}", args.default_country_code or ""):
        print("cardferry: --default-country-code must be 1-3 digits", file=sys.stderr)
        return 2
    inputs = []
    for label in args.files:
        try:
            with open(label, "rb") as fh:
                data = fh.read()
        except OSError as e:
            print("cardferry: cannot read %s: %s" % (label, e.strerror or e),
                  file=sys.stderr)
            return 2
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            print("cardferry: %s is not valid UTF-8" % label, file=sys.stderr)
            return 2
        inputs.append((label, text))
    cards, findings = audit(inputs, args.default_country_code)
    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    shown, counts, order, suppressed = cap_findings(findings, args.max_examples)
    if args.json:
        out = {
            "cards": len(cards),
            "errors": errors,
            "warnings": warnings,
            "counts": {"%s:%s" % (sev, code): counts[(sev, code)]
                       for (sev, code) in order},
            "suppressed": {"%s:%s" % (sev, code): suppressed[(sev, code)]
                           for (sev, code) in order if suppressed[(sev, code)]},
            "findings": shown,
        }
        print(json.dumps(out, indent=2, sort_keys=False))
    else:
        for f in shown:
            print("%s %s: %s" % (f["severity"], f["code"], f["message"]))
        for (sev, code) in order:
            if suppressed[(sev, code)]:
                print("... and %d more %s:%s findings" %
                      (suppressed[(sev, code)], sev, code))
        print("cardferry: %d cards, %d errors, %d warnings" %
              (len(cards), errors, warnings))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
