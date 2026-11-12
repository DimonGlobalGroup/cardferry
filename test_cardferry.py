import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "cardferry.py")
sys.path.insert(0, HERE)
import cardferry  # noqa: E402

ALICE = """BEGIN:VCARD
VERSION:4.0
FN:Alice Example
TEL;TYPE=cell:+1 (555) 010-2030
EMAIL:alice@example.test
UID:urn:uuid:alice-1
END:VCARD
"""
ALICE_ALT_PHONE_FORMAT = """BEGIN:VCARD
VERSION:4.0
FN:Alice Example
TEL:5550102030
EMAIL:other@example.test
UID:urn:uuid:alice-2
END:VCARD
"""
BOB = """BEGIN:VCARD
VERSION:3.0
FN:Bob Sample
EMAIL:bob@example.test
END:VCARD
"""


def run_cli(files, *extra):
    cmd = [sys.executable, TOOL, "check"] + files + list(extra)
    return subprocess.run(cmd, capture_output=True, text=True)


class CardFerryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        return p

    def test_clean_single_card_exit_0(self):
        f = self.write("a.vcf", ALICE)
        r = run_cli([f])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cardferry: 1 cards, 0 errors, 0 warnings", r.stdout)

    def test_clean_two_distinct_cards(self):
        f = self.write("a.vcf", ALICE + BOB)
        r = run_cli([f])
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_shared_phone_across_formats_is_error(self):
        f = self.write("a.vcf", ALICE + ALICE_ALT_PHONE_FORMAT)
        r = run_cli([f, "--json"])
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertEqual(data["counts"].get("error:shared-phone"), 1)

    def test_phone_normalization_variants(self):
        n = cardferry.normalize_phone
        self.assertEqual(n("+1 (555) 010-2030", "1"), "+15550102030")
        self.assertEqual(n("5550102030", "1"), "+15550102030")
        self.assertEqual(n("1-555-010-2030", "1"), "+15550102030")
        self.assertEqual(n("tel:+1-555-010-2030;ext=9", "1"), "+15550102030")
        self.assertEqual(n("+1 555 010 2030 x42", "1"), "+15550102030")
        self.assertEqual(n("0044 20 7946 0958", "1"), "+442079460958")

    def test_exact_duplicate(self):
        f = self.write("a.vcf", ALICE + ALICE)
        r = run_cli([f, "--json"])
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertEqual(data["counts"].get("error:exact-duplicate"), 1)
        # exact duplicates are not re-reported as shared phone/email/uid
        self.assertNotIn("error:shared-phone", data["counts"])
        self.assertNotIn("error:duplicate-uid", data["counts"])

    def test_duplicate_uid_different_cards(self):
        other = ALICE.replace("alice@example.test", "alice2@example.test").replace(
            "+1 (555) 010-2030", "+1 (555) 999-8888")
        f = self.write("a.vcf", ALICE + other)
        r = run_cli([f, "--json"])
        data = json.loads(r.stdout)
        self.assertEqual(data["counts"].get("error:duplicate-uid"), 1)

    def test_shared_email_casefolded(self):
        other = BOB.replace("bob@example.test", "ALICE@EXAMPLE.TEST").replace(
            "Bob Sample", "Carol Sample")
        f = self.write("a.vcf", ALICE + other)
        r = run_cli([f, "--json"])
        data = json.loads(r.stdout)
        self.assertEqual(data["counts"].get("error:shared-email"), 1)

    def test_name_collision_is_warning_only(self):
        a = ALICE.replace("alice@example.test", "a1@example.test").replace(
            "+1 (555) 010-2030", "+1 (555) 111-1111").replace("alice-1", "u1")
        b = ALICE.replace("alice@example.test", "a2@example.test").replace(
            "+1 (555) 010-2030", "+1 (555) 222-2222").replace("alice-1", "u2")
        f = self.write("a.vcf", a + b)
        r = run_cli([f, "--json"])
        self.assertEqual(r.returncode, 0, r.stdout)
        data = json.loads(r.stdout)
        self.assertEqual(data["counts"].get("warning:name-collision"), 1)

    def test_missing_fn_is_error(self):
        bad = "BEGIN:VCARD\nVERSION:4.0\nEMAIL:x@example.test\nEND:VCARD\n"
        f = self.write("a.vcf", bad)
        r = run_cli([f, "--json"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("error:missing-fn", json.loads(r.stdout)["counts"])

    def test_missing_version_and_no_channel_warnings(self):
        card = "BEGIN:VCARD\nFN:Solo Name\nEND:VCARD\n"
        f = self.write("a.vcf", card)
        r = run_cli([f, "--json"])
        self.assertEqual(r.returncode, 0)
        counts = json.loads(r.stdout)["counts"]
        self.assertIn("warning:missing-version", counts)
        self.assertIn("warning:no-channel", counts)

    def test_malformed_email_and_bday_and_short_phone(self):
        card = ("BEGIN:VCARD\nVERSION:4.0\nFN:Bad Fields\n"
                "EMAIL:not-an-email\nTEL:123\nBDAY:20261340\nEND:VCARD\n")
        f = self.write("a.vcf", card)
        r = run_cli([f, "--json"])
        counts = json.loads(r.stdout)["counts"]
        self.assertIn("warning:malformed-email", counts)
        self.assertIn("warning:suspicious-phone", counts)
        self.assertIn("warning:malformed-bday", counts)

    def test_valid_bday_forms(self):
        for bday in ("19900115", "1990-01-15", "--0115", "--01-15"):
            card = ("BEGIN:VCARD\nVERSION:4.0\nFN:B Day\nEMAIL:b@example.test\n"
                    "BDAY:%s\nEND:VCARD\n" % bday)
            f = self.write("a.vcf", card)
            r = run_cli([f, "--json"])
            self.assertNotIn("warning:malformed-bday",
                             json.loads(r.stdout)["counts"], bday)

    def test_outside_card_and_unterminated(self):
        f = self.write("a.vcf", "FN:Loose\nBEGIN:VCARD\nVERSION:4.0\nFN:Never Closed\n")
        r = run_cli([f, "--json"])
        self.assertEqual(r.returncode, 1)
        counts = json.loads(r.stdout)["counts"]
        self.assertIn("error:outside-card", counts)
        self.assertIn("error:structure", counts)

    def test_no_cards_error(self):
        f = self.write("a.vcf", "\n\n")
        r = run_cli([f, "--json"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("error:no-cards", json.loads(r.stdout)["counts"])

    def test_malformed_line(self):
        card = "BEGIN:VCARD\nVERSION:4.0\nFN Ok\nFN:Has Name\nEMAIL:h@example.test\nEND:VCARD\n"
        # Note: "FN Ok" has a space but no colon.
        f = self.write("a.vcf", card)
        r = run_cli([f, "--json"])
        self.assertIn("error:malformed-line", json.loads(r.stdout)["counts"])

    def test_folded_line_and_group_prefix(self):
        card = ("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Folded \r\n Name\r\n"
                "item1.EMAIL;TYPE=home:fold@example.test\r\nEND:VCARD\r\n")
        f = self.write("a.vcf", card)
        r = run_cli([f])
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_cross_file_duplicate_numbering(self):
        f1 = self.write("one.vcf", ALICE)
        f2 = self.write("two.vcf", ALICE)
        r = run_cli([f1, f2, "--json"])
        data = json.loads(r.stdout)
        dup = [x for x in data["findings"] if x["code"] == "exact-duplicate"][0]
        self.assertEqual(dup["cards"], [1, 2])

    def test_privacy_no_values_in_output(self):
        secret_name = "Zqxylphia Uniquename"
        secret_phone = "+1 (555) 314-2718"
        secret_email = "zqxylphia@privmail.example.test"
        card1 = ("BEGIN:VCARD\nVERSION:4.0\nFN:%s\nTEL:%s\nEMAIL:%s\n"
                 "UID:secret-uid-12345\nEND:VCARD\n"
                 % (secret_name, secret_phone, secret_email))
        card2 = card1.replace("secret-uid-12345", "secret-uid-67890").replace(
            secret_email, "other@privmail.example.test")
        f = self.write("a.vcf", card1 + card2)
        for extra in ([], ["--json"]):
            r = run_cli([f] + list(extra))
            blob = r.stdout + r.stderr
            for secret in (secret_name, "Zqxylphia", secret_phone, "314-2718",
                           "3142718", secret_email, "secret-uid-12345",
                           "+15553142718"):
                self.assertNotIn(secret, blob, (extra, secret))

    def test_determinism(self):
        f = self.write("a.vcf", ALICE + ALICE_ALT_PHONE_FORMAT + BOB)
        r1 = run_cli([f, "--json"])
        r2 = run_cli([f, "--json"])
        self.assertEqual(r1.stdout, r2.stdout)

    def test_missing_file_exit_2(self):
        r = run_cli([os.path.join(self.dir, "nope.vcf")])
        self.assertEqual(r.returncode, 2)

    def test_invalid_utf8_exit_2(self):
        p = os.path.join(self.dir, "bad.vcf")
        with open(p, "wb") as fh:
            fh.write(b"BEGIN:VCARD\nFN:\xff\xfe\nEND:VCARD\n")
        r = run_cli([p])
        self.assertEqual(r.returncode, 2)

    def test_max_examples_cap_counts_exact(self):
        cards = ""
        for i in range(15):
            cards += ("BEGIN:VCARD\nVERSION:4.0\nEMAIL:e%d@example.test\nEND:VCARD\n" % i)
        f = self.write("a.vcf", cards)
        r = run_cli([f, "--json", "--max-examples", "3"])
        data = json.loads(r.stdout)
        self.assertEqual(data["counts"]["error:missing-fn"], 15)
        shown = [x for x in data["findings"] if x["code"] == "missing-fn"]
        self.assertEqual(len(shown), 3)
        self.assertEqual(data["suppressed"]["error:missing-fn"], 12)

    def test_duplicate_singleton_warning(self):
        card = ("BEGIN:VCARD\nVERSION:4.0\nVERSION:4.0\nFN:Dup Prop\n"
                "EMAIL:d@example.test\nEND:VCARD\n")
        f = self.write("a.vcf", card)
        r = run_cli([f, "--json"])
        self.assertIn("warning:duplicate-singleton", json.loads(r.stdout)["counts"])

    def test_unknown_version_warning(self):
        card = ALICE.replace("VERSION:4.0", "VERSION:9.9")
        f = self.write("a.vcf", card)
        r = run_cli([f, "--json"])
        self.assertIn("warning:unknown-version", json.loads(r.stdout)["counts"])

    def test_long_line_warning(self):
        card = ("BEGIN:VCARD\nVERSION:4.0\nFN:Long Note Person\n"
                "EMAIL:l@example.test\nNOTE:" + "x" * 90 + "\nEND:VCARD\n")
        f = self.write("a.vcf", card)
        r = run_cli([f, "--json"])
        self.assertIn("warning:long-line", json.loads(r.stdout)["counts"])

    def test_version_flag(self):
        r = subprocess.run([sys.executable, TOOL, "--version"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("1.0.0", r.stdout)


if __name__ == "__main__":
    unittest.main()
