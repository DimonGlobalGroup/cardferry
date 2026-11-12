# CardFerry

**Audit a set of vCard files before you import them anywhere — with a report that never prints a single contact value.**

Moving contacts between two phones, a backup, and a cloud account is
normally done by importing first and discovering the duplicates
afterwards, inside an address book that is already polluted.
CardFerry is the check that happens *before* the import: a
single-file, stdlib-only, read-only Python gate that audits one or
more `.vcf` files **as one set** and reports what would go wrong —
without ever merging, rewriting, or deleting anything.

```console
$ python3 cardferry.py check phone-a.vcf phone-b.vcf
warning no-channel: card #4 in phone-b.vcf (fp a4c6e72261d7) has no TEL and no EMAIL
error shared-phone: cards #1, #3 share a phone (value fp d17583ae0628)
cardferry: 4 cards, 1 errors, 1 warnings
$ echo $?
1
```

Two exports of the same address book, checked together: one card
has no way to reach its person, and two different cards turn out to
carry the same phone number — written in two different formats
(`+1 (555) 010-2030` in one file, `5550102030` in the other). A
clean file is quiet:

```console
$ python3 cardferry.py check clean.vcf
cardferry: 1 cards, 0 errors, 0 warnings
```

## Why it's different

1. **The report is not a leak.** Contact files are personal data,
   and dedupe tools normally print exactly that data — names,
   numbers, addresses — into terminal logs, CI output, and support
   tickets. CardFerry never prints a name, phone number, email
   address, or UID, in raw or normalized form. Cards are identified
   only by position (`card #3 in phone-b.vcf`) and a short SHA-256
   fingerprint of their normalized contents; a matched phone or
   email is identified only by a fingerprint of the value. A dirty
   verdict is safe to paste anywhere. (This is test-enforced: the
   suite feeds the tool canary contact values and asserts that no
   form of them appears in any output.)
2. **Read-only by construction.** Mergers and duplicate removers
   change the data they judge. CardFerry only judges: exit codes
   0/1/2, deterministic text or JSON output, findings capped per
   code with exact totals always reported. The import decision —
   and any merge — stays with you.
3. **Whole-set, not per-file.** The duplicates that matter during
   a phone-to-phone move live *between* files: last year's export
   against this year's. CardFerry numbers cards globally across
   every file you give it and checks the set as a whole, so
   cross-file duplicates are first-class findings, not invisible.
4. **Conservative matching, stated plainly.** Phones match only
   after the documented normalization below; emails match
   case-folded exactly; names match case/space-folded exactly.
   There is no fuzzy matching and no last-digits guessing — a
   near-match is reported as nothing, never inflated into a
   duplicate claim.

## What it checks

Per card:

| Code | Severity | Meaning |
|---|---|---|
| `missing-fn` | error | No FN property, or every FN is empty |
| `missing-version` | warning | No VERSION property |
| `unknown-version` | warning | VERSION is not 2.1, 3.0, or 4.0 |
| `duplicate-singleton` | warning | VERSION, FN, or UID repeated on one card |
| `no-channel` | warning | The card has no TEL and no EMAIL |
| `malformed-email` | warning | An EMAIL value is not address-shaped |
| `suspicious-phone` | warning | A TEL value has fewer than 7 digits |
| `malformed-bday` | warning | BDAY is not a valid vCard date form |

Structure (per file): content `outside-card`, unbalanced or nested
VCARDs (`structure`), a line with no `:` (`malformed-line`), a file
with `no-cards`, and physical lines over 75 octets (`long-line`,
warning).

Across the set:

| Code | Severity | Meaning |
|---|---|---|
| `exact-duplicate` | error | Two or more cards with identical normalized contents |
| `duplicate-uid` | error | The same UID on different cards |
| `shared-phone` | error | The same normalized phone on different cards |
| `shared-email` | error | The same normalized email on different cards |
| `name-collision` | warning | Same name, but no shared phone/email — namesakes or unlinked duplicates; the tool reports, it does not decide |

Cards that are exact duplicates are reported once, as
`exact-duplicate` — they are not re-reported as shared
phone/email/UID findings.

## Install

Nothing to install. One file, Python 3.10 or newer, standard
library only:

```console
$ python3 cardferry.py check contacts.vcf
```

## Usage

```console
$ python3 cardferry.py check FILE [FILE...] [--json]
    [--max-examples N] [--default-country-code DIGITS]
```

- `--json` — machine-readable report (counts per
  `severity:code`, suppressed counts, findings). Byte-deterministic
  for a fixed input set.
- `--max-examples N` — show at most N findings per code
  (default 10); totals in the counts are always exact.
- `--default-country-code DIGITS` — country code assumed when a
  bare national number needs one (default `1`).

Phone normalization, exactly: a `tel:` URI prefix is stripped; an
extension (`;ext=…`, or a trailing ` x…` / ` ext…`) is cut;
punctuation is dropped; a leading `00` becomes `+`; a bare 10-digit
number gains `+<default-country-code>`; a bare number that already
starts with that code at the right length gains `+`. Anything else
compares as its digit string.

## Exit codes

- `0` — no error findings (warnings may be present)
- `1` — error findings present: do not import until you have
  looked at them
- `2` — usage or I/O error (missing file, invalid UTF-8, bad
  options)

## Limitations, honestly

- Matching is deliberately conservative: two writings of the same
  number that normalization cannot reconcile (for example a number
  stored with a different country code, or a name with a typo) are
  not reported as duplicates.
- Card fingerprints and exact-duplicate matching ignore property
  parameters (`TYPE=cell` and friends) — two cards differing only
  in parameters count as the same card.
- BDAY is validated in the common full and year-less forms only;
  time-valued BDAY forms in vCard 4.0 are reported as malformed.
- CardFerry reads vCard structure; it does not validate every
  property defined by RFC 6350/2426, and a clean report means "no
  findings under these rules," not "every importer will accept
  this file."
- Line-length warnings count octets of the physical lines as
  stored; they say nothing about whether a given importer cares.

## License

MIT — see `LICENSE`. Copyright (c) 2026 Dimon Global Group.
