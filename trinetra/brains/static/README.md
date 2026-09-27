# The static brain

Trinetra's bundled, offline static-analysis ruleset. It ships inside the package,
runs with no network access, and never sends scanned code anywhere. Every rule has
annotated test cases, so its precision is measured, not claimed.

## Layout

```
trinetra/brains/static/rules/<language>/<family>.yaml   # the rules
tests/rule_fixtures/<language>/<family>.<ext>            # annotated test code
```

`<language>` is one of `python`, `javascript`, `java`, `php`, `go`, `generic`.
A rules file and its fixture share a relative path and stem, so
`semgrep --test --config trinetra/brains/static/rules tests/rule_fixtures` pairs them.

Never name a directory or file `secrets`, `*.pem`, `*.key` or `.env*`: `.gitignore`
drops those.

## Rule contract

```yaml
rules:
  - id: py-sqli-tainted            # <lang>-<name>, kebab-case, globally unique
    languages: [python]
    severity: ERROR                # ERROR | WARNING | INFO
    message: >-
      What is wrong, why it is dangerous, and how to fix it, in plain words.
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      owasp: "A03:2021 - Injection"
      category: security
      confidence: HIGH             # HIGH | MEDIUM | LOW — be honest
      likelihood: HIGH
      impact: HIGH
      security-severity: "8.8"     # CVSS-style 0-10, ALWAYS a quoted string
      references:
        - https://owasp.org/Top10/A03_2021-Injection/
    mode: taint                    # or plain patterns
    ...
```

- **Id prefixes:** `py-`, `js-`, `java-`, `php-`, `go-`, `secret-`.
- **`security-severity` must be a quoted string.** A bare float crashes Semgrep 1.178.
  Trinetra maps it to severity: >= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0 low.
- **`cwe`** starts with the exact `CWE-<n>` id; **`owasp`** uses the 2021 Top 10 names.
- **Confidence:** taint rules from real user-input sources are `HIGH`. Structural
  rules (a dynamically built string reaching a sink, source unknown) are `MEDIUM`.
  Heuristics (name-based secret detection, weak-hash-on-password) are `MEDIUM` or `LOW`.
- **Two rules on one line is fine** when they catch one issue two ways (a taint rule
  and a structural rule). The Semgrep adapter collapses findings that share a file,
  line and CWE into one, keeping the highest severity.
- Prefer precision: exclude literals, constants, parameterized APIs, and known
  sanitizers (`pattern-not`, `pattern-sanitizers`, `metavariable-regex`).

## Test contract

Annotate the line **after** the comment (Semgrep's `--test` syntax):

```python
# ruleid: py-sqli-tainted
cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")

# ok: py-sqli-tainted
cursor.execute("SELECT * FROM users WHERE id = %s", (request.args["id"],))
```

- Every rule has at least two `ruleid:` cases and two `ok:` cases, written as
  realistic framework code, including safe lookalikes of the vulnerable pattern.
- A known miss is `todoruleid:`; a known false positive is `todook:`. Never delete a
  failing case to make the suite pass. The todo markers keep the numbers honest.
- Several ids on one line: `# ruleid: id-one, id-two`.
- Fake secrets must be obviously fake (contain `FAKE`, `EXAMPLE` or long runs of `0`)
  so nothing real is ever committed and push protection is not tripped.

Run the suite:

```
semgrep --test --metrics off --config trinetra/brains/static/rules tests/rule_fixtures
```
