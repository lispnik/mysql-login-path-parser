# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Native Common Lisp parser for MySQL's obfuscated `~/.mylogin.cnf` login-path file (written by `mysql_config_editor`). Library only — no executable. Depends on ironclad (AES) and babel (UTF-8 decoding).

## Commands

Dependencies are managed by **ocicl** (not Quicklisp); systems live in `ocicl/` with pinned digests in `ocicl.csv`. `~/.sbclrc` loads the ocicl runtime and adds the current working directory to the ASDF source registry, so **all `sbcl` commands must be run from the repo root**.

```sh
# Run the full test suite
sbcl --non-interactive --eval '(asdf:test-system :mysql-login-path-parser)'

# Load the library only (REPL / manual poking)
sbcl --non-interactive --eval '(asdf:load-system :mysql-login-path-parser)' --eval '<expr>'

# Run a single FiveAM test
sbcl --non-interactive \
     --eval '(asdf:load-system :mysql-login-path-parser/tests)' \
     --eval '(fiveam:run! (quote mysql-login-path-parser.tests::test-parse-basic-fixture))'

# Add a dependency
ocicl install <system>
```

CI (`.github/workflows/test.yml`) reproduces this on Ubuntu/SBCL and fails the build when `run-mysql-tests` returns NIL.

## File format and decryption pipeline

`parser.lisp` implements the format reverse-engineered from MySQL source; the layout is documented in the header comment there. The pipeline, in order:

1. `read-aes-key-from-file` / `fold-aes-key` — the file stores a **20-byte** key after a 4-byte unused version header. The real AES-128 key is that key XOR-*folded* to 16 bytes (`rkey[i mod 16] ^= key[i]`), mirroring MySQL's `my_aes_create_key`. This folding is the non-obvious part; the stored key is not the cipher key.
2. `decrypt-mylogin-text` — the body is a sequence of chunks, each a 4-byte little-endian length followed by that many bytes of AES-128-**ECB** ciphertext. Each chunk is decrypted independently and PKCS7-unpadded. `decrypt-mysql-data` rejects a chunk that is not a whole number of 16-byte blocks (ironclad's ECB decrypt would otherwise silently leave the trailing bytes unwritten), and `strip-pkcs7-padding` validates *every* padding byte — that check doubles as the only integrity signal that the key folding was right. The concatenated plaintext is **UTF-8** and is decoded as a whole via babel; decoding byte-by-byte mangles non-ASCII credentials.
3. `parse-ini-text` → `unquote-value` → `unescape-option-value` — INI sections become `(path-name . ((key . value) ...))` alists. Values keep `=` and `#` literally; only a *fully* surrounding pair of double quotes is stripped, and MySQL option-file backslash escapes (`\b \t \n \r \s \\ \"`) are processed inside quotes only.

## Error-handling contract

Two deliberately different layers, do not collapse them:

- `parse-mylogin-cnf` **signals** — it wraps any unexpected error in `mysql-login-path-parse-error` so callers only ever see the `mysql-login-path-error` hierarchy.
- `get-login-path-credentials` and `list-login-paths` **swallow** `mysql-login-path-error` and return `nil` / `'()`. This is intentional: they are the convenience API and must let callers fall back to other credential sources rather than blow up. Keep them non-signaling.

A header-only file (exactly 24 bytes) is valid and parses to `'()`. Anything else that does not end exactly on a chunk boundary — a partial 4-byte length header, a zero length, a chunk running past EOF — signals `mysql-login-path-parse-error`. **Never degrade that back into ending the decode loop early**: partial results from a truncated file are indistinguishable to the caller from a short-but-valid one.

## Tests and fixtures

Three layers, in increasing order of what they can cover:

1. **Fixtures** — `tests/fixtures/*.cnf` are real files produced by MySQL's own `mysql_config_editor` via `tests/fixtures/make-fixtures.sh` (which uses `MYSQL_TEST_LOGIN_FILE` to redirect output). They are the authority on the format and are the only layer that runs on CI. Their expected contents are hard-asserted in `tests.lisp`, so **the script and the assertions must be kept in sync**. Regenerating requires MySQL client tools locally; the script rewrites *all* fixtures with fresh keys, so generate a single new one by hand if you want to avoid churning the others.
2. **Synthetic images** — `synthetic-mylogin` builds a `.mylogin.cnf` in memory (header + folded key + encrypted chunks). Use this for inputs `mysql_config_editor` will never produce: corrupt chunks, truncation, arbitrary byte sequences.
3. **Live tests** — these drive the real MySQL tools and `skip` when they are absent, which is the case on CI, so `run-mysql-tests` still exits 0 there. This is the only layer that catches format drift in a new MySQL release. Two kinds: `with-live-login-file` writes with `mysql_config_editor` and reads back what it wrote, and `test-live-fixtures-match-my-print-defaults` compares our output against MySQL's own option parser on every fixture.

Tests reach internal symbols with `mysql-login-path-parser::` for unit tests of the low-level helpers; exported symbols come in via `:use`.

### Picking the right MySQL tool as an oracle

Getting this wrong wastes time, because the two tools disagree and only one of them answers the question you usually have.

- **`my_print_defaults --show <path>` is the oracle.** It runs the same option-file code the mysql client does, so it reports values *after* unescaping — which is what you want when checking whether this parser resolves escapes correctly. `--show` is essential: without it passwords come back as `*****`, and the password is the field most worth checking. Verified: our output matches it exactly on every fixture, including `\"` and UTF-8.
- **`mysql_config_editor print --all` is NOT.** It is a raw dump of the decrypted text — it echoes the stored quoting and escaping verbatim (literal tabs, surrounding quotes, `\` sequences) and masks passwords. Useful only as a structural oracle (which login paths exist). It briefly looks like this parser diverges from MySQL when compared against it; it does not. **Do not "fix" the parser to match its output.**

One genuine MySQL quirk sits underneath all this: `mysql_config_editor` escapes `"` on write but *not* `\`, so a value like `back\slash` reaches the file with a single backslash and its `\s` is then read as the escape for a space. Both MySQL and this parser read it back as `back lash` — the data was lost on write, by MySQL, and no reader can recover it. `test-live-escaping-matches-mysql` proves the agreement rather than assuming it, so don't chase a round-trip fix for backslash-bearing values.
