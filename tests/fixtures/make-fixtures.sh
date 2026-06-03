#!/usr/bin/env bash
#
# Regenerate the .mylogin.cnf test fixtures using MySQL's own
# mysql_config_editor, so the fixtures are authoritative.
#
# mysql_config_editor honors the MYSQL_TEST_LOGIN_FILE environment variable
# to choose the output file instead of the default ~/.mylogin.cnf. The
# password is fed on stdin to avoid the interactive prompt.
#
# The expected contents are asserted in tests.lisp -- keep the two in sync.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mce() { mysql_config_editor "$@"; }

# --- basic.cnf: two login paths with assorted fields --------------------
export MYSQL_TEST_LOGIN_FILE="$DIR/basic.cnf"
rm -f "$MYSQL_TEST_LOGIN_FILE"
printf 'secret\n'     | mce set --login-path=local   --host=localhost               --user=root   --password
printf 'st@ging-pw\n' | mce set --login-path=staging --host=db.staging.example.com  --user=deploy --port=3307 --password

# --- single.cnf: one login path, user only (no password) ----------------
export MYSQL_TEST_LOGIN_FILE="$DIR/single.cnf"
rm -f "$MYSQL_TEST_LOGIN_FILE"
mce set --login-path=client --user=admin

# --- special.cnf: password containing characters that stress parsing ----
export MYSQL_TEST_LOGIN_FILE="$DIR/special.cnf"
rm -f "$MYSQL_TEST_LOGIN_FILE"
printf 'a=b=c#"x\n' | mce set --login-path=weird --user='the user' --password

# --- empty.cnf: a valid file with no login paths ------------------------
export MYSQL_TEST_LOGIN_FILE="$DIR/empty.cnf"
rm -f "$MYSQL_TEST_LOGIN_FILE"
mce reset

echo "Wrote fixtures to $DIR"
ls -l "$DIR"/*.cnf
