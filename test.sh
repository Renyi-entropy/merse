#!/usr/bin/env bash
# Regression tests for merse: builds from merse.c, asserts `check` exit
# codes (0 CLEAN, 1 SUSPECT, 2 COMPROMISED, 3 error). Deterministic --
# data comes from awk with a fixed seed.
set -u
cd "$(dirname "$0")"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
gcc -O2 -Wall -Wextra -Werror -o "$T/merse" merse.c -lm || exit 1

# gauss <mean> <sd> <n> <seed> -- Box-Muller
gauss() { awk -v m="$1" -v s="$2" -v n="$3" -v seed="$4" 'BEGIN{srand(seed);
  for(i=0;i<n;i++){u=rand();v=rand();if(u<1e-12)u=1e-12;
  printf "%.6f\n", m+s*sqrt(-2*log(u))*cos(6.283185307*v)}}'; }

fail=0
expect() {  # expect <name> <rc> <cmd...>
  local name=$1 want=$2; shift 2
  "$@" >"$T/out" 2>&1; local got=$?
  if [ "$got" = "$want" ]; then echo "PASS  $name (rc=$got)"
  else echo "FAIL  $name: want rc=$want got rc=$got"; sed 's/^/      /' "$T/out"; fail=1; fi
}

gauss 10    1 2000 1 > "$T/base.txt"
gauss 10.12 1 2000 3 > "$T/shift_small.txt"
gauss 13    1 2000 4 > "$T/shift_big.txt"
for i in $(seq 2000); do echo 5.0; done > "$T/flat.txt"
"$T/merse" baseline "$T/base.txt" "$T/b.merse" >/dev/null 2>&1
"$T/merse" baseline "$T/flat.txt" "$T/flat.merse" >/dev/null 2>&1

# the baseline data itself is the only guaranteed-CLEAN sample: merse's
# latency SE ignores the baseline's own sampling error, so two independent
# clean draws cross |z|>2 ~16% of the time
expect "unchanged sample -> CLEAN"    0 "$T/merse" check "$T/base.txt"        "$T/b.merse"
expect "small mean shift -> SUSPECT"  1 "$T/merse" check "$T/shift_small.txt" "$T/b.merse"
expect "large shift -> COMPROMISED"   2 "$T/merse" check "$T/shift_big.txt"   "$T/b.merse"
expect "flat baseline fails closed"   1 "$T/merse" check "$T/base.txt"        "$T/flat.merse"

# Regression: one REGIME state indeterminate (state1_sd ~ 0) must not
# hide the other state's valid deviation. Baseline mean pinned to the
# sample's own mean so LATENCY is exactly clean (z=0) -- the case the old
# code got wrong: sample low state ~9.7 vs baseline 5.0 +- 0.1 -> z ~ 47
# was reported SUSPECT (indeterminate) instead of COMPROMISED.
M=$(awk '{s+=$1} END{printf "%.10g", s/NR}' "$T/base.txt")
printf 'n 2000\nmean %s\nstd 1\nstate0_mu 5\nstate0_sd 0.1\nstate1_mu 10\nstate1_sd 1e-12\n' "$M" > "$T/partial.merse"
expect "partial REGIME: valid state still counts" 2 "$T/merse" check "$T/base.txt" "$T/partial.merse"
# ...and with no real deviation, the indeterminate state still floors at SUSPECT
printf 'n 2000\nmean %s\nstd 1\nstate0_mu %s\nstate0_sd 1\nstate1_mu 10\nstate1_sd 1e-12\n' "$M" "$M" > "$T/partial_ok.merse"
expect "partial REGIME: indeterminate floors SUSPECT" 1 "$T/merse" check "$T/base.txt" "$T/partial_ok.merse"

head -3 "$T/b.merse" > "$T/trunc.merse"
printf '1\n2\nabc\n' > "$T/junk.txt"
expect "truncated baseline"  3 "$T/merse" check "$T/base.txt"  "$T/trunc.merse"
expect "non-numeric input"   3 "$T/merse" check "$T/junk.txt"  "$T/b.merse"
expect "missing file"        3 "$T/merse" check "$T/nope.txt"  "$T/b.merse"
expect "no args"             3 "$T/merse"
expect "unknown command"     3 "$T/merse" foo a b

exit $fail
