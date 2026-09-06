# Case study: adversarially testing Merse against a real MITM injection

2026-09-06. A live WireGuard tunnel (Mint <-> EC2, `wg-irssi` interface)
was deliberately impaired using `tc netem` to test whether Merse could
actually detect tampering, not just plausible-sounding statistics on
clean data.

## Baseline

Captured 5 minutes of real, unmodified tunnel traffic (7,818 packets).
Rolling-mean jitter fit to a 2-state Gaussian HMM:

- calm state: mean 2.8ms
- active state: mean 13.6ms

## Test 1: random jitter injection

```
tc qdisc add dev wg-irssi root netem delay 20ms 15ms distribution normal
```

Captured 2 minutes under this condition, ran `merse check` against the
baseline. Both HMM states shifted to 23.9ms and 31.5ms — 9x and 2.3x
above baseline. Verdict: **COMPROMISED**. Caught cleanly, as expected —
variable, noisy interference is exactly what a regime-shift detector
is built to catch.

## Test 2: fixed-delay relay injection

```
tc qdisc add dev wg-irssi root netem delay 25ms
```

A constant delay, no injected randomness — the timing signature of a
deterministic relay or inserted hop, not a noisy link. Captured 2
minutes, ran the same check.

Result: the "active" state came back at 13.4ms — nearly identical to
the clean baseline's 13.6ms. The regime check saw almost nothing.

This isn't a detector failure, it's a structural blind spot worth
being honest about: **a uniform delay applied to every packet doesn't
change the spacing between packets.** Interarrival-based jitter
analysis can only ever see relative timing, so a clean constant-delay
relay is close to invisible to it by construction, no matter how
sensitive the estimator.

## Closing the blind spot

Interarrival timing can't see a constant delay, but round-trip time
can. Pinged the tunnel gateway (60 samples) before and during the same
25ms-delay impairment:

- baseline RTT: 162.6ms ± 2.5ms
- impaired RTT: 187.1ms ± 0.9ms
- shift: 24.5ms (the injected delay was 25ms)
- z = 76.4

Trivial catch, once measuring the right variable. **Regime analysis
and absolute-latency baselining are sensitive to orthogonal tampering
signatures — a real detector needs both, run against both a jitter
series and an RTT series per link.** Neither alone covers the full
threat model.

## A real bug, found by adversarial testing

While building the two-check verdict logic, review surfaced a fail-open
condition: if baseline variance rounded to ~0 (a too-quiet or too-short
baseline), the z-score computation defaulted to 0.0 — which reads as
CLEAN regardless of how large the actual deviation was. An attacker
timing their tampering to coincide with, or benefiting from, an
unusually quiet baseline capture window would have passed undetected.

Fixed: a degenerate baseline now produces an explicit INDETERMINATE
result and forces the verdict to at least SUSPECT. It can never
silently resolve to CLEAN. Re-verified against both real injected
conditions above to confirm the fix didn't regress either detection.

## What this demonstrates

Not "this tool always works" — the opposite is more useful and more
credible: it has a specific, documented blind spot, a specific fix for
it, and a real logic bug that got caught and closed before shipping,
all against actual injected tampering on real infrastructure rather
than synthetic test data. See `README.md` for the full scope
(including what Merse explicitly does not detect: protocol/session-
layer attacks, compromised keys, passive decryption).
