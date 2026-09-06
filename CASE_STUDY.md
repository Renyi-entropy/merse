# Case study: adversarially testing Merse against a real MITM injection

2026-09-06. A live WireGuard tunnel (Mint <-> EC2, `wg-irssi` interface
on the Mint side) was deliberately impaired using `tc netem` to test
whether Merse could actually detect tampering, not just plausible-
sounding statistics on clean data.

## Baseline

Captured 5 minutes of real, unmodified tunnel traffic on Mint's local
`wg-irssi` interface (7,152 packets, same side the impairment was
later applied to — see the correction below for why that match
matters). Rolling-mean jitter fit to a 2-state Gaussian HMM:

- calm state: mean 2.4ms
- active state: mean 11.2ms

## Test 1: random jitter injection

```
tc qdisc add dev wg-irssi root netem delay 20ms 15ms distribution normal
```

Captured 2 minutes under this condition, ran `merse check` against the
baseline. Both checks fired hard: LATENCY z=199.5, REGIME z=9.1 (state
means shifted to 24.1ms and 32.1ms, well outside baseline). Verdict:
**COMPROMISED**. Caught cleanly, as expected — variable, noisy
interference is exactly what both checks are built to catch.

## Test 2: fixed-delay relay injection

```
tc qdisc add dev wg-irssi root netem delay 25ms
```

A constant delay, no injected randomness — the timing signature of a
deterministic relay or inserted hop, not a noisy link. Captured 2
minutes, ran the same check.

Result: REGIME check saw almost nothing (z=1.51, reads CLEAN) — the
"active" state came back at 13.4ms, barely different from baseline.
This is a real, structural blind spot worth being honest about: **a
uniform delay applied to every packet doesn't change the spacing
between packets**, so a regime-shift detector built on interarrival
timing is close to blind to a clean constant-delay relay by
construction, no matter how sensitive the estimator.

But LATENCY check (mean-shift of the same jitter series, not the
regime structure) caught it: z=22.6, COMPROMISED overall. The two
checks are sensitive to different things even on the *same* input
series — REGIME can't see a pure mean shift with unchanged shape,
LATENCY can.

## Closing the blind spot further

Interarrival-based jitter is one proxy; round-trip time is a more
direct measurement of the same underlying delay. Pinged the tunnel
gateway (60 samples) before and during the same 25ms-delay impairment:

- baseline RTT: 162.6ms +/- 2.5ms
- impaired RTT: 187.1ms +/- 0.9ms
- shift: 24.5ms (the injected delay was 25ms)
- z = 76.4

A cleaner, more directly interpretable signal than the jitter-mean
catch above (z=76.4 vs z=22.6, and the shift matches the injected
delay almost exactly in real units) — but per the correction below,
not the *only* thing standing between this attack and detection.

**Operational conclusion: REGIME and LATENCY checks are sensitive to
orthogonal tampering signatures, and RTT is a cleaner LATENCY signal
than jitter-mean when available. A real deployment should run all
three where possible.**

## A correction found during a later audit

The first version of this case study compared Test 1/2 against a
baseline captured on **EC2's** side of the tunnel, while the injected-
tampering samples were captured on **Mint's** side (where the
impairment was actually applied) — two different vantage points on an
asymmetric link, not a controlled comparison. Under that mismatched
baseline, Test 2's LATENCY check looked weak (z=-2.76, SUSPECT) and
the write-up concluded RTT was the *only* way to catch a constant-
delay relay.

Rebuilding the baseline from Mint's own traffic (matching the
endpoint the tampering was actually injected at) changed the result:
Mint's baseline turned out measurably different from EC2's (2.4ms/
11.2ms vs 2.8ms/13.6ms calm/active means — the two ends of the tunnel
genuinely see it differently), and against the correctly matched
baseline, Test 2's LATENCY check resolved to COMPROMISED (z=22.6), not
SUSPECT. The tool was more capable than the first draft gave it credit
for; the mismatch was in how the test was set up, not in the detector.

## A real bug, found by adversarial testing

Separately, while building the two-check verdict logic, review
surfaced a fail-open condition: if baseline variance rounded to ~0 (a
too-quiet or too-short baseline), the z-score computation defaulted to
0.0 -- which reads as CLEAN regardless of how large the actual
deviation was. An attacker timing their tampering to coincide with an
unusually quiet baseline capture window would have passed undetected.

Fixed: a degenerate baseline now produces an explicit INDETERMINATE
result and forces the verdict to at least SUSPECT. It can never
silently resolve to CLEAN. Re-verified against both real injected
conditions to confirm the fix didn't regress either detection.

## What this demonstrates

Not "this tool always works," and not "the first write-up was
perfect" either — both would be less useful and less credible than
what actually happened: a specific blind spot found and documented
(REGIME check vs constant delay), a real logic bug found and fixed
(fail-open on degenerate baselines) before shipping, and a real
methodology mistake in the *evaluation itself* found on a later audit
and corrected with the actual numbers shown, not smoothed over. All of
it against real injected tampering on real infrastructure, not
synthetic test data. See `README.md` for the full scope, including
what Merse explicitly does not detect: protocol/session-layer attacks,
compromised keys, passive decryption.
