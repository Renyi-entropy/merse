/* merse.c -- boundary detector. "Merse": Old English for a march/
 * boundary -- the line between clean and compromised.
 *
 * Detects whether a channel (network link, or any numeric series) has
 * drifted from an established clean baseline, using the two checks
 * validated adversarially against a real WireGuard MITM injection
 * test (2026-09-06):
 *
 *   1. REGIME check -- fit a 2-state Gaussian HMM on the input,
 *      compare its state means against a saved baseline HMM's state
 *      means. Catches noisy/variable tampering (e.g. a relay with
 *      inconsistent processing delay): a real injection test showed
 *      state means shift 9x/2.3x above baseline under random jitter.
 *
 *   2. LATENCY check -- compare the input's mean against the
 *      baseline's mean via a z-test (baseline std, standard error
 *      scaled by new sample size). Catches constant-delay tampering
 *      (e.g. a deterministic relay/inserted hop) that the regime
 *      check is structurally blind to: a uniform delay shift doesn't
 *      change inter-sample spacing at all. Real test: 25ms injected
 *      delay -> z=76.4 on this check, while regime check barely moved.
 *
 * Neither check alone covers both tampering signatures. Both are run
 * on every `merse check` call; verdict is the worse of the two.
 *
 * Input format: one number per line (already-preprocessed by the
 * caller -- e.g. rolling jitter, RTT samples, any monitored metric).
 * This binary is domain-agnostic; capturing the raw data (tcpdump,
 * ping, etc.) is the caller's job, not this tool's.
 *
 * Usage:
 *   merse baseline <values_file> <baseline_out_file>
 *   merse check    <values_file> <baseline_file>
 *
 * Compile: gcc -O3 -Wall -o merse merse.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#define N_RESTARTS 6
#define N_EM_ITERS 80
/* below this, a 2-state HMM fit is prone to overfitting noise rather
 * than finding real regimes -- empirically found during development
 * (a 5-min/224-sample crypto window scored WORSE than its own
 * shuffle-null, a clean overfitting signature, not evidence of "no
 * regime"). Not a hard limit, just an honest warning threshold. */
#define MIN_RELIABLE_SAMPLES 500

static uint64_t rng_state[2];
static uint64_t xorshift128plus(void) {
    uint64_t x = rng_state[0]; uint64_t const y = rng_state[1];
    rng_state[0] = y; x ^= x << 23; x ^= x >> 17; x ^= y ^ (y >> 26);
    rng_state[1] = x; return x + y;
}
static double uniform01(void) { return (xorshift128plus() >> 11) * (1.0/9007199254740992.0); }
static void seed_rng(uint64_t seed) {
    rng_state[0] = seed * 2685821657736338717ULL + 1;
    rng_state[1] = seed * 3269478271480010147ULL + 1;
}

static double *read_values(const char *path, long *n_out) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "merse: cannot open %s\n", path); exit(1); }
    long cap = 1024, n = 0;
    double *v = malloc(cap * sizeof(double));
    double x;
    while (fscanf(f, "%lf", &x) == 1) {
        if (n >= cap) { cap *= 2; v = realloc(v, cap * sizeof(double)); }
        v[n++] = x;
    }
    /* fscanf stops silently on the first non-numeric token (a stray
     * header/blank/comment line, a corrupted row) -- without this
     * check that truncates the read with no warning, and a security
     * tool silently working from a partial capture is the same
     * fail-open class of bug as the z=0 default fixed earlier. Fail
     * loudly instead: if we're not cleanly at EOF, something in the
     * file wasn't a number and the rest was dropped. */
    if (!feof(f)) {
        fprintf(stderr, "merse: %s contains non-numeric content after %ld values -- refusing a silently truncated read\n", path, n);
        fclose(f); exit(1);
    }
    fclose(f);
    if (n < 10) { fprintf(stderr, "merse: need at least 10 values, got %ld\n", n); exit(1); }
    if (n < MIN_RELIABLE_SAMPLES)
        fprintf(stderr, "merse: WARNING -- only %ld samples (< %d); HMM regime fit is likely underpowered/overfit at this size, treat REGIME check with suspicion\n", n, MIN_RELIABLE_SAMPLES);
    *n_out = n;
    return v;
}

static void mean_std(const double *x, long n, double *mean_out, double *std_out) {
    double m = 0; for (long i=0;i<n;i++) m += x[i]; m /= n;
    double v = 0; for (long i=0;i<n;i++) v += (x[i]-m)*(x[i]-m); v /= n;
    *mean_out = m; *std_out = sqrt(v);
}

/* ---- 2-state Gaussian HMM, Baum-Welch/EM from scratch ---- */
static double gauss_pdf(double x, double mu, double sigma2) {
    if (sigma2 < 1e-12) sigma2 = 1e-12;
    double d = x - mu;
    return exp(-0.5*d*d/sigma2) / sqrt(2.0*M_PI*sigma2);
}

typedef struct { double pi[2]; double A[2][2]; double mu[2]; double sigma2[2]; } HMM2;

static double fit_hmm2_once(const double *x, long T, HMM2 *out) {
    double xmin=x[0], xmax=x[0]; for (long t=1;t<T;t++){ if(x[t]<xmin)xmin=x[t]; if(x[t]>xmax)xmax=x[t]; }
    double xmean, xstd; mean_std(x, T, &xmean, &xstd);
    double xvar = xstd*xstd;

    HMM2 h;
    for (int k=0;k<2;k++) {
        h.mu[k] = xmin + (xmax-xmin)*(k+0.5)/2.0 + (uniform01()-0.5)*(xmax-xmin)*0.05;
        h.sigma2[k] = xvar * (0.5 + uniform01());
        h.pi[k] = 0.5;
        for (int l=0;l<2;l++) h.A[k][l] = (k==l) ? 0.85 : 0.15;
    }

    double **alpha_hat = malloc(T*sizeof(double*));
    double **beta_hat = malloc(T*sizeof(double*));
    double **gamma = malloc(T*sizeof(double*));
    double *c = malloc(T*sizeof(double));
    for (long t=0;t<T;t++){ alpha_hat[t]=malloc(2*sizeof(double)); beta_hat[t]=malloc(2*sizeof(double)); gamma[t]=malloc(2*sizeof(double)); }
    double ***xi = malloc((T-1)*sizeof(double**));
    for (long t=0;t<T-1;t++){ xi[t]=malloc(2*sizeof(double*)); for(int k=0;k<2;k++) xi[t][k]=malloc(2*sizeof(double)); }

    double loglik = -1e18;
    for (int iter = 0; iter < N_EM_ITERS; iter++) {
        double a0sum=0;
        for (int k=0;k<2;k++){ alpha_hat[0][k]=h.pi[k]*gauss_pdf(x[0],h.mu[k],h.sigma2[k]); a0sum+=alpha_hat[0][k]; }
        c[0]=a0sum; for(int k=0;k<2;k++) alpha_hat[0][k]/=c[0];
        for (long t=1;t<T;t++){
            double s=0;
            for (int k=0;k<2;k++){
                double acc=0; for(int j=0;j<2;j++) acc+=alpha_hat[t-1][j]*h.A[j][k];
                alpha_hat[t][k]=acc*gauss_pdf(x[t],h.mu[k],h.sigma2[k]);
                s+=alpha_hat[t][k];
            }
            c[t]=s; for(int k=0;k<2;k++) alpha_hat[t][k]/=c[t];
        }
        double ll=0; for(long t=0;t<T;t++) ll+=log(c[t]);

        for (int k=0;k<2;k++) beta_hat[T-1][k]=1.0;
        for (long t=T-2;t>=0;t--){
            for (int k=0;k<2;k++){
                double acc=0;
                for(int j=0;j<2;j++) acc += h.A[k][j]*gauss_pdf(x[t+1],h.mu[j],h.sigma2[j])*beta_hat[t+1][j];
                beta_hat[t][k]=acc/c[t+1];
            }
        }
        for (long t=0;t<T;t++){
            double s=0; for(int k=0;k<2;k++){ gamma[t][k]=alpha_hat[t][k]*beta_hat[t][k]; s+=gamma[t][k]; }
            for(int k=0;k<2;k++) gamma[t][k]/=s;
        }
        for (long t=0;t<T-1;t++){
            for (int k=0;k<2;k++) for (int l=0;l<2;l++)
                xi[t][k][l] = alpha_hat[t][k]*h.A[k][l]*gauss_pdf(x[t+1],h.mu[l],h.sigma2[l])*beta_hat[t+1][l]/c[t+1];
        }

        for (int k=0;k<2;k++) h.pi[k]=gamma[0][k];
        for (int k=0;k<2;k++){
            double denom=0; for(long t=0;t<T-1;t++) denom+=gamma[t][k];
            for (int l=0;l<2;l++){
                double num=0; for(long t=0;t<T-1;t++) num+=xi[t][k][l];
                h.A[k][l] = (denom>1e-12) ? num/denom : 0.5;
            }
        }
        for (int k=0;k<2;k++){
            double denom=0, summu=0;
            for(long t=0;t<T;t++){ denom+=gamma[t][k]; summu+=gamma[t][k]*x[t]; }
            h.mu[k] = (denom>1e-12) ? summu/denom : xmean;
            double sv=0; for(long t=0;t<T;t++) sv += gamma[t][k]*(x[t]-h.mu[k])*(x[t]-h.mu[k]);
            h.sigma2[k] = (denom>1e-12) ? sv/denom : xvar;
        }

        if (fabs(ll-loglik) < 1e-6*fabs(loglik) && iter > 5) { loglik=ll; break; }
        loglik = ll;
    }

    for (long t=0;t<T;t++){ free(alpha_hat[t]); free(beta_hat[t]); free(gamma[t]); }
    for (long t=0;t<T-1;t++){ for(int k=0;k<2;k++) free(xi[t][k]); free(xi[t]); }
    free(alpha_hat); free(beta_hat); free(gamma); free(xi); free(c);

    if (h.mu[0] > h.mu[1]) {
        double t;
        t=h.mu[0]; h.mu[0]=h.mu[1]; h.mu[1]=t;
        t=h.sigma2[0]; h.sigma2[0]=h.sigma2[1]; h.sigma2[1]=t;
        t=h.pi[0]; h.pi[0]=h.pi[1]; h.pi[1]=t;
        double a00=h.A[0][0], a01=h.A[0][1], a10=h.A[1][0], a11=h.A[1][1];
        h.A[0][0]=a11; h.A[0][1]=a10; h.A[1][0]=a01; h.A[1][1]=a00;
    }

    *out = h;
    return loglik;
}

static HMM2 fit_hmm2_best(const double *x, long T) {
    HMM2 best; double best_ll = -1e300;
    for (int r = 0; r < N_RESTARTS; r++) {
        HMM2 h; double ll = fit_hmm2_once(x, T, &h);
        if (ll > best_ll) { best_ll = ll; best = h; }
    }
    return best;
}

/* ---- baseline file I/O ---- */
typedef struct {
    long n;
    double mean, std;
    double state_mu[2], state_sd[2];
} Baseline;

static void save_baseline(const char *path, const Baseline *b) {
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "merse: cannot write %s\n", path); exit(1); }
    fprintf(f, "n %ld\n", b->n);
    fprintf(f, "mean %.10g\n", b->mean);
    fprintf(f, "std %.10g\n", b->std);
    fprintf(f, "state0_mu %.10g\n", b->state_mu[0]);
    fprintf(f, "state0_sd %.10g\n", b->state_sd[0]);
    fprintf(f, "state1_mu %.10g\n", b->state_mu[1]);
    fprintf(f, "state1_sd %.10g\n", b->state_sd[1]);
    fclose(f);
}

/* Every field below must actually be present in the file -- a
 * Baseline missing just one (e.g. "mean" dropped by a corrupted or
 * interrupted write, while "std"/state fields stay legitimately
 * nonzero) would otherwise silently keep the zero-initialized default
 * and pass the MIN_BASELINE_SD variance-floor check further down,
 * which only screens std/state_sd, not mean. That's the same
 * fail-open class of bug already fixed for the z=0 default and the
 * silently-truncated values-file read -- close it here too by
 * requiring every key to be seen at least once. */
static const char *const REQUIRED_BASELINE_KEYS[] = {
    "n", "mean", "std", "state0_mu", "state0_sd", "state1_mu", "state1_sd"
};
#define N_REQUIRED_BASELINE_KEYS (sizeof(REQUIRED_BASELINE_KEYS)/sizeof(REQUIRED_BASELINE_KEYS[0]))

static Baseline load_baseline(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "merse: cannot open baseline %s\n", path); exit(1); }
    Baseline b = {0};
    int seen[N_REQUIRED_BASELINE_KEYS] = {0};
    char key[64]; double val;
    while (fscanf(f, "%63s %lf", key, &val) == 2) {
        if (!strcmp(key,"n")) { b.n=(long)val; seen[0]=1; }
        else if (!strcmp(key,"mean")) { b.mean=val; seen[1]=1; }
        else if (!strcmp(key,"std")) { b.std=val; seen[2]=1; }
        else if (!strcmp(key,"state0_mu")) { b.state_mu[0]=val; seen[3]=1; }
        else if (!strcmp(key,"state0_sd")) { b.state_sd[0]=val; seen[4]=1; }
        else if (!strcmp(key,"state1_mu")) { b.state_mu[1]=val; seen[5]=1; }
        else if (!strcmp(key,"state1_sd")) { b.state_sd[1]=val; seen[6]=1; }
    }
    fclose(f);

    int n_missing = 0;
    for (size_t i = 0; i < N_REQUIRED_BASELINE_KEYS; i++) {
        if (!seen[i]) {
            fprintf(stderr, "merse: baseline %s is missing required field '%s'\n",
                    path, REQUIRED_BASELINE_KEYS[i]);
            n_missing++;
        }
    }
    if (n_missing > 0) {
        fprintf(stderr, "merse: refusing a corrupted/incomplete baseline (%d field%s missing) --\n"
                        "       re-run 'merse baseline' to regenerate it\n",
                n_missing, n_missing == 1 ? "" : "s");
        exit(1);
    }
    return b;
}

/* MIN_BASELINE_SD: if baseline variance is below this, a z-score can't
 * be trusted -- NOT the same as "no deviation." Fail closed: this
 * check reports INDETERMINATE, never CLEAN, and forces the overall
 * verdict to at least SUSPECT. Silently returning z=0 here (as an
 * earlier version did) is a fail-open logic bug: a low-variance or
 * short baseline capture window would make an arbitrarily large real
 * deviation score identically to "no deviation at all." */
#define MIN_BASELINE_SD 1e-9

static const char *verdict_label(double z) {
    double az = fabs(z);
    if (az < 2.0) return "CLEAN";
    if (az < 5.0) return "SUSPECT";
    return "COMPROMISED";
}

static void cmd_baseline(const char *values_path, const char *out_path) {
    long n; double *x = read_values(values_path, &n);
    seed_rng(0xC0FFEE);

    double mean, std; mean_std(x, n, &mean, &std);
    HMM2 h = fit_hmm2_best(x, n);

    Baseline b;
    b.n = n; b.mean = mean; b.std = std;
    b.state_mu[0] = h.mu[0]; b.state_sd[0] = sqrt(h.sigma2[0]);
    b.state_mu[1] = h.mu[1]; b.state_sd[1] = sqrt(h.sigma2[1]);
    save_baseline(out_path, &b);

    printf("merse: baseline recorded from %ld samples -> %s\n", n, out_path);
    printf("  overall mean=%.6f std=%.6f\n", mean, std);
    printf("  state 0 (low):  mu=%.6f sd=%.6f\n", b.state_mu[0], b.state_sd[0]);
    printf("  state 1 (high): mu=%.6f sd=%.6f\n", b.state_mu[1], b.state_sd[1]);
    if (std <= MIN_BASELINE_SD || b.state_sd[0] <= MIN_BASELINE_SD || b.state_sd[1] <= MIN_BASELINE_SD)
        fprintf(stderr, "merse: WARNING -- this baseline has near-zero variance; any 'merse check' against it will report\n"
                        "       INDETERMINATE rather than CLEAN, by design. Capture a longer or more representative window.\n");
    free(x);
}

static void cmd_check(const char *values_path, const char *baseline_path) {
    long n; double *x = read_values(values_path, &n);
    seed_rng(0xC0FFEE);
    Baseline b = load_baseline(baseline_path);

    /* LATENCY check: sample mean vs baseline mean, SE from baseline std */
    double mean, std; mean_std(x, n, &mean, &std);
    int latency_valid = (b.std > MIN_BASELINE_SD);
    double se = b.std / sqrt((double)n);
    double z_latency = latency_valid ? (mean - b.mean) / se : 0.0;

    /* REGIME check: fresh HMM state means vs baseline state means,
     * scaled by baseline state std */
    HMM2 h = fit_hmm2_best(x, n);
    int state0_valid = (b.state_sd[0] > MIN_BASELINE_SD);
    int state1_valid = (b.state_sd[1] > MIN_BASELINE_SD);
    double z_state0 = state0_valid ? (h.mu[0] - b.state_mu[0]) / b.state_sd[0] : 0.0;
    double z_state1 = state1_valid ? (h.mu[1] - b.state_mu[1]) / b.state_sd[1] : 0.0;
    int regime_valid = state0_valid && state1_valid;
    double z_regime = fabs(z_state0) > fabs(z_state1) ? z_state0 : z_state1;

    printf("=== merse check: %s vs baseline %s ===\n", values_path, baseline_path);
    printf("\n[LATENCY check] mean-shift vs baseline\n");
    printf("  baseline mean=%.6f std=%.6f (n=%ld)\n", b.mean, b.std, b.n);
    printf("  sample   mean=%.6f (n=%ld)\n", mean, n);
    if (latency_valid)
        printf("  z=%.2f -> %s\n", z_latency, verdict_label(z_latency));
    else
        printf("  INDETERMINATE -- baseline std (%.2e) too small to trust a z-score; re-capture a longer/more representative baseline\n", b.std);

    printf("\n[REGIME check] state-mean shift vs baseline\n");
    printf("  baseline states: low=%.6f(+-%.6f)  high=%.6f(+-%.6f)\n", b.state_mu[0], b.state_sd[0], b.state_mu[1], b.state_sd[1]);
    printf("  sample   states: low=%.6f            high=%.6f\n", h.mu[0], h.mu[1]);
    if (regime_valid)
        printf("  z(low)=%.2f  z(high)=%.2f -> worst z=%.2f -> %s\n", z_state0, z_state1, z_regime, verdict_label(z_regime));
    else
        printf("  INDETERMINATE -- baseline state std too small to trust a z-score; re-capture a longer/more representative baseline\n");

    /* fail closed: an indeterminate check can never resolve to CLEAN --
     * it forces at least SUSPECT rather than silently passing */
    const char *final_verdict;
    const char *trigger = "";
    if (!latency_valid || !regime_valid) {
        int both_clean_if_valid = (!latency_valid || fabs(z_latency) < 2.0) && (!regime_valid || fabs(z_regime) < 2.0);
        final_verdict = both_clean_if_valid ? "SUSPECT (indeterminate)" : verdict_label(fabs(z_latency) > fabs(z_regime) ? z_latency : z_regime);
        trigger = !latency_valid && !regime_valid ? "BOTH checks indeterminate" : (!latency_valid ? "LATENCY indeterminate" : "REGIME indeterminate");
    } else {
        double worst = fabs(z_latency) > fabs(z_regime) ? z_latency : z_regime;
        final_verdict = verdict_label(worst);
        trigger = fabs(z_latency) > fabs(z_regime) ? "LATENCY" : "REGIME";
    }
    printf("\n=== OVERALL VERDICT: %s ===\n", final_verdict);
    printf("(%s)\n", trigger);
    free(x);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "merse: boundary detector -- the line between clean and compromised\n\n");
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "  merse baseline <values_file> <baseline_out_file>\n");
        fprintf(stderr, "  merse check    <values_file> <baseline_file>\n");
        return 1;
    }
    if (!strcmp(argv[1], "baseline")) {
        if (argc != 4) { fprintf(stderr, "usage: merse baseline <values_file> <baseline_out_file>\n"); return 1; }
        cmd_baseline(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "check")) {
        if (argc != 4) { fprintf(stderr, "usage: merse check <values_file> <baseline_file>\n"); return 1; }
        cmd_check(argv[2], argv[3]);
    } else {
        fprintf(stderr, "merse: unknown command '%s'\n", argv[1]);
        return 1;
    }
    return 0;
}
