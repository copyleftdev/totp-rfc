#!/bin/sh
set -eu

runs=${TIMING_EVIDENCE_RUNS:-3}
case "$runs" in
    *[!0-9]* | "")
        echo "TIMING_EVIDENCE_RUNS must be an integer from 3 through 10" >&2
        exit 2
        ;;
esac
if [ "$runs" -lt 3 ] || [ "$runs" -gt 10 ]; then
    echo "TIMING_EVIDENCE_RUNS must be from 3 through 10" >&2
    exit 2
fi

evidence_dir=target/timing-evidence
summary=$evidence_dir/summary.tsv
environment=$evidence_dir/environment.txt
mkdir -p "$evidence_dir"

{
    date -u '+generated_utc=%Y-%m-%dT%H:%M:%SZ'
    printf 'runs=%s\n' "$runs"
    uname -a
    rustc -Vv
    if command -v valgrind >/dev/null 2>&1; then
        valgrind --version
    fi
    if [ -r /proc/cpuinfo ]; then
        awk -F ': ' '/^model name/ { print "cpu=" $2; exit }' /proc/cpuinfo
    fi
} > "$environment"

printf 'pass\tbenchmark\tmax_t\tmax_tau\n' > "$summary"

pass=1
while [ "$pass" -le "$runs" ]; do
    raw=$evidence_dir/pass-$pass.txt
    if ! scripts/timing-test.sh > "$raw" 2>&1; then
        sed -n '1,240p' "$raw"
        echo "timing evidence pass $pass did not complete" >&2
        exit 1
    fi
    sed -n '1,240p' "$raw"
    awk -v pass="$pass" '
        /^bench .*max t =/ {
            line = $0
            sub(/^bench /, "", line)
            name = line
            sub(/ .*/, "", name)

            max_t = line
            sub(/.*max t = /, "", max_t)
            sub(/,.*/, "", max_t)

            max_tau = line
            sub(/.*max tau = /, "", max_tau)
            sub(/,.*/, "", max_tau)

            printf "%s\t%s\t%s\t%s\n", pass, name, max_t, max_tau
        }
    ' "$raw" >> "$summary"
    pass=$((pass + 1))
done

if ! awk -F '	' '
    function absolute(value) {
        return value < 0 ? -value : value
    }
    NR == 1 {
        next
    }
    $2 == "calibration_invalid_length_vs_valid_code" {
        calibrations += 1
        if (absolute($3) <= 5) {
            printf "calibration was not detected in pass %s: |t|=%s\n", $1, $3
            failed = 1
        }
        next
    }
    $2 ~ /^(hotp_code_fixed_vs_random|code_wrong_first_vs_last_digit|totp_sha[0-9]+_secret_fixed_vs_random|totp_window_current_vs_edge)$/ {
        sensitive += 1
        if (absolute($3) > 5) {
            signals[$2] += 1
            printf "sensitive timing excursion in pass %s for %s: |t|=%s\n", $1, $2, $3
        }
    }
    END {
        if (calibrations == 0 || sensitive == 0) {
            print "timing evidence summary did not contain all required probe classes"
            failed = 1
        }
        for (benchmark in signals) {
            if (signals[benchmark] >= 2) {
                printf "reproduced sensitive timing signal for %s in %s passes\n", benchmark, signals[benchmark]
                failed = 1
            } else {
                printf "advisory: %s crossed the threshold once but did not reproduce\n", benchmark
            }
        }
        exit failed
    }
' "$summary"; then
    echo "timing evidence did not satisfy the release threshold" >&2
    exit 1
fi

echo "timing evidence passed $runs calibrated runs"
echo "machine-readable summary: $summary"
