#!/usr/bin/env bash
# Run the research and server tests with one summary line each; full output goes to log files.
# Results to cite in the thesis are recorded in thesis_log/test-results.md — re-run only when the
# code a group covers changes.
#
#   bash run_tests.sh              # all groups
#   bash run_tests.sh chain        # one or more groups: poc, chain, server
#   bash run_tests.sh --build ...  # rebuild rustcode first (after changes in rustcode/ or poc_adaptor_sig/)
#
# Groups:
#   poc     Part A Steps 1-4, B1, B2 (server/poc_adaptor_sig, no chain)
#   chain   B3 on Bitcoin regtest, Part C test_fde_regtest (starts bitcoind -regtest if needed)
#   server  test_gs_full, test_redelegate_full, test_denomination_trust (no chain)

cd "$(dirname "$0")" || exit 1
source "$HOME/.cargo/env"
source .venv/bin/activate

BTC_DATADIR="${BTC_DATADIR:-$HOME/btc-regtest}"
LOG_DIR="test_logs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOG_DIR"

build=0
groups=()
for a in "$@"; do
    case "$a" in
        --build) build=1 ;;
        poc|chain|server) groups+=("$a") ;;
        *) echo "unknown argument: $a (groups: poc chain server; flag: --build)"; exit 2 ;;
    esac
done
[ ${#groups[@]} -eq 0 ] && groups=(poc chain server)

pass=0
fail=0

# run <name> <command...>: one line per test; on failure, the last lines of its log.
run() {
    local name=$1; shift
    local log="$LOG_DIR/$name.log"
    local start=$SECONDS
    "$@" >"$log" 2>&1
    local rc=$? cases
    cases=$(grep -c '^\[ok\]' "$log")
    if [ $rc -eq 0 ]; then
        pass=$((pass + 1))
        printf '%-26s PASS  %3s checks  %3ss\n' "$name" "$cases" $((SECONDS - start))
    else
        fail=$((fail + 1))
        printf '%-26s FAIL  (exit %s, %s checks passed before)\n' "$name" "$rc" "$cases"
        tail -n 8 "$log" | sed 's/^/    | /'
    fi
}

py() {
    python3 -c "from server import $1; $1()"
}

ensure_bitcoind() {
    if bitcoin-cli -regtest -datadir="$BTC_DATADIR" getblockcount >/dev/null 2>&1; then
        return 0
    fi
    mkdir -p "$BTC_DATADIR"
    bitcoind -regtest -datadir="$BTC_DATADIR" -daemon -fallbackfee=0.0001 >/dev/null || return 1
    for _ in $(seq 30); do
        bitcoin-cli -regtest -datadir="$BTC_DATADIR" getblockcount >/dev/null 2>&1 && { echo "(started bitcoind -regtest)"; return 0; }
        sleep 1
    done
    return 1
}

if [ $build -eq 1 ]; then
    bash build.sh >"$LOG_DIR/build.log" 2>&1 || { echo "build.sh FAILED, see $LOG_DIR/build.log"; exit 1; }
    echo "(rustcode rebuilt)"
fi

for g in "${groups[@]}"; do
    case "$g" in
        poc)
            (cd poc_adaptor_sig && cargo build -q --release) >"$LOG_DIR/poc_build.log" 2>&1 \
                || { echo "poc_adaptor_sig build FAILED, see $LOG_DIR/poc_build.log"; fail=$((fail + 1)); continue; }
            for b in step1_baseline_elgamal step2_check1_encrypted step3_check2_encrypted step4_cross_group_link b1_ecdsa_adaptor b2_bonding_ledger; do
                run "$b" poc_adaptor_sig/target/release/$b
            done
            ;;
        chain)
            if ! ensure_bitcoind; then
                echo "bitcoind -regtest not reachable (datadir $BTC_DATADIR): chain group skipped"
                fail=$((fail + 1)); continue
            fi
            (cd poc_adaptor_sig && cargo build -q --release --bin b3_bitcoin_regtest) >"$LOG_DIR/b3_build.log" 2>&1 \
                || { echo "b3 build FAILED, see $LOG_DIR/b3_build.log"; fail=$((fail + 1)); continue; }
            run b3_bitcoin_regtest poc_adaptor_sig/target/release/b3_bitcoin_regtest
            run test_fde_regtest py test_fde_regtest
            ;;
        server)
            run test_gs_full py test_gs_full
            run test_redelegate_full py test_redelegate_full
            run test_denomination_trust py test_denomination_trust
            ;;
    esac
done

echo "-- $pass passed, $fail failed. Logs: server/$LOG_DIR"
[ $fail -eq 0 ]
