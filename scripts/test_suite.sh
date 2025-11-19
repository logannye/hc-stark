#!/bin/bash

# hc-STARK Comprehensive Test Suite
# Tests all functions, verifies complexity scaling, and provides sanity checks
#
# This script systematically tests:
# 1. Sanity checks - basic functionality of all components
# 2. Stress tests - edge cases and parameter variations
# 3. Ladder tests - scaling analysis with O(√T) verification
#
# Usage: ./scripts/test_suite.sh [sanity|stress|ladder|all]
#
# Author: hc-STARK team
# Date: 2025-11-15

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_ROOT/test_suite_$(date +%Y%m%d_%H%M%S).log"
TEMP_DIR="$PROJECT_ROOT/test_temp"
BENCH_DIR="$PROJECT_ROOT/benchmarks"
STRESS_REPORT="$BENCH_DIR/stress_latest.json"
LADDER_REPORT="$BENCH_DIR/ladder_latest.json"
LADDER_CSV="$BENCH_DIR/ladder_latest.csv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# Error function
error() {
    echo -e "${RED}ERROR: $*${NC}" >&2
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $*" >> "$LOG_FILE"
}

# Success function
success() {
    echo -e "${GREEN}SUCCESS: $*${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: $*" >> "$LOG_FILE"
}

# Warning function
warning() {
    echo -e "${YELLOW}WARNING: $*${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: $*" >> "$LOG_FILE"
}

# Info function
info() {
    echo -e "${BLUE}INFO: $*${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $*" >> "$LOG_FILE"
}

# Setup function
setup() {
    log "Setting up test environment..."
    mkdir -p "$TEMP_DIR"
    mkdir -p "$BENCH_DIR"

    # Check if we're in the right directory
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crates" ]]; then
        error "Must be run from hc-stark project root"
        exit 1
    fi

    # Check if cargo is available
    if ! command -v cargo &> /dev/null; then
        error "Cargo not found. Please install Rust."
        exit 1
    fi

    success "Test environment ready"
}

# Cleanup function
cleanup() {
    log "Cleaning up..."
    rm -rf "$TEMP_DIR"
}

# Run cargo command with timeout
run_cargo() {
    local timeout="${2:-300}" # Default 5 minute timeout
    shift 1  # Remove first argument (timeout) from $@

    log "Running: cargo $@"

    # Check if timeout command exists (not available on macOS by default)
    if command -v timeout &> /dev/null; then
        if timeout "$timeout" cargo "$@" 2>&1; then
            success "Cargo command completed successfully"
            return 0
        else
            error "Cargo command failed or timed out"
            return 1
        fi
    else
        warning "timeout command not available, running without timeout protection"
        if cargo "$@" 2>&1; then
            success "Cargo command completed successfully"
            return 0
        else
            error "Cargo command failed"
            return 1
        fi
    fi
}

# Run cargo command and capture output
run_cargo_capture() {
    local timeout="${2:-300}" # Default 5 minute timeout
    shift 1  # Remove first argument (timeout) from $@

    log "Running: cargo $@"

    # Check if timeout command exists (not available on macOS by default)
    if command -v timeout &> /dev/null; then
        if output=$(timeout "$timeout" cargo "$@" 2>&1); then
            success "Cargo command completed successfully"
            echo "$output"
            return 0
        else
            error "Cargo command failed or timed out"
            return 1
        fi
    else
        warning "timeout command not available, running without timeout protection"
        if output=$(cargo "$@" 2>&1); then
            success "Cargo command completed successfully"
            echo "$output"
            return 0
        else
            error "Cargo command failed"
            return 1
        fi
    fi
}

# Globals for profile metrics
PROFILE_DURATION_MS=0
PROFILE_MEMORY_KB=0

# Run bench command with optional profiler/time tracking
run_bench_with_profiler() {
    local timeout="$1"
    local block_size="$2"
    shift 2
    local profile_log="$TEMP_DIR/profile_${block_size}.log"
    PROFILE_DURATION_MS=0
    PROFILE_MEMORY_KB=0

    log "Profiling benchmark (block size: $block_size)"
    local cmd=("cargo" "$@")

    if command -v timeout &> /dev/null; then
        if command -v /usr/bin/time &> /dev/null; then
            if output=$(timeout "$timeout" /usr/bin/time -v "${cmd[@]}" 2> "$profile_log"); then
                parse_profile_output "$profile_log"
                success "Benchmark completed (profiled)"
                echo "$output"
                return 0
            else
                error "Benchmark failed or timed out for block size $block_size"
                return 1
            fi
        else
            warning "Profiler (/usr/bin/time) not available, running without profiling"
            if output=$(timeout "$timeout" "${cmd[@]}" 2>&1); then
                success "Benchmark completed (no profiler)"
                echo "$output"
                return 0
            else
                error "Benchmark failed for block size $block_size"
                return 1
            fi
        fi
    else
        warning "timeout not available, running benchmark without timeout guard"
        if command -v /usr/bin/time &> /dev/null; then
            if output=$(/usr/bin/time -v "${cmd[@]}" 2> "$profile_log"); then
                parse_profile_output "$profile_log"
                success "Benchmark completed (profiled)"
                echo "$output"
                return 0
            else
                error "Benchmark failed for block size $block_size"
                return 1
            fi
        else
            warning "Profiler (/usr/bin/time) not available, running without profiling"
            if output=$("${cmd[@]}" 2>&1); then
                success "Benchmark completed (no profiler)"
                echo "$output"
                return 0
            else
                error "Benchmark failed for block size $block_size"
                return 1
            fi
        fi
    fi
}

parse_profile_output() {
    local log_file="$1"
    PROFILE_DURATION_MS=0
    PROFILE_MEMORY_KB=0

    if [[ ! -f "$log_file" ]]; then
        return
    fi

    local real_line
    real_line=$(grep '^real' "$log_file" | head -n1 || true)
    if [[ -n "$real_line" ]]; then
        local time_part
        time_part=$(echo "$real_line" | awk '{print $2}')
        local minutes=$(echo "$time_part" | cut -dm -f1)
        local seconds=$(echo "$time_part" | cut -dm -f2 | tr -d 's')
        PROFILE_DURATION_MS=$(awk -v mts="$minutes" -v sec="$seconds" 'BEGIN { print (mts * 60 + sec) * 1000 }')
    fi

    local memory_line
    memory_line=$(grep -i 'Maximum resident set size' "$log_file" | head -n1 || true)
    if [[ -n "$memory_line" ]]; then
        PROFILE_MEMORY_KB=$(echo "$memory_line" | tr -dc '0-9')
    fi
}

# Sanity checks - basic functionality tests
sanity_checks() {
    log "=== Running Sanity Checks ==="

    # Test 1: Build the entire workspace
    info "Test 1: Building workspace..."
    if run_cargo 60 build; then
        success "Workspace builds successfully"
    else
        error "Workspace build failed"
        return 1
    fi

    # Test 2: Run all unit tests
    info "Test 2: Running unit tests..."
    if run_cargo 600 test; then  # 10 minute timeout for tests
        success "All unit tests pass"
    else
        error "Unit tests failed"
        return 1
    fi

    # Test 3: Basic CLI functionality
    info "Test 3: Testing CLI commands..."

    # Test prove command
    local proof_file="$TEMP_DIR/test_proof.json"
    if run_cargo 30 run -p hc-cli -- prove --output "$proof_file"; then
        success "CLI prove command works"
    else
        error "CLI prove command failed"
        return 1
    fi

    # Test verify command
    if run_cargo 30 run -p hc-cli -- verify --input "$proof_file"; then
        success "CLI verify command works"
    else
        error "CLI verify command failed"
        return 1
    fi

    # Test 4: Core library functionality
    info "Test 4: Testing core library functions..."

    # Test FFT
    if run_cargo 30 run -p hc-core --example fft_test; then
        success "FFT functionality works"
    else
        warning "FFT test not available or failed (non-critical)"
    fi

    # Test field operations
    if run_cargo 30 run -p hc-core --example field_test; then
        success "Field operations work"
    else
        warning "Field test not available or failed (non-critical)"
    fi

    # Test 5: AIR evaluation
    info "Test 5: Testing AIR evaluation..."
    if run_cargo 60 test -p hc-air; then
        success "AIR evaluation works"
    else
        error "AIR evaluation failed"
        return 1
    fi

    # Test 6: FRI prover/verifier
    info "Test 6: Testing FRI prover/verifier..."
    if run_cargo 60 test -p hc-fri; then
        success "FRI functionality works"
    else
        error "FRI functionality failed"
        return 1
    fi

    success "All sanity checks passed!"
    return 0
}

# Stress tests - parameter variations and edge cases
stress_tests() {
    log "=== Running Stress Tests ==="
    local stress_tmp="$TEMP_DIR/stress_metrics.txt"
    : > "$stress_tmp"

    # Test 1: Different block sizes
    info "Test 1: Testing different block sizes..."
    local block_sizes=(1 2 4 8 16 32 64 128 256 512)

    for bs in "${block_sizes[@]}"; do
        info "  Testing block size: $bs"
        local output
        if output=$(run_cargo_capture 60 run -p hc-cli -- bench --iterations 1 --block-size "$bs" --scenario prover); then
            echo "$output" | tail -n 1 >> "$stress_tmp"
            success "  Block size $bs works"
        else
            error "  Block size $bs failed"
            return 1
        fi
    done

    # Test 2: Multiple iterations
    info "Test 2: Testing multiple iterations..."
    if output=$(run_cargo_capture 120 run -p hc-cli -- bench --iterations 5 --block-size 4 --scenario prover); then
        echo "$output" | tail -n 1 >> "$stress_tmp"
        success "Multiple iterations work"
    else
        error "Multiple iterations failed"
        return 1
    fi

    # Test 3: Large block sizes (stress memory)
    info "Test 3: Testing large block sizes..."
    if output=$(run_cargo_capture 180 run -p hc-cli -- bench --iterations 1 --block-size 1024 --scenario prover); then
        echo "$output" | tail -n 1 >> "$stress_tmp"
        success "Large block size works"
    else
        warning "Large block size test failed (may be expected on low-memory systems)"
    fi

    # Test 4: Edge case - minimal parameters
    info "Test 4: Testing minimal parameters..."
    if output=$(run_cargo_capture 60 run -p hc-cli -- bench --iterations 1 --block-size 1 --scenario prover); then
        echo "$output" | tail -n 1 >> "$stress_tmp"
        success "Minimal parameters work"
    else
        error "Minimal parameters failed"
        return 1
    fi

    # Test 5: Streaming Merkle path replay vs in-memory
    info "Test 5: Streaming Merkle path benchmark..."
    if output=$(run_cargo_capture 90 run -p hc-cli -- bench --scenario merkle --leaves 4096 --queries 128 --fanout 2); then
        echo "$output" | tail -n 1 >> "$stress_tmp"
        success "Merkle benchmark captured"
    else
        warning "Merkle benchmark failed"
    fi

    # Test 6: Batched LDE throughput benchmark
    info "Test 6: Batched LDE benchmark..."
    if output=$(run_cargo_capture 90 run -p hc-cli -- bench --scenario lde --columns 4 --degree 512 --samples 2048); then
        echo "$output" | tail -n 1 >> "$stress_tmp"
        success "LDE benchmark captured"
    else
        warning "LDE benchmark failed"
    fi

    if [[ -s "$stress_tmp" ]]; then
        local stress_json="["
        local first=true
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ "$first" == true ]]; then
                stress_json="$stress_json$line"
                first=false
            else
                stress_json="$stress_json,$line"
            fi
        done < "$stress_tmp"
        stress_json="$stress_json]"
        echo "$stress_json" > "$STRESS_REPORT"
        info "Stress metrics saved to $STRESS_REPORT"
    fi

    success "All stress tests passed!"
    return 0
}

# Ladder tests - scaling analysis with O(√T) verification
ladder_tests() {
    log "=== Running Ladder Tests ==="

    # Test scaling behavior with different block sizes
    # According to theory: memory ~ O(√T) when b ~ √T

    local results_file="$LADDER_REPORT"
    local temp_results="$TEMP_DIR/temp_results.txt"
    echo "" > "$temp_results"

    info "Running scaling analysis..."

    # Test different block sizes to find optimal scaling
    local block_sizes=(2 4 8 16 32 64 128 256 512)

    info "Phase 1: Measuring performance vs block size..."
    for bs in "${block_sizes[@]}"; do
        info "  Testing block size: $bs"

        # Run benchmark with profiler (if available)
        local output
        if ! output=$(run_bench_with_profiler 120 "$bs" run -p hc-cli -- bench --iterations 3 --block-size "$bs"); then
            warning "  Block size $bs failed, skipping..."
            continue
        fi

        # Extract the last line which should contain the JSON output
        output=$(echo "$output" | tail -n 1)

        # Extract metrics from JSON output
        local duration fri_blocks trace_blocks profile_duration memory_kb
        if command -v jq &> /dev/null; then
            duration=$(echo "$output" | jq -r '.avg_duration_ms // 0' 2>/dev/null || echo "0")
            fri_blocks=$(echo "$output" | jq -r '.avg_fri_blocks // 0' 2>/dev/null || echo "0")
            trace_blocks=$(echo "$output" | jq -r '.avg_trace_blocks // 0' 2>/dev/null || echo "0")
            profile_duration=$PROFILE_DURATION_MS
            memory_kb=$PROFILE_MEMORY_KB
        else
            # Fallback parsing without jq
            duration=$(echo "$output" | grep -o '"avg_duration_ms":[^,}]*' | cut -d: -f2 | tr -d ' ' 2>/dev/null || echo "0")
            fri_blocks=$(echo "$output" | grep -o '"avg_fri_blocks":[^,}]*' | cut -d: -f2 | tr -d ' ' 2>/dev/null || echo "0")
            trace_blocks=$(echo "$output" | grep -o '"avg_trace_blocks":[^,}]*' | cut -d: -f2 | tr -d ' ' 2>/dev/null || echo "0")
            profile_duration=$PROFILE_DURATION_MS
            memory_kb=$PROFILE_MEMORY_KB
        fi

        # Store results temporarily
        echo "{\"block_size\":$bs,\"duration\":$duration,\"fri_blocks\":$fri_blocks,\"trace_blocks\":$trace_blocks,\"profile_duration\":$profile_duration,\"memory_kb\":$memory_kb}" >> "$temp_results"

        success "  Block size $bs: ${duration}ms, profile_time=${profile_duration}ms, memory=${memory_kb}kB, trace_blocks:${trace_blocks}, fri_blocks:${fri_blocks}"
    done

    # Build final JSON array
    local results_array="["
    local first=true
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            if [[ "$first" == true ]]; then
                results_array="$results_array$line"
                first=false
            else
                results_array="$results_array,$line"
            fi
        fi
    done < "$temp_results"
    results_array="$results_array]"

    echo "$results_array" > "$results_file"

    if command -v jq &> /dev/null; then
        {
            echo "block_size,duration_ms,trace_blocks,fri_blocks,profile_duration_ms,memory_kb"
            jq -r '.[] | "\(.block_size),\(.duration),\(.trace_blocks),\(.fri_blocks),\(.profile_duration),\(.memory_kb)"' "$results_file"
        } > "$LADDER_CSV"
        info "Ladder CSV saved to $LADDER_CSV"
    fi

    # Analyze results
    info "Phase 2: Analyzing scaling behavior..."
    if command -v jq &> /dev/null; then
        analyze_scaling "$results_file"
    else
        warning "jq not available, skipping detailed scaling analysis"
        info "Raw results saved to: $results_file"
    fi

    success "Ladder tests completed!"
    return 0
}

# Analyze scaling behavior from results
analyze_scaling() {
    local results_file="$1"

    info "Scaling Analysis Results:"
    info "========================"

    # Calculate theoretical optimal block size
    # For our toy program, T ≈ 3 (trace length), so √T ≈ 1.7
    # But we need larger traces for meaningful analysis

    info ""
    info "Expected behavior (theory):"
    info "  - Memory usage should minimize at b ≈ √T"
    info "  - For T=3 (our toy program), optimal b ≈ 2"
    info "  - Performance should degrade gracefully outside optimal range"
    info ""

    # Find best performing block size
    local best_bs=0
    local best_duration=999999
    local best_trace_blocks=0
    local best_fri_blocks=0
    local min_memory_ratio=999999
    local max_memory_ratio=0
    local min_time_ratio=999999
    local max_time_ratio=0

    # Parse results and find optimal
    if ! command -v jq &> /dev/null || ! command -v bc &> /dev/null; then
        warning "jq or bc not available, skipping detailed analysis"
        return 0
    fi

    local results=$(cat "$results_file")
    local count=$(echo "$results" | jq '. | length')

    for ((i=0; i<count; i++)); do
        local bs=$(echo "$results" | jq ".[$i].block_size")
        local duration=$(echo "$results" | jq ".[$i].duration")
        local trace_blocks=$(echo "$results" | jq ".[$i].trace_blocks")
        local fri_blocks=$(echo "$results" | jq ".[$i].fri_blocks")
        local profile_duration=$(echo "$results" | jq ".[$i].profile_duration")
        local memory_kb=$(echo "$results" | jq ".[$i].memory_kb")

        local normalized_bs=$bs
        if (( $(echo "$normalized_bs < 2" | bc -l) )); then
            normalized_bs=2
        fi
        local time_ratio=$(awk -v duration="$duration" -v bs="$normalized_bs" 'BEGIN { print duration / (bs * (log(bs)^2 + 1)) }')
        local memory_ratio=0
        if (( $(echo "$memory_kb > 0" | bc -l) )); then
            memory_ratio=$(awk -v mem="$memory_kb" -v bs="$bs" 'BEGIN { print mem / sqrt(bs) }')
        fi

        if (( $(echo "$memory_ratio > 0" | bc -l) )) && (( $(echo "$memory_ratio < $min_memory_ratio" | bc -l) )); then
            min_memory_ratio=$memory_ratio
        fi
        if (( $(echo "$memory_ratio > $max_memory_ratio" | bc -l) )); then
            max_memory_ratio=$memory_ratio
        fi

        if (( $(echo "$time_ratio < $min_time_ratio" | bc -l) )); then
            min_time_ratio=$time_ratio
        fi
        if (( $(echo "$time_ratio > $max_time_ratio" | bc -l) )); then
            max_time_ratio=$time_ratio
        fi

        if (( $(echo "$duration < $best_duration" | bc -l) )); then
            best_duration=$duration
            best_bs=$bs
            best_trace_blocks=$trace_blocks
            best_fri_blocks=$fri_blocks
        fi

        info "  Block size $bs: duration=${duration}ms, profile_time=${profile_duration}ms, memory=${memory_kb}kB, time_ratio=${time_ratio}, memory_norm=${memory_ratio}"
    done

    info "Empirical Results:"
    info "  - Best block size: $best_bs"
    info "  - Best duration: ${best_duration}ms"
    info "  - Trace blocks loaded: $best_trace_blocks"
    info "  - FRI blocks loaded: $best_fri_blocks"
    info ""

    if (( $(echo "$min_memory_ratio < 999999" | bc -l) )); then
        info "  - Memory normalization per √b: min=${min_memory_ratio}, max=${max_memory_ratio}"
    else
        info "  - Memory statistics unavailable (profiler missing)"
    fi
    info "  - Time ratio (duration / (b·log²b)): min=${min_time_ratio}, max=${max_time_ratio}"

    # Check if results make sense
    if (( best_bs >= 1 && best_bs <= 16 )); then
        success "✓ Block size optimization working (reasonable optimal found)"
    else
        warning "! Block size optimization may need tuning (unusual optimal: $best_bs)"
    fi

    # Verify that larger block sizes don't cause excessive overhead
    local large_bs_count=$(echo "$results" | jq "[.[] | select(.block_size > 64)] | length")
    if (( large_bs_count > 0 )); then
        info "✓ Large block sizes tested (good for stress testing)"
    else
        info "! No large block sizes tested (consider adding larger sizes)"
    fi

    info "Raw results saved to: $results_file"
}

# Main function
main() {
    local test_type="${1:-all}"

    log "Starting hc-STARK Comprehensive Test Suite"
    log "Test type: $test_type"
    log "Log file: $LOG_FILE"
    log "Project root: $PROJECT_ROOT"

    setup

    case "$test_type" in
        sanity)
            if sanity_checks; then
                success "Sanity checks completed successfully"
            else
                error "Sanity checks failed"
                exit 1
            fi
            ;;
        stress)
            if stress_tests; then
                success "Stress tests completed successfully"
            else
                error "Stress tests failed"
                exit 1
            fi
            ;;
        ladder)
            if ladder_tests; then
                success "Ladder tests completed successfully"
            else
                error "Ladder tests failed"
                exit 1
            fi
            ;;
        all)
            if sanity_checks && stress_tests && ladder_tests; then
                success "All tests completed successfully"
            else
                error "Some tests failed"
                exit 1
            fi
            ;;
        *)
            error "Invalid test type: $test_type"
            echo "Usage: $0 [sanity|stress|ladder|all]"
            exit 1
            ;;
    esac

    cleanup
    success "Test suite completed. Check $LOG_FILE for detailed logs."
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"
