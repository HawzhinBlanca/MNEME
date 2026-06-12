#!/usr/bin/env bash
# Shared assertions for cheap CI smoke scripts. Source from the repository root.

VALIDATION_LANE_TOKEN_PATTERN='[a-z0-9][a-z0-9-]*'

require_exact_line() {
  local label="$1"
  local output="$2"
  local expected="$3"

  if ! grep -Fqx -- "$expected" <<<"$output"; then
    echo "$label: missing expected line:" >&2
    echo "  $expected" >&2
    echo "$label: actual output:" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_exact_output() {
  local label="$1"
  local actual="$2"
  local expected="$3"

  if [[ "$actual" != "$expected" ]]; then
    echo "$label: output mismatch" >&2
    echo "$label: expected output:" >&2
    printf '%s\n' "$expected" >&2
    echo "$label: actual output:" >&2
    printf '%s\n' "$actual" >&2
    exit 1
  fi
}

require_absent_substring() {
  local label="$1"
  local output="$2"
  local forbidden="$3"

  if grep -Fq -- "$forbidden" <<<"$output"; then
    echo "$label: forbidden output found: $forbidden" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_line_count() {
  local label="$1"
  local output="$2"
  local expected_count="$3"
  local actual_count

  actual_count="$(wc -l <<<"$output" | tr -d ' ')"
  if [[ "$actual_count" != "$expected_count" ]]; then
    echo "$label: expected exactly $expected_count output lines, got $actual_count" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_exit_status() {
  local label="$1"
  local actual_status="$2"
  local expected_status="$3"
  local output="$4"

  if [[ "$actual_status" != "$expected_status" ]]; then
    echo "$label: expected exit status $expected_status, got $actual_status" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_validation_lane_choices() {
  local label="$1"
  local lane_choices="$2"
  local lane
  local seen_lane
  local validation_lane_choice_pattern
  local validation_lanes=()
  local seen_validation_lanes=()
  local IFS

  validation_lane_choice_pattern="^${VALIDATION_LANE_TOKEN_PATTERN}(\\|${VALIDATION_LANE_TOKEN_PATTERN})*$"
  if [[ ! "$lane_choices" =~ $validation_lane_choice_pattern ]]; then
    echo "$label: invalid validation lane choices: $lane_choices" >&2
    exit 1
  fi

  IFS='|' read -r -a validation_lanes <<< "$lane_choices"
  for lane in "${validation_lanes[@]}"; do
    if [[ "${#seen_validation_lanes[@]}" -gt 0 ]]; then
      for seen_lane in "${seen_validation_lanes[@]}"; do
        if [[ "$lane" == "$seen_lane" ]]; then
          echo "$label: duplicate validation lane choice: $lane" >&2
          exit 1
        fi
      done
    fi
    seen_validation_lanes+=("$lane")
  done
}

validation_lane_choices_from_source() {
  local label="$1"
  local validation_lane_source="${2:-scripts/ci/validation-lane.sh}"
  local validation_lanes_line
  local validation_lanes_pattern
  local validation_lanes_tokens
  local validation_lanes_token_pattern
  local validation_lane
  local seen_validation_lane
  local validation_lanes=()
  local seen_validation_lanes=()
  local IFS

  validation_lanes_line="$(grep -E '^VALIDATION_LANES=\(' "$validation_lane_source" || true)"
  if [[ -z "$validation_lanes_line" ]]; then
    echo "$label: cannot parse VALIDATION_LANES" >&2
    exit 1
  fi
  if [[ "$(printf '%s\n' "$validation_lanes_line" | wc -l | tr -d ' ')" != "1" ]]; then
    echo "$label: expected exactly one VALIDATION_LANES declaration" >&2
    printf '%s\n' "$validation_lanes_line" >&2
    exit 1
  fi

  validation_lanes_pattern='^VALIDATION_LANES=\(([^)]*)\)$'
  if [[ ! "$validation_lanes_line" =~ $validation_lanes_pattern ]]; then
    echo "$label: cannot parse VALIDATION_LANES" >&2
    exit 1
  fi

  validation_lanes_tokens="${BASH_REMATCH[1]}"
  validation_lanes_token_pattern="^${VALIDATION_LANE_TOKEN_PATTERN}( ${VALIDATION_LANE_TOKEN_PATTERN})*$"
  if [[ ! "$validation_lanes_tokens" =~ $validation_lanes_token_pattern ]]; then
    echo "$label: invalid VALIDATION_LANES tokens" >&2
    printf '%s\n' "$validation_lanes_line" >&2
    exit 1
  fi

  IFS=' ' read -r -a validation_lanes <<< "$validation_lanes_tokens"
  for validation_lane in "${validation_lanes[@]}"; do
    if [[ "${#seen_validation_lanes[@]}" -gt 0 ]]; then
      for seen_validation_lane in "${seen_validation_lanes[@]}"; do
        if [[ "$validation_lane" == "$seen_validation_lane" ]]; then
          echo "$label: duplicate VALIDATION_LANES token: $validation_lane" >&2
          printf '%s\n' "$validation_lanes_line" >&2
          exit 1
        fi
      done
    fi
    seen_validation_lanes+=("$validation_lane")
  done

  printf '%s\n' "${validation_lanes_tokens// /|}"
}

validation_lane_choices_for_target() {
  local label="$1"
  local target_dir="$2"
  local validation_lane_script="${3:-scripts/ci/validation-lane.sh}"
  local output

  output="$(CARGO_TARGET_DIR="$target_dir" bash "$validation_lane_script" --list)"
  require_line_count "$label" "$output" "1"
  require_validation_lane_choices "$label" "$output"
  printf '%s\n' "$output"
}

validation_lane_sublanes_before() {
  local label="$1"
  local lane_choices="$2"
  local stop_lane="$3"
  local lane
  local saw_stop=0
  local validation_lanes=()
  local sublanes=()
  local IFS

  require_validation_lane_choices "$label" "$lane_choices"

  IFS='|' read -r -a validation_lanes <<< "$lane_choices"
  for lane in "${validation_lanes[@]}"; do
    if [[ "$lane" == "$stop_lane" ]]; then
      saw_stop=1
      break
    fi
    sublanes+=("$lane")
  done

  if [[ "${#sublanes[@]}" -eq 0 || "$saw_stop" != "1" ]]; then
    echo "$label: $lane_choices did not produce $stop_lane sentinel" >&2
    exit 1
  fi

  IFS=' '
  printf '%s\n' "${sublanes[*]}"
}
