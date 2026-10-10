#!/bin/bash

# Get all the variables.
PROCESSES=$1
TRANCHES=$2
SHUFFLE_SEED=$3

# Here we also shift 3 times and get the rest of our flags to pass on in $@.
shift 3

# Create a variable to hold the final exit code.
exit_code=0

# Run all tranches (0..TRANCHES-1) with at most PROCESSES concurrent jobs.
active=0
for ((tranche=0; tranche<TRANCHES; tranche++)); do
	while [ "$active" -ge "$PROCESSES" ]; do
		wait -n
		ec=$?
		active=$((active - 1))
		if [ "$ec" -ne 0 ] && [ "$exit_code" -eq 0 ]; then
			exit_code=$ec
		fi
	done

	scripts/itest_part.sh "$tranche" "$TRANCHES" "$SHUFFLE_SEED" "$@" &
	active=$((active + 1))
done

while [ "$active" -gt 0 ]; do
	wait -n
	ec=$?
	active=$((active - 1))
	if [ "$ec" -ne 0 ] && [ "$exit_code" -eq 0 ]; then
		exit_code=$ec
	fi
done

# Exit with the exit code of the first failing itest or 0.
exit $exit_code
