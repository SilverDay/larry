#!/usr/bin/env bash
# Run the scenario in every distro of the matrix. Needs podman or docker and a musl toolchain target.
# Usage: tests/containers/run.sh [base-image db]...   (default: the whole matrix)
set -euo pipefail
cd "$(dirname "$0")"
rt=$(command -v podman || command -v docker) || { echo "neither podman nor docker is installed" >&2; exit 1; }
(cd ../.. && cargo build --release --locked --target x86_64-unknown-linux-musl)
cp ../../target/x86_64-unknown-linux-musl/release/larry ./larry
trap 'rm -f ./larry' EXIT
matrix=("debian:12 mariadb" "ubuntu:22.04 mariadb" "ubuntu:24.04 mariadb" "ubuntu:24.04 mysql")
[ $# -ge 2 ] && matrix=("$1 $2")
failed=0
for row in "${matrix[@]}"; do
  set -- $row
  tag="larry-test-$(echo "$1-$2" | tr ':/' '--')"
  echo "=== $1 with $2"
  "$rt" build -q -t "$tag" --build-arg BASE="$1" --build-arg DB="$2" . >/dev/null
  if "$rt" run --rm "$tag"; then echo "PASS $1 $2"; else echo "FAIL $1 $2"; failed=1; fi
done
exit $failed
