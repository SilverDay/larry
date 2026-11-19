#!/usr/bin/env bash
# Usage: scripts/package.sh <rust target> <version>   (run after `cargo build --release --target <t>`)
set -euo pipefail
target="${1:?target}"; version="${2:?version}"
name="larry-${version}-${target}"
rm -rf "dist/${name}"; mkdir -p "dist/${name}"
cp "target/${target}/release/larry" LICENSE README.md "dist/${name}/"
cp -r LICENSES "dist/${name}/"
tar -C dist -czf "dist/${name}.tar.gz" "${name}"
rm -rf "dist/${name}"
echo "dist/${name}.tar.gz"
