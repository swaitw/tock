#!/usr/bin/env bash

# Licensed under the Apache License, Version 2.0 or the MIT License.
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright Tock Contributors 2023.

# Runs `cargo generate-lockfile` (which generates and/or updates the Cargo.lock
# file for a crate) on every subdirectory from . that has a Cargo.toml file.
#
# Author: Brad Campbell <bradjc5@gmail.com>

set -e

# Verify that we're running in the base directory
if [ ! -x tools/run_cargo_generate-lockfile.sh ]; then
	echo ERROR: $0 must be run from the tock repository root.
	echo ""
	exit 1
fi

for f in $(find . | grep Cargo.toml); do
	pushd $(dirname $f) > /dev/null
	cargo generate-lockfile
	popd > /dev/null
done

echo "Generated or updated all Cargo.lock files."
echo "Because of the .gitignore file this will not show any changed files."
