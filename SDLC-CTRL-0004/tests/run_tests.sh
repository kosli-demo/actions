#!/usr/bin/env bash
set -Eeu

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly tmp_dir=$(mktemp -d "/tmp/reusable-actions-workflows.XXX")
remove_tmp_dir() { rm -rf "${tmp_dir}" > /dev/null; }
trap remove_tmp_dir INT EXIT

echo
for test_file in ${my_dir}/test_*; do
  ${test_file}
done
