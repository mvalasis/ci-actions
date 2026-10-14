# Offline stand-in for PHPUnit over a suite of many test files that each fail alone, for the
# isolate-files step-summary legs: selftest.mjs copies it into a scratch working directory beside
# files.txt (one absolute test-file path a line) and runs it as `sh phpunit-many-stub.sh`. sh, not
# node like phpunit-stub.mjs: isolate-files starts one process per test file, and a thousand node
# startups take most of a minute.
#
#   (no path)             the full suite — green
#   --list-test-files     "Available test files:" and one " - <path>" line per files.txt line, or
#                         for the one path given
#   <path>                that file alone: PHPUnit's defect block, its message $STUB_WHY; exit 2
echo 'PHPUnit 12.5.30 by Sebastian Bergmann and contributors.'
echo
list=
for a in "$@"; do [ "$a" = --list-test-files ] && list=1; done
if [ -n "$list" ]; then
  echo 'Available test files:'
  if [ "$1" = --list-test-files ]; then
    while IFS= read -r f; do printf ' - %s\n' "$f"; done < files.txt
  else
    printf ' - %s\n' "$1"
  fi
  exit 0
fi
if [ $# -eq 0 ]; then echo 'OK (2 tests, 2 assertions)'; exit 0; fi
printf 'There was 1 error:\n\n1) ManyTest::test_it\n%s\n\nERRORS!\nTests: 1, Assertions: 0, Errors: 1.\n' "$STUB_WHY"
exit 2
