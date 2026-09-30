// Offline stand-in for `php phpunit.phar` over a two-file suite, so the isolate-files legs need no
// PHP: it prints PHPUnit's own shapes and exits the way PHPUnit does. The fixture is the defect the
// feature exists for: BorrowedHarnessTest.php passes whenever a sibling file is loaded with it,
// because that file's harness defines the function it needs, and dies alone.
//
// Like PHPUnit, every positional argument selects tests (a directory: its *Test.php files; a
// file: itself) and options may come after them. The files a run selects are loaded together.
//
//   (no path)             the full suite — green (STUB_SUITE=fail: red)
//   --list-test-files     "Available test files:" and one " - <absolute path>" line per selected
//                         file (STUB_LIST=fail: an unknown option, as a PHPUnit without it answers;
//                         STUB_LIST=empty: the header and no file; STUB_LIST=exit1: the list, then
//                         exit 1)
//   <paths>               the selected files, loaded together: BorrowedHarnessTest.php alone exits
//                         2 with PHPUnit's defect block (its message is STUB_WHY when set);
//                         STUB_ALONE=exit1 fails it with an assertion instead (PHPUnit's exit 1),
//                         STUB_ALONE=signal kills the process; STUB_FIXED=1 is the fix
//
// fs.writeSync, not process.stdout: every path here ends in process.exit().
import fs from 'node:fs';
import path from 'node:path';

const out = (s) => fs.writeSync(1, `${s}\n`);
const testsIn = (dir) => fs.readdirSync(dir).filter((f) => f.endsWith('Test.php')).sort().map((f) => path.join(dir, f));
const all = testsIn(path.join(process.cwd(), 'tests'));
const args = process.argv.slice(2);
const list = args.includes('--list-test-files');
const paths = args.filter((a) => !a.startsWith('--'));
const selected = [];
for (const p of paths) {
  const abs = path.resolve(p);
  for (const f of fs.statSync(abs).isDirectory() ? testsIn(abs) : [abs]) if (!selected.includes(f)) selected.push(f);
}
const files = paths.length ? selected : all;
out('PHPUnit 12.5.30 by Sebastian Bergmann and contributors.\n');

if (list) {
  const mode = process.env.STUB_LIST || '';
  if (mode === 'fail') { out('Unknown option "--list-test-files"'); process.exit(2); }
  out('Available test files:');
  if (mode !== 'empty') for (const f of files) out(` - ${f}`);
  process.exit(mode === 'exit1' ? 1 : 0);
}
if (!paths.length && process.env.STUB_SUITE === 'fail') { out('FAILURES!\nTests: 2, Assertions: 2, Failures: 1.'); process.exit(1); }
const borrowedAlone = files.length === 1 && !process.env.STUB_FIXED && fs.readFileSync(files[0], 'utf8').includes('fails-alone');
if (borrowedAlone) {
  const name = path.basename(files[0], '.php');
  if (process.env.STUB_ALONE === 'signal') process.kill(process.pid, 'SIGKILL');
  if (process.env.STUB_ALONE === 'exit1') {
    out(`There was 1 failure:\n\n1) ${name}::test_it\nFailed asserting that false is true.\n\n${files[0]}:9\n\nFAILURES!\nTests: 1, Assertions: 1, Failures: 1.`);
    process.exit(1);
  }
  out(`There was 1 error:\n\n1) ${name}::test_it\n${process.env.STUB_WHY || 'Error: Call to undefined function wp_json_encode()'}\n\n${files[0]}:9\n\nERRORS!\nTests: 1, Assertions: 0, Errors: 1.`);
  process.exit(2);
}
out(`OK (${files.length} test${files.length === 1 ? '' : 's'}, ${files.length} assertion${files.length === 1 ? '' : 's'})`);
process.exit(0);
