// Offline stand-in for `vitest run` over a 1-pass / 1-fail suite. Emits the EXACT summary shape
// vitest prints (so parseCounts is exercised against the real format) and exits 1 — letting the
// selftest assert the action detects RED end-to-end without installing vitest or hitting the
// network. The two "tests" below are illustrative; the stub is deterministic.
//
//   test/math.test.js
//     ✓ adds            (would pass)
//     ✗ subtracts wrong (would fail)
process.stdout.write([
  '',
  ' RUN  v1.0.0',
  '',
  ' ❯ test/math.test.js (2 tests | 1 failed)',
  '   ✓ adds',
  '   ✗ subtracts wrong',
  '     → expected 1 to be 2',
  '',
  ' Test Files  1 failed (1)',
  '      Tests  1 failed | 1 passed (2)',
  '   Start at  00:00:00',
  '   Duration  10ms',
  '',
].join('\n') + '\n');
process.exit(1);
