// Offline stand-in for `vitest run` over an all-passing suite. Emits the exact vitest summary
// shape and exits 0 — the selftest asserts the action reports PASS end-to-end without network.
process.stdout.write([
  '',
  ' RUN  v1.0.0',
  '',
  ' ✓ test/math.test.js (3 tests) 4ms',
  '',
  ' Test Files  1 passed (1)',
  '      Tests  3 passed (3)',
  '   Start at  00:00:00',
  '   Duration  8ms',
  '',
].join('\n') + '\n');
process.exit(0);
