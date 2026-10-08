// Offline self-test for agent-benchmark. No network: two node:http servers on 127.0.0.1 stand in for
// ora.ai and isitagentready.com, and the real benchmark.mjs runs against them (the bases and the poll
// timing are env-overridable for exactly this). Every case asserts what reaches the job log, the step
// summary, GITHUB_OUTPUT and the JSON, and that the exit is 0 whatever the scanners do.
// Run locally or in CI (`node agent-benchmark/scripts/selftest.mjs`); exits non-zero on any regression.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

let failed = 0;
function check(name, cond, detail = '') { if (cond) { console.log(`  ✅ ${name}`); } else { console.log(`  ❌ ${name} ${detail}`); failed++; } }

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENTRY = path.join(HERE, 'benchmark.mjs');
const TARGET = 'https://www.example.test/';
const T1 = '2026-10-08T13:17:08.258+00:00';
const T2 = '2026-10-08T15:00:00.000+00:00';

// ora's audit contract (format=audit), trimmed to what the report reads.
const AUDIT = (o = {}) => ({
  contractVersion: '1.27.0', domain: 'example.test', score: 52, scoreMax: 100, grade: 'C', scannedAt: T1,
  analysisStatus: 'complete', pendingChecks: [],
  layers: [
    { id: 'discovery', name: 'Discovery', score: 2, maxScore: 6, checks: [
      { id: 'ard-catalog', status: 'fail', tier: 'required', estScoreGain: 3.7, recommendation: 'Publish an ARD catalog at /.well-known/ard.json.' },
      { id: 'robots-ai-policy-quality', status: 'pass', tier: 'required' },
    ] },
    { id: 'accessibility', name: 'Access', score: 25, maxScore: 42, checks: [
      { id: 'markdown-negotiation', status: 'fail', tier: 'emerging', estScoreGain: 1.6, recommendation: 'Return text/markdown for Accept: text/markdown.' },
      { id: 'json-ld', status: 'warning', tier: 'required', estScoreGain: 1.2, recommendation: 'Add description to the Organization entity.' },
      { id: 'openapi-spec', status: 'na', tier: 'required' },
    ] },
    { id: 'payments', name: 'Payments', score: 0, maxScore: 0, checks: [
      { id: 'ucp-support', status: 'warning', tier: 'required', recommendation: 'Publish a UCP profile.' },
    ] },
  ],
  topFixes: [{ id: 'webmcp', estScoreGain: 9.7 }, { id: 'ard-catalog', estScoreGain: 3.7 }],
  ...o,
});
// isitagentready's scan result.
const LEVEL = (o = {}) => ({
  url: 'https://www.example.test', level: 1, levelName: 'Basic Web Presence',
  checks: {
    discoverability: { robotsTxt: { status: 'pass', message: 'ok' }, linkHeaders: { status: 'fail', message: 'none' } },
    botAccessControl: { contentSignals: { status: 'fail' }, webBotAuth: { status: 'neutral' } },
  },
  nextLevel: { target: 2, name: 'Bot-Aware', requirements: [{ check: 'contentSignals', description: 'Declare AI content usage preferences with Content Signals in robots.txt' }] },
  ...o,
});

// A stand-in scanner: POSTs and GETs answer from their own queue, in order, the last one repeating.
// An answer is { status, body (object or raw string), headers, delayMs }. Every request is recorded.
function standIn() {
  const st = { post: [], get: [], hits: [] };
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      st.hits.push({ method: req.method, url: req.url, headers: req.headers, body: raw });
      const q = req.method === 'POST' ? st.post : st.get;
      const a = (q.length > 1 ? q.shift() : q[0]) || { status: 418, body: { error: 'nothing queued' } };
      const send = () => {
        if (res.destroyed) return;
        res.writeHead(a.status, { 'content-type': 'application/json', ...(a.headers || {}) });
        res.end(typeof a.body === 'string' ? a.body : JSON.stringify(a.body));
      };
      if (a.delayMs) setTimeout(send, a.delayMs); else send();
    });
  });
  return { st, server };
}

const ora = standIn();
const iiar = standIn();
await Promise.all([ora.server, iiar.server].map((s) => new Promise((r) => s.listen(0, '127.0.0.1', r))));
const ORA_BASE = `http://127.0.0.1:${ora.server.address().port}`;
const IIAR_BASE = `http://127.0.0.1:${iiar.server.address().port}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-benchmark-'));
const summaryPath = path.join(tmp, 'summary.md');
const outputPath = path.join(tmp, 'output.txt');
const jsonPath = path.join(tmp, 'agent-benchmark.json');

function queue(oraPost, oraGet = [], iiarPost = [{ status: 200, body: LEVEL() }]) {
  ora.st.post = [...oraPost]; ora.st.get = [...oraGet]; ora.st.hits = [];
  iiar.st.post = [...iiarPost]; iiar.st.get = []; iiar.st.hits = [];
}
// MUST be async (spawn, not spawnSync): the stand-ins live in THIS process. The env is built from
// scratch so a CI runner's own GITHUB_ACTIONS / GITHUB_STEP_SUMMARY / GITHUB_OUTPUT never leak into a case.
const run = (extra = {}) => new Promise((resolve) => {
  for (const f of [summaryPath, outputPath, jsonPath]) { try { fs.rmSync(f, { force: true }); } catch { /* fresh per run */ } }
  const child = spawn(process.execPath, [ENTRY], {
    env: {
      PATH: process.env.PATH, HOME: tmp, TMPDIR: tmp, RUNNER_TEMP: tmp, GITHUB_OUTPUT: outputPath, TARGET_URL: TARGET,
      AGENT_BENCHMARK_ORA_BASE: ORA_BASE, AGENT_BENCHMARK_IIAR_BASE: IIAR_BASE,
      AGENT_BENCHMARK_POLL_MS: '20', AGENT_BENCHMARK_POLL_MAX_MS: '400', AGENT_BENCHMARK_TIMEOUT_MS: '5000',
      ...extra,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  const killer = setTimeout(() => child.kill('SIGKILL'), 30000);
  child.on('close', (status) => {
    clearTimeout(killer);
    const read = (f) => (fs.existsSync(f) && fs.statSync(f).isFile() ? fs.readFileSync(f, 'utf8') : '');
    let json = null; try { json = JSON.parse(read(jsonPath)); } catch { /* none written */ }
    const outputs = Object.fromEntries(read(outputPath).split('\n').filter(Boolean).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
    resolve({ status, stdout, stderr, summary: read(summaryPath), outputRaw: read(outputPath), outputs, json });
  });
});
const HEADER = '## 🤖 agent-benchmark';
// A line the runner would read as a command: `::` after leading whitespace, or `##[` anywhere.
const commands = (text) => text.split('\n').filter((l) => /^\s*::/.test(l) || l.includes('##['));
const once = (r) => r.stdout.split(HEADER).length === 2;
const why = (r) => `exit ${r.status}, ${r.stdout.length} B stdout, stderr ${JSON.stringify(r.stderr.split('\n').find((l) => l.trim()) || '')}`;
const posts = (s) => s.hits.filter((h) => h.method === 'POST');
const gets = (s) => s.hits.filter((h) => h.method === 'GET');
const oraLine = (r) => r.stdout.split('\n').find((l) => l.startsWith('- **') && l.includes('grade')) || '';

try {
  console.log('\n# a complete scan, on Actions');
  queue([{ status: 200, body: AUDIT() }]);
  const a = await run({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true' });
  check('exit 0', a.status === 0, why(a));
  check('the report reaches the log once', once(a), why(a));
  check('the step summary is the report, and the log carries all of it', a.summary.startsWith(HEADER) && a.stdout.includes(a.summary), JSON.stringify(a.summary.slice(0, 80)));
  check('ora: score, grade, the scan time, analysis complete', /^- \*\*52\/100, grade C\*\* · scanned 2026-10-08 13:17 UTC · analysis complete$/m.test(a.stdout), oraLine(a));
  check('ora: the layers line', a.stdout.includes('- layers: Discovery 2/6 · Access 25/42 · Payments 0/0'));
  check('ora: the status counts', a.stdout.includes('- checks: 1 pass · 2 warning · 2 fail · 1 not applicable'));
  check('ora: top fixes with their estimated gain', a.stdout.includes("- top fixes (ora's estimated score gain): `webmcp` +9.7 · `ard-catalog` +3.7"));
  check('ora: a layer with nothing to give is named unscored', a.stdout.includes('- unscored here (layer max 0): Payments'));
  check('ora: the to-do table skips the unscored layer', !/\| `ucp-support` \|/.test(a.stdout) && a.stdout.includes('3 check(s) fail or warn'));
  const rows = a.stdout.split('\n').filter((l) => /^\| (Discovery|Access) \| `/.test(l)).map((l) => l.split('`')[1]);
  check('ora: the required tier first, then by estimated gain', JSON.stringify(rows) === JSON.stringify(['ard-catalog', 'json-ld', 'markdown-negotiation']), JSON.stringify(rows));
  check('isitagentready: level and name', a.stdout.includes('- **level 1 (Basic Web Presence)**'));
  check('isitagentready: what the next level needs', a.stdout.includes('- next: level 2 (Bot-Aware) needs `contentSignals`: Declare AI content usage preferences'));
  check('isitagentready: a line per category', a.stdout.includes('- discoverability: ✅ robotsTxt · ❌ linkHeaders') && a.stdout.includes('- botAccessControl: ❌ contentSignals · ➖ webBotAuth'));
  check('one ::notice with both headlines, nothing else command-shaped', JSON.stringify(commands(a.stdout)) === JSON.stringify(['::notice title=agent-benchmark::ora 52/100 (C) · isitagentready level 1 (Basic Web Presence)']), JSON.stringify(commands(a.stdout)));
  check('no command lines in the step summary', commands(a.summary).length === 0);
  check('outputs: score, grade, level, the JSON path', a.outputs['ora-score'] === '52' && a.outputs['ora-grade'] === 'C' && a.outputs['isitagentready-level'] === '1' && a.outputs.json === jsonPath, JSON.stringify(a.outputs));
  check('the JSON holds both answers in full', a.json && a.json.target === TARGET && a.json.ora.audit.score === 52 && a.json.ora.audit.layers.length === 3 && a.json.isitagentready.result.level === 1, JSON.stringify(a.json).slice(0, 200));
  const op = posts(ora.st)[0] || {}, ip = posts(iiar.st)[0] || {};
  check('ora gets POST /api/scan?format=audit with the url and nothing else (never force, never ephemeral)', op.url === '/api/scan?format=audit' && op.body === JSON.stringify({ url: TARGET }), JSON.stringify(op.body));
  check('isitagentready gets POST /api/scan with the url and nothing else', ip.url === '/api/scan' && ip.body === JSON.stringify({ url: TARGET }), JSON.stringify(ip.body));
  check('both requests carry our user-agent and no credential header', [op, ip].every((h) => h.headers && /^ci-actions-agent-benchmark\//.test(h.headers['user-agent'] || '') && !h.headers.authorization && !h.headers.cookie));
  check('a complete answer is not polled', gets(ora.st).length === 0, `${gets(ora.st).length} GET(s)`);

  console.log('\n# off Actions: no workflow commands; /dev/stdout as the summary means none');
  for (const [label, extra] of [['local run', {}], ['GITHUB_STEP_SUMMARY=/dev/stdout', { GITHUB_STEP_SUMMARY: '/dev/stdout' }]]) {
    queue([{ status: 200, body: AUDIT() }]);
    const b = await run(extra);
    check(`${label}: exit 0, printed once, no commands`, b.status === 0 && once(b) && b.stdout.length > 0 && commands(b.stdout).length === 0, why(b));
  }

  console.log("\n# ora's cache");
  queue([{ status: 200, body: AUDIT({ servedFromCache: true, resultAgeSeconds: 7200 }) }]);
  const c = await run();
  check("a cache-served answer says so, with its age", c.stdout.includes("served from ora's cache (scanned 2026-10-08 13:17 UTC, 2 h ago;"), oraLine(c));

  console.log('\n# 202: scored, analysis still running');
  queue([{ status: 202, body: AUDIT({ score: 40, analysisStatus: 'partial', pendingChecks: ['x'] }) }],
    [{ status: 200, body: AUDIT({ score: 45, analysisStatus: 'partial', pendingChecks: ['x'] }) }, { status: 200, body: AUDIT() }]);
  const d = await run();
  check('polled until complete: the final score, "after 2 poll(s)"', d.stdout.includes('**52/100, grade C**') && d.stdout.includes('analysis complete after 2 poll(s)'), oraLine(d));
  check('the poll reads GET /api/score/<domain>?format=audit', gets(ora.st).length === 2 && gets(ora.st).every((h) => h.url === '/api/score/example.test?format=audit'), JSON.stringify(gets(ora.st).map((h) => h.url)));

  queue([{ status: 202, body: AUDIT({ score: 40, scannedAt: T2, analysisStatus: 'partial', pendingChecks: ['x'] }) }], [{ status: 200, body: AUDIT({ scannedAt: T1 }) }]);
  const e = await run();
  check('a polled answer OLDER than the scan in hand (a CDN copy) is never taken', e.stdout.includes('**40/100, grade C**') && e.outputs['ora-score'] === '40', oraLine(e));
  check('… and at the deadline the report says the score may still move', /analysis still running after \d+ s: the score may still move/.test(e.stdout), oraLine(e));
  check('… having polled until then', gets(ora.st).length >= 3, `${gets(ora.st).length} GET(s)`);

  queue([{ status: 202, body: AUDIT({ score: 40, analysisStatus: 'partial', pendingChecks: ['x'] }) }], [{ status: 200, body: AUDIT({ score: 41, analysisStatus: 'stuck' }) }]);
  const f = await run();
  check('stuck: polling stops, the score is what it reached', f.stdout.includes('**41/100, grade C**') && f.stdout.includes('ora reports its analysis stuck') && gets(ora.st).length === 1, oraLine(f));

  console.log('\n# 429: rate-limited');
  queue([{ status: 429, headers: { 'retry-after': '3600' }, body: { error: 'daily quota' } }], [{ status: 200, body: AUDIT() }]);
  const g = await run();
  check('a long Retry-After (the daily quota): no retry, the stored result is read and labelled', posts(ora.st).length === 1 && g.stdout.includes('**52/100, grade C**') && g.stdout.includes('ora rate-limited this runner, so this is its last stored result'), `${posts(ora.st).length} POST(s); ${oraLine(g)}`);
  queue([{ status: 429, body: { error: 'slow down' } }], [{ status: 200, body: AUDIT() }]);
  const h = await run();
  check('a 429 with no Retry-After is not retried either', posts(ora.st).length === 1 && h.stdout.includes('its last stored result'), `${posts(ora.st).length} POST(s)`);
  queue([{ status: 429, headers: { 'retry-after': '0' }, body: { error: 'burst' } }, { status: 200, body: AUDIT() }]);
  const i = await run();
  check('a short Retry-After (the burst cap): one retry, then a normal reading', posts(ora.st).length === 2 && gets(ora.st).length === 0 && /^- \*\*52\/100, grade C\*\* · scanned /m.test(i.stdout), `${posts(ora.st).length} POST(s); ${oraLine(i)}`);
  queue([{ status: 429, headers: { 'retry-after': '3600' }, body: { error: 'daily quota' } }], [{ status: 404, body: { code: 'DOMAIN_NOT_SCANNED' } }]);
  const j = await run();
  check('rate-limited and never scanned: could not look, no score output', j.status === 0 && j.stdout.includes('- ⚠️ could not look: rate-limited (HTTP 429), and ora has no stored result for this domain. Not a verdict about the site.') && j.outputs['ora-score'] === '' && j.outputs['ora-grade'] === '', why(j));

  console.log('\n# a scanner that could not look is never a score');
  const cnl = [
    ['HTTP 500', [{ status: 500, body: { error: 'Scan failed' } }], 'could not look: HTTP 500 (Scan failed).'],
    ['an answer that is not JSON', [{ status: 200, body: '<html>oops</html>' }], 'could not look: HTTP 200, but the answer is not JSON.'],
    ['JSON without a score', [{ status: 200, body: { error: 'bad input' } }], 'could not look: HTTP 200, but the answer has no score (bad input).'],
    ['an answer over 5 MB', [{ status: 200, body: JSON.stringify({ pad: 'x'.repeat(6 * 1024 * 1024) }) }], 'could not look: answered with over 5 MB.'],
  ];
  for (const [label, answers, text] of cnl) {
    queue(answers);
    const r = await run();
    check(`ora, ${label}: exit 0, named, no score output`, r.status === 0 && r.stdout.includes(text) && r.outputs['ora-score'] === '' && !oraLine(r), `${why(r)} ${JSON.stringify((r.stdout.match(/could not look:[^\n]*/) || [''])[0])}`);
  }
  queue([{ status: 200, body: AUDIT(), delayMs: 2500 }]);
  const k = await run({ AGENT_BENCHMARK_TIMEOUT_MS: '1000' });
  check('ora, no answer in time: could not look, named as a timeout', k.status === 0 && k.stdout.includes('could not look: no answer within 1 s.'), why(k));
  const closed = createServer();
  await new Promise((r) => closed.listen(0, '127.0.0.1', r));
  const deadBase = `http://127.0.0.1:${closed.address().port}`;
  await new Promise((r) => closed.close(r));
  queue([]);
  const l = await run({ AGENT_BENCHMARK_ORA_BASE: deadBase });
  check('ora, connection refused: could not look, the other leg still reports', l.status === 0 && /could not look: ECONNREFUSED/.test(l.stdout) && l.stdout.includes('- **level 1 (Basic Web Presence)**'), why(l));
  for (const [label, answers, text] of [
    ['HTTP 500', [{ status: 500, body: { error: 'boom' } }], 'could not look: HTTP 500 (boom).'],
    ['JSON without a level', [{ status: 200, body: { error: 'Could not reach site' } }], 'could not look: HTTP 200, but the answer has no level (Could not reach site).'],
  ]) {
    queue([{ status: 200, body: AUDIT() }], [], answers);
    const r = await run({ GITHUB_ACTIONS: 'true' });
    check(`isitagentready, ${label}: exit 0, named, no level output, the notice says so`, r.status === 0 && r.stdout.includes(text) && r.outputs['isitagentready-level'] === '' && r.stdout.includes('::notice title=agent-benchmark::ora 52/100 (C) · isitagentready could not look'), why(r));
  }

  console.log('\n# hostile scanner strings are defused');
  const HOSTILE = AUDIT({
    domain: '../../evil?x=', grade: 'C\n::error::pwned-grade', analysisStatus: 'partial', pendingChecks: ['x'],
    layers: [{ id: 'd', name: 'Disc\n::warning::pwned-layer', score: 1, maxScore: 6, checks: [
      { id: 'x`|<img src=x onerror=alert(1)>', status: 'fail', tier: 'required', recommendation: '![b](https://beacon.example/p.png) ##[error]pwned-legacy \u2028::error::pwned-sep' },
    ] }],
    topFixes: [{ id: '\r\n::error::pwned-fix', estScoreGain: 1 }],
  });
  const HOSTILE_LEVEL = LEVEL({
    levelName: 'Basic\n::error::pwned-level',
    checks: { 'cat<script>': { 'id\n::error::pwned-id': { status: 'constructor' }, ok: { status: '__proto__' } } },
    nextLevel: { target: 2, name: 'Next', requirements: [{ check: 'c', description: 'see [here](javascript:alert(1)) pwned-req' }] },
  });
  queue([{ status: 202, body: HOSTILE }], [{ status: 200, body: { ...HOSTILE, analysisStatus: 'complete' } }], [{ status: 200, body: HOSTILE_LEVEL }]);
  const m = await run({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true' });
  check('exit 0, printed once, no crash', m.status === 0 && once(m) && !m.stdout.includes('crashed'), why(m));
  check('the planted strings reached the report (so the test is real)', ['pwned-layer', 'pwned-legacy', 'pwned-sep', 'pwned-fix', 'pwned-level', 'pwned-id', 'pwned-req'].every((s) => m.stdout.includes(s)));
  const cmds = commands(m.stdout);
  check('the only command-shaped line is our ::notice, on one line', cmds.length === 1 && cmds[0].startsWith('::notice title=agent-benchmark::'), JSON.stringify(cmds));
  check('no HTML, no link or image, no legacy command, no separator character in the summary', !/<img|<script|\]\(|##\[|\u2028/.test(m.summary), JSON.stringify((m.summary.match(/.{0,30}(<img|<script|\]\(|##\[|\u2028).{0,30}/) || [''])[0]));
  check('a grade that is not a grade is shown as ?, and never output', m.stdout.includes(', grade ?**') && m.outputs['ora-grade'] === '', JSON.stringify(m.outputs));
  check('GITHUB_OUTPUT carries exactly the four keys, nothing injected', m.outputRaw.split('\n').filter(Boolean).length === 4 && Object.keys(m.outputs).join() === 'ora-score,ora-grade,isitagentready-level,json', JSON.stringify(m.outputRaw));
  check('a domain that is not a hostname never reaches the poll path (the target host is used)', gets(ora.st).length >= 1 && gets(ora.st).every((x) => x.url === '/api/score/www.example.test?format=audit'), JSON.stringify(gets(ora.st).map((x) => x.url)));
  check('a status named like an Object prototype key (constructor, __proto__) renders as ❔, no crash', /^- catscript: ❔ id ::error::pwned-id, ok$/m.test(m.stdout), JSON.stringify((m.stdout.match(/- catscript[^\n]*/) || [''])[0]));

  console.log('\n# switches and inputs');
  queue([{ status: 200, body: AUDIT() }]);
  const n = await run({ ORA: 'FALSE ', GITHUB_ACTIONS: 'true' });
  check('ora off ("FALSE " counts): never asked, said so, isitagentready still runs', ora.st.hits.length === 0 && n.stdout.includes('- off (`ora: false`)') && n.stdout.includes('- **level 1') && n.stdout.includes('::notice title=agent-benchmark::ora off · isitagentready level 1'), why(n));
  queue([{ status: 200, body: AUDIT() }]);
  const o = await run({ ISITAGENTREADY: 'false' });
  check('isitagentready off: never asked, said so', iiar.st.hits.length === 0 && o.stdout.includes('- off (`isitagentready: false`)') && o.stdout.includes('**52/100'), why(o));
  queue([{ status: 200, body: AUDIT() }]);
  const p = await run({ ORA: 'false', ISITAGENTREADY: 'false', GITHUB_ACTIONS: 'true' });
  check('both off: nothing asked, skipped, no notice, outputs empty', p.status === 0 && ora.st.hits.length + iiar.st.hits.length === 0 && p.stdout.includes('both scanners are off') && commands(p.stdout).length === 0 && Object.values(p.outputs).every((v) => v === ''), why(p));
  for (const [label, url, text] of [['no url', '', '- no usable `url`: nothing to scan (skipped)'], ['an ftp url', 'ftp://example.test/', '(ftp://example.test/ is not an http(s) URL)']]) {
    queue([{ status: 200, body: AUDIT() }]);
    const r = await run({ TARGET_URL: url, GITHUB_ACTIONS: 'true' });
    check(`${label}: skipped, exit 0, nothing asked, no JSON, empty outputs`, r.status === 0 && r.stdout.includes(text) && ora.st.hits.length + iiar.st.hits.length === 0 && !r.json && r.outputRaw.split('\n').filter(Boolean).length === 4 && commands(r.stdout).length === 0, why(r));
  }
  queue([{ status: 200, body: AUDIT() }]);
  await run({ TARGET_URL: 'www.example.test' });
  check('a bare host gets https:// and a path', (posts(ora.st)[0] || {}).body === JSON.stringify({ url: 'https://www.example.test/' }), (posts(ora.st)[0] || {}).body);
  queue([{ status: 200, body: AUDIT() }]);
  await run({ TARGET_URL: 'https://user:secret@www.example.test/shop?q=1#top' });
  check('credentials and the fragment never leave the runner', [...posts(ora.st), ...posts(iiar.st)].every((x) => x.body === JSON.stringify({ url: 'https://www.example.test/shop?q=1' })), JSON.stringify(posts(ora.st).map((x) => x.body)));

  console.log('\n# faults in our own sinks');
  const sinkDir = path.join(tmp, 'summary-is-a-dir');
  fs.mkdirSync(sinkDir);
  queue([{ status: 200, body: AUDIT() }]);
  const q = await run({ GITHUB_STEP_SUMMARY: sinkDir, GITHUB_ACTIONS: 'true' });
  check('unwritable summary: exit 0, the report in the log once, the fault named on one line', q.status === 0 && once(q) && /agent-benchmark crashed: .*EISDIR/.test(q.stdout) && !/^\s+at /m.test(q.stdout), why(q));
  const fileAsDir = path.join(tmp, 'runner-temp-is-a-file');
  fs.writeFileSync(fileAsDir, '');
  queue([{ status: 200, body: AUDIT() }]);
  const s = await run({ RUNNER_TEMP: fileAsDir });
  check('unwritable JSON: said so, no json output, the scores still output, exit 0', s.status === 0 && s.stdout.includes('- ⚠️ the JSON could not be written:') && s.outputs.json === '' && s.outputs['ora-score'] === '52', why(s));
  const nlDir = path.join(tmp, 'a\nb');
  fs.mkdirSync(nlDir);
  queue([{ status: 200, body: AUDIT() }]);
  const t = await run({ RUNNER_TEMP: nlDir });
  check('a JSON path with a line break is never written to GITHUB_OUTPUT', t.status === 0 && t.outputs.json === '' && t.outputRaw.split('\n').filter(Boolean).length === 4, JSON.stringify(t.outputRaw));

  console.log('\n# action.yml → benchmark.mjs wiring');
  const yml = fs.readFileSync(path.join(HERE, '..', 'action.yml'), 'utf8');
  const src = fs.readFileSync(ENTRY, 'utf8');
  const envKeys = [...(yml.split(/^\s+env:\s*$/m)[1] || '').matchAll(/^\s{8}([A-Z_]+):/gm)].map((x) => x[1]);
  check('the step passes TARGET_URL, ORA, ISITAGENTREADY', JSON.stringify(envKeys) === JSON.stringify(['TARGET_URL', 'ORA', 'ISITAGENTREADY']), JSON.stringify(envKeys));
  check('the script reads every one of them', envKeys.length > 0 && envKeys.every((k) => src.includes(`env.${k}`)));
  check('no GITHUB_-prefixed name in the step env (it would shadow the ambient one)', !envKeys.some((k) => k.startsWith('GITHUB_')));
  for (const k of ['ora-score', 'ora-grade', 'isitagentready-level', 'json']) {
    check(`output ${k} maps to the step's own and the script writes it`, yml.includes(`value: \${{ steps.bench.outputs.${k} }}`) && src.includes(`'${k}'`) || (k === 'json' && yml.includes('value: ${{ steps.bench.outputs.json }}') && /\bjson: ''/.test(src)));
  }
  check('the step id is bench', /^\s+id: bench$/m.test(yml));
  check('inputs: url required, both switches default true', /\n  url:\n(?:    .*\n)*?    required: true/.test(yml) && /\n  ora:\n(?:    .*\n)*?    default: 'true'/.test(yml) && /\n  isitagentready:\n(?:    .*\n)*?    default: 'true'/.test(yml));
} finally {
  ora.server.close();
  iiar.server.close();
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
