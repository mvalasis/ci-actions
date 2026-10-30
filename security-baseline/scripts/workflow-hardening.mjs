// security-baseline — workflow hardening and vendor pins. PURE apart from the caller's own reads: no
// network, no process exit. scan.mjs lists the tree and hands each file here; selftest.mjs plants one
// defect per detector. Four of these ask what a workflow LACKS or how two of its parts combine, which
// a semgrep pattern over one YAML node cannot say, so they are not in rules/gha.yaml. Their ids carry
// `wf-`, not `gha-`: LEGS.gha claims every `gha-` id for the semgrep leg.
//
// The workflow reader is line-based on purpose, the action having no YAML dependency: it knows
// top-level keys and `run:` scalars, plain or block. All of it is a WARN a caller may promote.
import crypto from 'node:crypto';

const indent = (l) => l.length - l.trimStart().length;
// A `run:` key, with or without the list dash: its inline text, or '' for a block scalar's marker.
const RUN = /^(\s*(?:-\s+)?)run:\s*(.*)$/;
const BLOCK = /^[|>][-+0-9]*\s*(#.*)?$/;

// Every shell line of a workflow as { line, text }, shell comments dropped.
export function runLines(src) {
  const lines = String(src).split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(RUN);
    if (!m) continue;
    const at = m[1].length;   // the key's own column: a step's `env:` sits there, past the list dash
    if (!BLOCK.test(m[2])) { if (m[2]) out.push({ line: i + 1, text: m[2] }); continue; }
    let j = i + 1;
    for (; j < lines.length; j++) {
      if (lines[j].trim() === '') continue;
      if (indent(lines[j]) <= at) break;
      if (!lines[j].trim().startsWith('#')) out.push({ line: j + 1, text: lines[j].trim() });
    }
    i = j - 1;
  }
  return out;
}

const DEPLOYS = /\b(?:rsync|scp)\s|\bssh\s|\bwrangler\s+(?:pages\s+)?deploy\b|\beas\s+(?:build|submit|update)\b/;
const SECRET = /\$\{\{[^}]*\bsecrets\.([A-Za-z0-9_-]+)/;

export function findWorkflowHardening(src) {
  const text = String(src);
  const lines = text.split(/\r?\n/);
  const out = [];
  const shell = runLines(text);
  if (!lines.some((l) => /^permissions:/.test(l))) {
    out.push({ checkId: 'wf-no-permissions', line: 1, rule: 'no top-level permissions', cwe: 'CWE-250',
      msg: 'no top-level permissions: — this workflow inherits the repository default token scope; declare the least it needs' });
  }
  const deploy = shell.find((s) => DEPLOYS.test(s.text));
  if (deploy) {
    // A `${{ … }}` value is the usual "cancel PR runs, never a deploy", which only the run can judge.
    const at = lines.findIndex((l) => /^\s*cancel-in-progress:\s*true\b/.test(l));
    if (at >= 0) out.push({ checkId: 'wf-cancel-deploy', line: at + 1, rule: 'cancel-in-progress: true', cwe: 'CWE-662',
      msg: `cancel-in-progress: true on a workflow that deploys (line ${deploy.line}) — a cancel mid-transfer leaves the site half-written and skips what follows; set it to false` });
  }
  for (const s of shell) {
    if (/\bssh-keyscan\b/.test(s.text)) out.push({ checkId: 'wf-ssh-keyscan', line: s.line, rule: 'ssh-keyscan', cwe: 'CWE-295',
      msg: 'ssh-keyscan trusts whatever answers on first use — pin the host key in a tracked known_hosts and connect with StrictHostKeyChecking yes' });
    const m = s.text.match(SECRET);
    if (m) out.push({ checkId: 'wf-secret-in-run', line: s.line, rule: `secrets.${m[1]}`, cwe: 'CWE-214',
      msg: `secrets.${m[1]} is expanded inside a run: block, into the step's script file and any argv it reaches — read it through the step's env: instead` });
  }
  return out.map((f) => ({ tool: 'workflow-hardening', ...f }));
}

// ---------- vendor pins ----------
// Third-party code no package manager tracks, against a `deps.json` of the shape luxairportlu's:
// { vendored: [{ name, dir, files: { <relative path>: <sha256> } }], cdn: [{ name, version, url, sri }] }.
// Fonts are left out: Google Fonts' CSS differs per browser, so it can carry no integrity.
const CDN_HOSTS = 'code\\.jquery\\.com|cdn\\.jsdelivr\\.net|cdnjs\\.cloudflare\\.com|unpkg\\.com|ajax\\.googleapis\\.com|stackpath\\.bootstrapcdn\\.com|maxcdn\\.bootstrapcdn\\.com';
const CDN_URL = new RegExp(`(?:https?:)?//(?:${CDN_HOSTS})/[^\\s'"<>)]+`, 'g');
const TAG = /<(?:script|link)\b[^>]*>/gi;
const ENQUEUE = /\bwp_(?:enqueue|register)_(?:script|style)\s*\([^;]*;/g;
const SOURCE = /\.(?:php|html?|astro|twig|vue|[jt]sx)$/i;
const SKIP = /(?:^|\/)(?:wp-admin|wp-includes|vendor|node_modules|dist|build)\//;

export const vendorTarget = (f) => SOURCE.test(f) && !SKIP.test(f) && !/\.min\./.test(f);

const lineAt = (src, i) => src.slice(0, i).split('\n').length;
const bare = (u) => String(u).replace(/^(?:https?:)?\/\//, '');
const vendorFinding = (line, rule, msg) => ({ checkId: 'vendor-pin', tool: 'vendor-pins', line, rule, cwe: 'CWE-1104', msg });

// One source file against the record. `deps` is null when the repository has no deps.json.
export function findCdnPins(src, deps) {
  const text = String(src);
  const cdn = deps && Array.isArray(deps.cdn) ? deps.cdn : [];
  const out = [];
  const recorded = (u) => cdn.find((c) => c && bare(c.url) === bare(u));
  for (const m of text.matchAll(TAG)) {
    const url = (m[0].match(CDN_URL) || [])[0];
    if (!url) continue;
    const line = lineAt(text, m.index);
    if (!/\bintegrity\s*=/i.test(m[0])) out.push(vendorFinding(line, url, `${url} loads from a public CDN with no integrity attribute — a changed file there runs here`));
    if (!recorded(url)) out.push(vendorFinding(line, url, `${url} is not recorded in deps.json — nothing can say this library's version when an advisory lands`));
  }
  for (const m of text.matchAll(ENQUEUE)) {
    const url = (m[0].match(CDN_URL) || [])[0];
    if (!url) continue;
    const line = lineAt(text, m.index);
    const entry = recorded(url);
    if (!entry) { out.push(vendorFinding(line, url, `${url} is enqueued from a public CDN and not recorded in deps.json, with its version and SRI`)); continue; }
    if (!entry.sri) out.push(vendorFinding(line, url, `${url} has no sri in deps.json, so its loader tag cannot carry one`));
    if (entry.version && !m[0].includes(`'${entry.version}'`) && !m[0].includes(`"${entry.version}"`)) {
      out.push(vendorFinding(line, url, `the enqueue of ${url} does not pass the version deps.json records, ${entry.version}`));
    }
  }
  return out;
}

// Each vendored directory against its hashes: `read(path)` gives a Buffer, or null when unreadable.
export function findVendoredDrift(deps, tracked, read) {
  const out = [];
  for (const v of (deps && Array.isArray(deps.vendored) ? deps.vendored : [])) {
    if (!v || typeof v.dir !== 'string' || !v.files || typeof v.files !== 'object') continue;
    const dir = v.dir.replace(/\/+$/, '');
    for (const [rel, want] of Object.entries(v.files)) {
      const file = `${dir}/${rel}`;
      const body = read(file);
      if (body == null) { out.push({ ...vendorFinding(0, v.name || dir, `${file} is recorded in deps.json and is not in the tree`), file }); continue; }
      const got = crypto.createHash('sha256').update(body).digest('hex');
      if (got !== String(want).toLowerCase()) out.push({ ...vendorFinding(0, v.name || dir, `${file} does not hash to its deps.json entry — a local patch keeps upstream's hash on record beside its own`), file });
    }
    for (const f of tracked) {
      if (f.startsWith(`${dir}/`) && !Object.prototype.hasOwnProperty.call(v.files, f.slice(dir.length + 1))) {
        out.push({ ...vendorFinding(0, v.name || dir, `${f} sits in a vendored directory and deps.json does not list it`), file: f });
      }
    }
  }
  return out;
}
