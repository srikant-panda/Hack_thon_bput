#!/usr/bin/env node
/**
 * ORG-5 docs check — validates frontend/src/docs/content.ts against the real
 * backend. Checks:
 *   (a) every feature guide (id starting with "guide-") has >=1 code/diagram
 *       example block;
 *   (b) all TOC anchors resolve (doc ids referenced by hrefs exist);
 *   (c) audience and minRole tags are valid values;
 *   (d) every api-reference row (method, path) matches a REAL route parsed
 *       from backend/app/api/routes_*.py.
 *
 * Run: node scripts/check-docs.mjs   (from frontend/)
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const backend = join(root, '..', 'backend');

// content.ts is TypeScript — transpile the tiny typed subset we need by
// stripping types is fragile; instead import via a dynamic data extract:
// we evaluate it with a mini TS-type stripper (types are top-level only).
const ts = readFileSync(join(root, 'src', 'docs', 'content.ts'), 'utf8');
const js = ts
  .replace(/export type DocBlock =[\s\S]*?string\[\]\[\] \};/, '')
  .replace(/export type [^\n]+\n/g, '')
  .replace(/export interface [^{]*\{[^}]*\}/gs, '')
  .replace(/: DocBlock\[\]/g, '')
  .replace(/: DocSection\[\]/g, '')
  .replace(/: (Audience|MinRole|DocBlock|DocSection|string|string\[\]|number|boolean)(\[\])?/g, '')
  .replace(/\bas const\b/g, '');
const { DOC_SECTIONS } = await import(
  `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
);

let failures = 0;
const fail = (msg) => { console.error(`  ✖ ${msg}`); failures++; };
const ok = (msg) => console.log(`  ✔ ${msg}`);

// --- Parse real routes from backend routers -------------------------------
const HTTP = new Set(['get', 'post', 'put', 'patch', 'delete']);
const realRoutes = new Set();
for (const f of readdirSync(join(backend, 'app', 'api'))) {
  if (!f.startsWith('routes_') || !f.endsWith('.py')) continue;
  const src = readFileSync(join(backend, 'app', 'api', f), 'utf8');
  // Map every `<name> = APIRouter(prefix="…")` so multi-router files resolve.
  const prefixes = { '': '' };
  for (const m of src.matchAll(/(\w+)\s*=\s*APIRouter\(([^)]*)\)/gs)) {
    const pm = m[2].match(/prefix="([^"]*)"/);
    prefixes[m[1]] = pm ? pm[1] : '';
  }
  for (const m of src.matchAll(/@(\w+)\.(get|post|put|patch|delete)\(\s*\n?\s*"([^"]*)"/g)) {
    const method = m[2].toUpperCase();
    const prefix = prefixes[m[1]] ?? '';
    let path = (prefix + m[3]).replace(/\/$/, '') || '';
    realRoutes.add(`${method} ${path}`);
    // also accept the full prefixed form with /api/v1
    realRoutes.add(`${method} /api/v1${path === '' ? '' : path}`);
  }
}
if (realRoutes.size === 0) fail('no routes parsed from backend/app/api — parser broken?');
else ok(`parsed ${realRoutes.size} route entries from backend routers`);

// --- (a) feature guides carry example blocks ------------------------------
for (const s of DOC_SECTIONS) {
  if (!s.id.startsWith('guide-')) continue;
  const hasExample = s.body.some((b) => b.kind === 'code' || b.kind === 'diagram');
  if (!hasExample) fail(`feature guide '${s.id}' has no example block`);
}
ok('checked: every feature guide has >=1 example block');

// --- (b) anchors resolve ---------------------------------------------------
const ids = new Set(DOC_SECTIONS.map((s) => s.id));
for (const s of DOC_SECTIONS) {
  if (!ids.has(s.id)) fail(`section id '${s.id}' not resolvable`);
  for (const b of s.body) {
    const text = JSON.stringify(b);
    for (const m of text.matchAll(/#doc-([a-z0-9-]+)/g)) {
      if (!ids.has(m[1])) fail(`section '${s.id}' links to unknown anchor doc-${m[1]}`);
    }
  }
}
ok(`checked: all ${ids.size} TOC anchors resolve`);

// --- (c) audience / minRole valid -----------------------------------------
const AUD = new Set(['user', 'org', 'both']);
const ROLES = new Set(['viewer', 'analyst', 'admin']);
for (const s of DOC_SECTIONS) {
  if (!AUD.has(s.audience)) fail(`section '${s.id}' has invalid audience '${s.audience}'`);
  if (s.minRole !== undefined && !ROLES.has(s.minRole)) {
    fail(`section '${s.id}' has invalid minRole '${s.minRole}'`);
  }
  if (s.audience === 'org' && !s.minRole) {
    fail(`org section '${s.id}' must declare minRole`);
  }
}
ok('checked: audience/minRole tags valid');

// --- (d) api-reference rows ⊆ real routes ---------------------------------
const apiSection = DOC_SECTIONS.find((s) => s.id === 'api-reference');
if (!apiSection) fail('api-reference section missing');
else {
  const table = apiSection.body.find((b) => b.kind === 'table');
  if (!table) fail('api-reference has no route table');
  else {
    let checked = 0;
    for (const row of table.rows) {
      const [method, path] = row;
      // The docs table uses literal path params (e.g. {item_id}); the backend
      // may use different param names — compare with params normalized.
      const norm = (p) => p.replace(/\{[^}]+\}/g, '{param}');
      const m = `${method} ${norm(path)}`;
      const hit = [...realRoutes].some((r) => norm(r) === m);
      if (!hit) fail(`api-reference row does not match a real route: ${method} ${path}`);
      checked++;
    }
    if (checked > 0) ok(`checked: ${checked} api-reference rows ⊆ real routes`);
  }
}

console.log(failures === 0 ? '\ndocs check: ALL PASS' : `\ndocs check: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
