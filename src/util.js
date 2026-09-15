import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const IS_WIN = process.platform === 'win32';

/** Repo-relative POSIX path for a file, given an absolute or root-relative path. */
export function relPosix(root, p) {
  if (!p) return null;
  const abs = path.isAbsolute(p) ? p : path.resolve(root, p);
  let rel = path.relative(root, abs);
  if (rel.startsWith('..')) rel = abs; // outside root: keep absolute
  return rel.split(path.sep).join('/').replace(/^\.\//, '');
}

export function sha256(s) {
  return createHash('sha256').update(s).digest('hex');
}

export function sha256File(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

/** Run a command; never throws on non-zero exit. */
export function run(cmd, args = [], opts = {}) {
  const r = spawnSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    windowsHide: true,
    ...opts,
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', error: r.error || null };
}

/** Find an executable on PATH (plus extra dirs). Returns absolute path or null. */
export function which(name, extraDirs = []) {
  const exts = IS_WIN
    ? ['', ...(process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';').map((e) => e.toLowerCase())]
    : [''];
  const dirs = [...extraDirs, ...(process.env.PATH || '').split(path.delimiter)].filter(Boolean);
  for (const d of dirs) {
    for (const ext of exts) {
      const candidate = path.join(d, name + ext);
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch { /* not here */ }
    }
  }
  return null;
}

export function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { if (fallback !== undefined) return fallback; throw e; }
}

export function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

export function exists(p) { try { fs.accessSync(p); return true; } catch { return false; } }

/** Minimal glob to RegExp: supports **, *, ?, and a leading slash to anchor at the root. */
export function globToRegExp(glob) {
  let g = glob.replace(/\\/g, '/');
  const anchored = g.startsWith('/');
  if (anchored) g = g.slice(1);
  const special = new Set(['.', '+', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\']);
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*') {
      if (g[i + 1] === '*') {
        i++;
        if (g[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else if (special.has(c)) re += '\\' + c;
    else re += c;
  }
  return new RegExp((anchored ? '^' : '^(?:.*/)?') + re + '(?:/.*)?$');
}

export function matchesAny(file, globs = []) {
  return globs.some((g) => globToRegExp(g).test(file));
}

export const DEFAULT_IGNORE_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', 'target',
  'vendor', '.venv', 'venv', '__pycache__', '.secscan', '.terraform', '.idea', '.vscode',
]);

/** Walk a tree, skipping ignored dirs; yields absolute file paths. */
export function* walk(dir, { ignoreDirs = DEFAULT_IGNORE_DIRS, maxDepth = 40 } = {}, depth = 0) {
  if (depth > maxDepth) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (ignoreDirs.has(e.name)) continue;
      yield* walk(path.join(dir, e.name), { ignoreDirs, maxDepth }, depth + 1);
    } else if (e.isFile()) yield path.join(dir, e.name);
  }
}

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1 };

export function normalizeSeverity(s) {
  const v = String(s || '').toLowerCase();
  if (v === 'critical') return 'critical';
  if (v === 'high' || v === 'error') return 'high';
  if (v === 'medium' || v === 'moderate' || v === 'warning') return 'medium';
  if (v === 'low') return 'low';
  return 'info';
}

export function cvssToSeverity(score) {
  const n = Number(score);
  if (Number.isNaN(n)) return 'medium';
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  if (n > 0) return 'low';
  return 'info';
}

export function gitRoot(cwd) {
  const r = run('git', ['rev-parse', '--show-toplevel'], { cwd });
  return r.status === 0 ? r.stdout.trim() : null;
}

export function gitHead(cwd) {
  const r = run('git', ['rev-parse', 'HEAD'], { cwd });
  return r.status === 0 ? r.stdout.trim() : null;
}

/** Files changed: staged (default) or versus a base ref. Repo-relative POSIX paths. */
export function gitChangedFiles(root, base = null) {
  const common = ['diff', '--name-only', '--diff-filter=ACMR'];
  const attempts = base ? [[...common, `${base}...HEAD`], [...common, base]] : [[...common, '--cached']];
  for (const args of attempts) {
    const r = run('git', args, { cwd: root });
    if (r.status === 0) return r.stdout.split(/\r?\n/).filter(Boolean);
  }
  return [];
}

export function gitShow(root, ref, file) {
  const r = run('git', ['show', `${ref}:${file}`], { cwd: root });
  return r.status === 0 ? r.stdout : null;
}

export function nowIso() { return new Date().toISOString(); }
