/* SELinux Manager core: pure helpers with no DOM, tested in Node (tests/core.test.js). */
(function (root) {
  'use strict';

  function parseKV(txt) {
    const o = {};
    String(txt || '').split('\n').forEach(l => {
      const i = l.indexOf('=');
      if (i > 0) o[l.slice(0, i).trim()] = l.slice(i + 1).trim();
    });
    return o;
  }

  function field(line, re) { const m = line.match(re); return m ? m[1] : null; }
  /* "MM-DD HH:MM:SS.mmm" at the start of a logcat line, as epoch seconds in this year. */
  function logcatTime(l, now) {
    const m = l.match(/^\s*(\d\d)-(\d\d)\s+(\d\d):(\d\d):(\d\d)(?:\.(\d+))?\s/);
    if (!m) return 0;
    const y = (now || new Date()).getFullYear();
    return new Date(y, +m[1] - 1, +m[2], +m[3], +m[4], +m[5]).getTime() / 1000;
  }
  function typeOf(ctx) { const p = String(ctx || '').split(':'); return p.length >= 3 ? p[2] : null; }

  /*
   * avc lines from logcat and dmesg. One kernel event can appear in both, so events are
   * de-duplicated by audit serial. `since` (epoch seconds) drops older events, which is how
   * a recording session works. Grouped by source type, target type and class.
   */
  function parseAvc(txt, since) {
    const seen = new Set();
    const groups = new Map();
    String(txt || '').split('\n').forEach(l => {
      if (!/avc:\s+denied/.test(l)) return;
      let time = parseFloat(field(l, /audit\(([\d.]+):\d+\)/) || '0');
      // logcat copies of audit events often say audit(0.0:N); use the logcat header time.
      if (!time) time = logcatTime(l);
      if (since && time && time < since) return;
      const serial = field(l, /audit\([\d.]+:(\d+)\)/);
      const key = serial ? 's' + serial : l.replace(/^.*?avc:/, 'avc:');
      if (seen.has(key)) return;
      seen.add(key);
      const perms = field(l, /denied\s+\{([^}]+)\}/);
      const s = typeOf(field(l, /scontext=(\S+)/));
      const t = typeOf(field(l, /tcontext=(\S+)/));
      const c = field(l, /tclass=(\S+)/);
      if (!perms || !s || !t || !c) return;
      const k = s + ' ' + t + ' ' + c;
      let g = groups.get(k);
      if (!g) {
        g = { s, t, c, perms: new Set(), n: 0, comms: new Set(), paths: new Set(), pids: new Set(), permissive: false, last: 0 };
        groups.set(k, g);
      }
      perms.trim().split(/\s+/).forEach(p => g.perms.add(p));
      g.n++;
      if (time > g.last) g.last = time;
      const comm = field(l, /comm="([^"]*)"/); if (comm) g.comms.add(comm);
      const path = field(l, /\bpath="([^"]*)"/) || field(l, /\bname="([^"]*)"/); if (path) g.paths.add(path);
      // dmesg lines carry pid=; logcat lines often drop it and keep the pid in the
      // logcat header instead ("date time PID TID W tag: ...").
      const pid = field(l, /\bpid=(\d+)/) || field(l, /^\s*\d\d-\d\d\s+[\d:.]+\s+(\d+)\s+\d+\s+[VDIWEF]\s/);
      if (pid) g.pids.add(pid);
      if (/permissive=1/.test(l)) g.permissive = true;
    });
    return [...groups.values()].sort((a, b) => b.n - a.n).map(g => Object.assign(g, { rule: ruleFor(g) }));
  }

  function ruleFor(g, action) {
    const p = [...g.perms].sort();
    return (action || 'allow') + ' ' + g.s + ' ' + g.t + ' ' + g.c + ' ' + (p.length === 1 ? p[0] : '{ ' + p.join(' ') + ' }');
  }

  const NAME = /^[A-Za-z0-9_.*~-]+$/;
  const ACTIONS = ['allow', 'deny', 'auditallow', 'dontaudit', 'permissive', 'enforce'];

  function buildRule(a, s, t, c, perms) {
    const list = String(perms || '').trim().split(/[\s,]+/).filter(Boolean);
    if (!ACTIONS.includes(a)) return { rule: null, why: 'action' };
    if (!NAME.test(s || '')) return { rule: null, why: 'source' };
    if (a === 'permissive' || a === 'enforce') return { rule: a + ' ' + s, why: null };
    if (!NAME.test(t || '')) return { rule: null, why: 'target' };
    if (!NAME.test(c || '')) return { rule: null, why: 'class' };
    if (!list.length || !list.every(x => NAME.test(x))) return { rule: null, why: 'permissions' };
    const p = list.length === 1 ? list[0] : '{ ' + list.join(' ') + ' }';
    return { rule: a + ' ' + s + ' ' + t + ' ' + c + ' ' + p, why: null };
  }

  const APP = /^(untrusted_app|isolated_app|ephemeral_app|platform_app|priv_app|shell|sdk_sandbox)/;

  /* Why a rule deserves a second look, or null. Advice only, the user decides. */
  function riskOf(rule) {
    const r = String(rule || '').trim(), w = r.split(/\s+/);
    if (/[*~]/.test(r)) return 'wide';
    if (w[0] === 'permissive') return 'permissive';
    if (w[0] === 'allow' && APP.test(w[1] || '')) return 'app';
    return null;
  }

  function ruleLines(txt) {
    return String(txt || '').split('\n').map(x => x.trim()).filter(x => x && !x.startsWith('#'));
  }

  /* Line diff between two rule files: what was added and what was removed. */
  function diffRules(oldTxt, newTxt) {
    const a = new Set(ruleLines(oldTxt)), b = new Set(ruleLines(newTxt));
    return { added: [...b].filter(x => !a.has(x)), removed: [...a].filter(x => !b.has(x)) };
  }

  /* ps -AZ: LABEL USER PID PPID VSZ RSS WCHAN ADDR S NAME */
  function parsePs(txt) {
    return String(txt || '').split('\n').slice(1).map(l => l.trim().split(/\s+/)).filter(p => p.length >= 9)
      .map(p => ({ label: p[0], type: typeOf(p[0]), user: p[1], pid: p[2], name: p[p.length - 1] }));
  }

  function domains(procs) {
    const m = new Map();
    procs.forEach(p => {
      if (!p.type) return;
      const d = m.get(p.type) || { type: p.type, n: 0, names: [] };
      d.n++; if (d.names.length < 8) d.names.push(p.name);
      m.set(p.type, d);
    });
    return [...m.values()].sort((a, b) => b.n - a.n || (a.type < b.type ? -1 : 1));
  }

  /* modules-scan output: "### <id> <enabled|disabled>" headers followed by that module's rule lines. */
  function parseModuleScan(txt) {
    const mods = []; let cur = null;
    String(txt || '').split('\n').forEach(l => {
      const h = l.match(/^### (\S+) (enabled|disabled)$/);
      if (h) { cur = { id: h[1], enabled: h[2] === 'enabled', rules: [] }; mods.push(cur); return; }
      const r = l.trim();
      if (cur && r && !r.startsWith('#')) cur.rules.push(r);
    });
    const owners = new Map();
    mods.forEach(m => m.rules.forEach(r => {
      const o = owners.get(r) || []; o.push(m.id); owners.set(r, o);
    }));
    const shared = [...owners.entries()].filter(([, ids]) => ids.length > 1).map(([rule, ids]) => ({ rule, ids }));
    const permissive = [];
    mods.forEach(m => m.rules.forEach(r => { if (/^permissive\s/.test(r)) permissive.push({ id: m.id, rule: r }); }));
    return { mods, shared, permissive };
  }

  /* owners output: "pid|uid|package|cmdline" per line. */
  function parseOwners(txt) {
    const m = {};
    String(txt || '').split('\n').forEach(l => {
      const p = l.split('|');
      if (p.length >= 4 && p[0]) m[p[0]] = { uid: p[1], pkg: p[2], cmd: p[3] };
    });
    return m;
  }

  /* packages.list rows: name uid debuggable datadir seinfo gids... */
  function parsePackages(txt) {
    return String(txt || '').split('\n').map(l => l.trim().split(/\s+/)).filter(p => p.length >= 5)
      .map(p => ({ pkg: p[0], uid: p[1], seinfo: p[4] }));
  }

  const TEMPLATES = [
    { name: 'Silence one noisy denial', rule: 'dontaudit SOURCE TARGET CLASS { PERMS }' },
    { name: 'Module service reads its own files', rule: 'allow init TARGET file { read open getattr }' },
    { name: 'App reads a sysfs node', rule: 'allow untrusted_app sysfs file { read open getattr }' },
    { name: 'Domain talks to a binder service', rule: 'allow SOURCE TARGET binder { call transfer }' },
    { name: 'Make one domain permissive (debug only)', rule: 'permissive SOURCE' },
    { name: 'Put a domain back to enforcing', rule: 'enforce SOURCE' }
  ];

  const api = { parseKV, parseAvc, ruleFor, buildRule, riskOf, ruleLines, diffRules, parsePs, domains,
    parseModuleScan, parseOwners, parsePackages, typeOf, logcatTime, ACTIONS, TEMPLATES };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.Core = api;
})(this);
