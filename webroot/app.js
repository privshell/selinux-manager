/* SELinux Manager WebUI. Logic that can be tested lives in core.js. */
'use strict';
const MOD = '/data/adb/modules/selinux_manager';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const store = { get: k => { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} } };
let theme = store.get('theme') || 'amoled';
let status = {};

function toast(m) { const e = $('#toast'); e.textContent = m; e.style.display = 'block'; clearTimeout(toast.t); toast.t = setTimeout(() => e.style.display = 'none', 3200); }
function el(tag, cls, txt) { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
function btn(label, fn) { const b = el('button', '', label); b.onclick = fn; return b; }
function show(pre, txt) { pre.hidden = false; pre.textContent = txt; }
function kvRows(box, rows) { box.textContent = ''; rows.forEach(([k, v]) => { const d = el('div', 'kv'); d.append(el('span', '', k), el('span', '', v || '-')); box.append(d); }); }

/* ---- shell bridge ---- */
function exec(cmd) {
  return new Promise(res => {
    if (typeof ksu === 'undefined' || !ksu.exec) { res({ errno: -1, stdout: '', stderr: 'no ksu' }); return; }
    const cb = 'cb' + Date.now() + Math.random().toString(36).slice(2);
    window[cb] = (e, o, r) => { delete window[cb]; res({ errno: e, stdout: o || '', stderr: r || '' }); };
    try { ksu.exec(cmd, '{}', cb); } catch (x) { delete window[cb]; res({ errno: -1, stdout: '', stderr: String(x) }); }
  });
}
const q = s => "'" + String(s).replace(/'/g, "'\\''") + "'";
const sectl = (...a) => exec('sh ' + MOD + '/bin/sectl.sh ' + a.map(q).join(' '));
const b64 = s => btoa(unescape(encodeURIComponent(s)));

const RISK = {
  wide: 'This rule uses a wildcard or complement and can cover far more than one case.',
  permissive: 'A permissive domain is not confined by SELinux at all.',
  app: 'This rule gives an app domain more access, and every app in that domain gets it.'
};
function okRisk(rule) { const r = Core.riskOf(rule); return !r || confirm(RISK[r] + ' Continue?\n\n' + rule); }
const LIVE = 'Applied live. It stays until reboot. Save it to keep it after reboot.';

/* ---- navigation ---- */
$$('nav button').forEach(b => b.onclick = () => {
  $$('nav button').forEach(x => x.classList.toggle('on', x === b));
  $$('.pane').forEach(p => p.classList.toggle('on', p.id === 'p-' + b.dataset.tab));
});
$$('.sub').forEach(g => g.querySelectorAll('button').forEach(b => b.addEventListener('click', () => {
  g.querySelectorAll('button').forEach(x => x.classList.toggle('sel', x === b));
  const pane = g.closest('.pane');
  pane.querySelectorAll('.subpane').forEach(p => p.hidden = p.id !== b.dataset.sub);
})));
function applyTheme() { document.documentElement.dataset.theme = theme; $('#thm').textContent = theme === 'amoled' ? 'AMOLED' : 'DARK'; }
$('#thm').onclick = () => { theme = theme === 'amoled' ? 'dark' : 'amoled'; store.set('theme', theme); applyTheme(); };

/* ---- status ---- */
async function loadStatus() {
  const r = await sectl('status');
  if (r.errno !== 0 && !r.stdout) { toast('Not connected to KernelSU'); return; }
  status = Core.parseKV(r.stdout);
  const m = (status.mode || '').toLowerCase(), b = $('#badge');
  b.textContent = m ? m.toUpperCase() : '?';
  b.className = 'badge ' + (m === 'enforcing' ? 'enf' : m === 'permissive' ? 'per' : 'off');
  $('#bEnf').classList.toggle('sel', m === 'enforcing');
  $('#bPer').classList.toggle('sel', m === 'permissive');
  $('#bootSel').value = status.bootmode || 'none';
  kvRows($('#info'), [['Kernel node', status.node], ['Policy version', status.policyvers], ['Shell context', status.context],
    ['Policy tool', status.tool], ['Device', status.device], ['Android', (status.android || '') + ' (SDK ' + (status.sdk || '?') + ')'],
    ['Kernel', status.kernel], ['Saved rules', status.rules], ['Denials saved at boot', status.boot_denials]]);
  const notes = $('#notes'); notes.textContent = '';
  if (status.safemode) {
    notes.append(el('div', 'err', 'Boot guard: ' + status.safemode + '. Fix the rules, enable the module in the manager, then clear this.'));
    const bx = el('div', 'btns'); bx.append(btn('Clear', async () => { await sectl('safemode-clear'); loadStatus(); })); notes.append(bx);
  }
  if (status.live_changed === '1') notes.append(el('div', 'warn', 'Live rules were applied since boot. Only a reboot removes them.'));
  if (status.tool === 'none') notes.append(el('div', 'err', 'No policy tool found (ksud, magiskpolicy or supolicy). Rules cannot be applied.'));
  if (status.recording) notes.append(el('div', 'muted', 'Denial recording is running since ' + new Date(+status.recording * 1000).toLocaleTimeString() + '.'));
  if (status.revert_at) notes.append(el('div', 'warn', 'Permissive test running, back to enforcing at ' + new Date(+status.revert_at * 1000).toLocaleTimeString() + '.'));
  if (status.guard_test === '1') notes.append(el('div', 'warn', 'Boot guard test armed: the next boot disables this module on purpose.'));
  if (status.trial) notes.append(el('div', 'muted', status.trial + ' trial rules will be applied once after the next boot.'));
  notes.hidden = !notes.childNodes.length;
  updateRec();
}
async function setMode(v) {
  if (v === 0 && !confirm('Permissive turns off SELinux enforcement for the whole system until reboot or until you switch back. Continue?')) return;
  const r = await sectl('setmode', String(v));
  await loadStatus();
  toast(/verified/.test(r.stdout) ? 'Done, read back from the kernel' : 'Not applied: ' + (r.stdout.split('\n')[0] || r.stderr));
}
$('#bEnf').onclick = () => setMode(1);
$('#bPer').onclick = () => setMode(0);
$('#bootSel').onchange = async e => {
  const v = e.target.value;
  if (v === 'permissive' && !confirm('Permissive after every boot. Banking apps and integrity checks can notice it. Continue?')) { e.target.value = status.bootmode || 'none'; return; }
  await sectl('bootmode', v); await loadStatus();
  toast(status.bootmode === v ? 'Saved' : 'Failed');
};

/* ---- rules ---- */
const ed = $('#ed'), rlog = $('#rlog');
let savedText = '';
async function loadRules() { const r = await sectl('rules-read'); ed.value = r.stdout; savedText = r.stdout; }
async function saveRules() {
  const d = Core.diffRules(savedText, ed.value);
  const risky = d.added.filter(x => Core.riskOf(x));
  if (risky.length && !confirm('New rules that need a second look:\n\n' + risky.join('\n') + '\n\nSave anyway?')) return false;
  const r = await sectl('rules-write', b64(ed.value));
  const ok = /^saved/m.test(r.stdout);
  if (ok) { savedText = ed.value; show(rlog, 'Saved. +' + d.added.length + ' / -' + d.removed.length + ' rules.\n' +
    d.added.map(x => '+ ' + x).concat(d.removed.map(x => '- ' + x)).join('\n')); }
  else show(rlog, r.stdout + r.stderr);
  toast(ok ? 'Saved' : 'Not saved');
  loadStatus();
  return ok;
}
async function applyRules() { const r = await sectl('rules-apply'); show(rlog, r.stdout + r.stderr + '\n' + LIVE); loadStatus(); }
$('#rLoad').onclick = loadRules;
$('#rSave').onclick = saveRules;
$('#rLive').onclick = applyRules;
$('#rBoth').onclick = async () => { if (await saveRules()) await applyRules(); };
$('#rCheck').onclick = async () => { const r = await sectl('rules-check', b64(ed.value)); show(rlog, r.stdout + r.stderr); };
$('#rExport').onclick = async () => { const r = await sectl('export'); toast(r.stdout.trim() || 'Export failed'); };

function addLine(rule) {
  const lines = ed.value.split('\n').map(x => x.trim());
  if (!lines.includes(rule)) ed.value = ed.value.replace(/\s*$/, '') + '\n' + rule + '\n';
}
async function applyLive(rule, out) {
  if (!okRisk(rule)) return;
  const x = await sectl('rule-apply', rule);
  const ok = /^ok/m.test(x.stdout);
  if (out) show(out, rule + '\n' + x.stdout + x.stderr);
  toast(ok ? LIVE : 'Failed: ' + (x.stdout + x.stderr).trim().split('\n')[0]);
  loadStatus();
}

/* builder */
Core.ACTIONS.forEach(a => $('#bAct').append(el('option', '', a)));
function built() {
  const r = Core.buildRule($('#bAct').value, $('#bSrc').value.trim(), $('#bTgt').value.trim(), $('#bCls').value.trim(), $('#bPrm').value);
  if (!r.rule) toast('Check the ' + r.why + ' field');
  return r.rule;
}
$('#bAdd').onclick = () => { const r = built(); if (r && okRisk(r)) { addLine(r); toast('Added to the editor. Save to keep it.'); } };
$('#bNow').onclick = () => { const r = built(); if (r) applyLive(r, rlog); };

/* templates */
Core.TEMPLATES.forEach(tp => {
  const row = el('div', 'row'); row.append(el('b', '', tp.name), el('small', '', tp.rule));
  const a = el('div', 'act'); a.append(btn('Add to editor', () => { addLine(tp.rule); toast('Added. Replace the placeholders, then save.'); }));
  row.append(a); $('#tplList').append(row);
});

/* backups */
async function loadBackups() {
  const r = await sectl('backups'), box = $('#bakList'); box.textContent = '';
  const rows = r.stdout.split('\n').filter(Boolean);
  if (!rows.length) { box.append(el('div', 'muted', 'No backups yet.')); return; }
  rows.forEach(l => {
    const [name, n] = l.split('|');
    const row = el('div', 'row'); row.append(el('b', '', name.replace('.rule', '')), el('small', '', n + ' rules'));
    const a = el('div', 'act');
    a.append(btn('Diff with current', async () => {
      const x = await sectl('backup-read', name), d = Core.diffRules(x.stdout, ed.value);
      show($('#bakOut'), 'Current editor compared with ' + name + '\n' + (d.added.map(y => '+ ' + y).concat(d.removed.map(y => '- ' + y)).join('\n') || 'no difference'));
    }));
    a.append(btn('Restore', async () => {
      if (!confirm('Replace the saved rules with ' + name + '? The current file is backed up first.')) return;
      const x = await sectl('backup-restore', name);
      if (/restored/.test(x.stdout)) { await loadRules(); loadBackups(); toast('Restored. Reboot or apply live to use it.'); } else toast(x.stdout.trim() || 'Failed');
    }));
    row.append(a); box.append(row);
  });
}
$$('[data-sub="r-bak"]').forEach(b => b.addEventListener('click', loadBackups));

/* ---- denials ---- */
let denials = [], owners = {}, denSrc = 'now';
$$('[data-group="den"] button').forEach(b => b.addEventListener('click', () => { denSrc = b.dataset.sub; updateRec(); loadDenials(); }));
function updateRec() {
  const box = $('#recBox'), on = !!status.recording;
  $('#dRec').textContent = on ? 'Stop recording' : 'Start recording';
  box.hidden = denSrc !== 'rec';
  box.textContent = on ? 'Recording since ' + new Date(+status.recording * 1000).toLocaleTimeString() + '. Do the thing that fails, then Load.'
    : 'Start recording, do the thing that fails, then Load to see only what happened in between.';
}
$('#dRec').onclick = async () => { await sectl(status.recording ? 'rec-stop' : 'rec-start'); await loadStatus(); };
async function loadDenials() {
  const since = denSrc === 'rec' ? +status.recording || 0 : 0;
  if (denSrc === 'rec' && !since) { denials = []; renderDen(); return; }
  const r = await sectl(denSrc === 'boot' ? 'boot-denials' : 'denials', '2000');
  denials = Core.parseAvc(r.stdout, since);
  renderDen();
}
$('#dLoad').onclick = loadDenials;
$('#dOwn').onclick = async () => {
  const pids = [...new Set(denials.flatMap(d => [...d.pids]))].slice(0, 300);
  if (!pids.length) return toast('Load denials first');
  const r = await sectl('owners', ...pids);
  owners = Core.parseOwners(r.stdout);
  toast(Object.keys(owners).length + ' of ' + pids.length + ' processes are still running and were matched');
  renderDen();
};
function whoOf(d) {
  const apps = new Set();
  d.pids.forEach(p => { const o = owners[p]; if (o) apps.add(o.pkg || o.cmd || ('uid ' + o.uid)); });
  return [...apps];
}
function renderDen() {
  const f = $('#dF').value.toLowerCase(), box = $('#dList'); box.textContent = '';
  const list = denials.filter(d => (d.rule + ' ' + [...d.comms].join(' ') + ' ' + whoOf(d).join(' ')).toLowerCase().includes(f));
  $('#dSum').textContent = list.length + ' groups, ' + list.reduce((a, d) => a + d.n, 0) + ' events';
  if (!list.length) { box.append(el('div', 'muted', 'Nothing found.')); return; }
  list.slice(0, 200).forEach(d => {
    const row = el('div', 'row');
    row.append(el('b', '', d.rule));
    const tags = el('div');
    tags.append(el('span', 'tag wn', d.n + 'x'));
    if (d.permissive) tags.append(el('span', 'tag', 'permissive=1'));
    const rk = Core.riskOf(d.rule); if (rk) tags.append(el('span', 'tag er', rk));
    row.append(tags);
    const who = whoOf(d);
    if (who.length) row.append(el('small', '', 'app: ' + who.join(', ')));
    if (d.comms.size) row.append(el('small', '', 'process: ' + [...d.comms].slice(0, 5).join(', ')));
    if (d.paths.size) row.append(el('small', '', 'object: ' + [...d.paths].slice(0, 5).join(', ')));
    const a = el('div', 'act');
    a.append(btn('Add allow', () => { if (okRisk(d.rule)) { addLine(d.rule); toast('Added to the editor. Save to keep it.'); } }));
    a.append(btn('Add dontaudit', () => { addLine(Core.ruleFor(d, 'dontaudit')); toast('Added. dontaudit hides the log line, it does not allow anything.'); }));
    a.append(btn('Apply live', () => applyLive(d.rule)));
    row.append(a); box.append(row);
  });
}
$('#dF').oninput = renderDen;

/* ---- modules ---- */
$('#mScan').onclick = async () => {
  const r = await sectl('modules-scan'), res = Core.parseModuleScan(r.stdout), out = $('#mOut'); out.textContent = '';
  const sum = el('div', 'card');
  sum.append(el('h3', '', res.mods.length + ' modules add rules'));
  if (res.permissive.length) sum.append(el('div', 'warn', res.permissive.length + ' permissive lines: ' + res.permissive.map(p => p.id + ' (' + p.rule + ')').join(', ')));
  if (res.shared.length) sum.append(el('div', 'muted', res.shared.length + ' rules are added by more than one module.'));
  out.append(sum);
  res.mods.forEach(m => {
    const c = el('div', 'card'); const h = el('h3', '', m.id + '  ');
    h.append(el('span', m.enabled ? 'tag ok' : 'tag', m.enabled ? 'enabled' : 'disabled'), el('span', 'tag', m.rules.length + ' rules'));
    c.append(h);
    m.rules.slice(0, 200).forEach(x => {
      const row = el('div', 'row', x);
      const rk = Core.riskOf(x); if (rk) row.append(el('span', 'tag er', rk));
      if (res.shared.some(s => s.rule === x)) row.append(el('span', 'tag', 'shared'));
      c.append(row);
    });
    out.append(c);
  });
};

/* ---- inspect ---- */
let procs = [], pkgs = [];
function renderPs() {
  const f = $('#psF').value.toLowerCase(), box = $('#psList'); box.textContent = '';
  Core.domains(procs).filter(d => (d.type + ' ' + d.names.join(' ')).toLowerCase().includes(f)).slice(0, 300).forEach(d => {
    const row = el('div', 'row'); row.append(el('b', '', d.type + '  (' + d.n + ')'), el('small', '', d.names.join(', ')));
    box.append(row);
  });
}
$('#psLoad').onclick = async () => { const r = await sectl('ps'); procs = Core.parsePs(r.stdout); renderPs(); };
$('#psF').oninput = renderPs;

function renderApps() {
  const f = $('#apF').value.toLowerCase(), box = $('#apList'); box.textContent = '';
  const running = new Map(); procs.forEach(p => { if (/^u\d+_/.test(p.user)) running.set(p.name.split(':')[0], p.type); });
  pkgs.filter(p => (p.pkg + ' ' + p.seinfo).toLowerCase().includes(f)).slice(0, 300).forEach(p => {
    const row = el('div', 'row'); row.append(el('b', '', p.pkg));
    row.append(el('small', '', 'uid ' + p.uid + '   seinfo ' + p.seinfo + (running.has(p.pkg) ? '   running as ' + running.get(p.pkg) : '')));
    box.append(row);
  });
}
$('#apLoad').onclick = async () => {
  const [a, b] = await Promise.all([sectl('packages'), sectl('ps')]);
  pkgs = Core.parsePackages(a.stdout).sort((x, y) => x.pkg < y.pkg ? -1 : 1); procs = Core.parsePs(b.stdout); renderApps();
};
$('#apF').oninput = renderApps;

const fOut = $('#fOut');
$('#fLs').onclick = async () => { const r = await sectl('ls', $('#fPath').value); show(fOut, r.stdout + r.stderr); };
$('#fRes').onclick = async () => { const r = await sectl('restorecon', $('#fPath').value); show(fOut, r.stdout + r.stderr); };
$('#fSet').onclick = async () => {
  const c = $('#fCtx').value.trim(), p = $('#fPath').value, rec = $('#fRec').checked;
  if (!/^u:object_r:[\w.]+:s0\S*$/.test(c)) return toast('A label looks like u:object_r:type:s0');
  if (!confirm('Set ' + c + ' on ' + p + (rec ? ' and everything below it' : '') + '?')) return;
  const r = await sectl('chcon', c, p, rec ? '1' : '0'); show(fOut, r.stdout + r.stderr);
};
$('#prLoad').onclick = async () => { const r = await sectl('props', $('#prF').value.trim() || 'selinux'); show($('#prOut'), r.stdout || 'Nothing found.'); };

/* ---- more ---- */
$('#kLoad').onclick = async () => {
  const k = Core.parseKV((await sectl('kernel')).stdout), box = $('#kOut');
  const rows = Object.keys(k).map(x => [x, k[x]]);
  kvRows(box, rows);
  const hints = [];
  if (k.enforce === '0') hints.push('Permissive is visible to anything that can read the enforce state or run getenforce.');
  if (k['prop.ro.boot.selinux']) hints.push('ro.boot.selinux=' + k['prop.ro.boot.selinux'] + ' is set by the bootloader and readable by every app.');
  if (k['prop.ro.debuggable'] === '1') hints.push('ro.debuggable=1 marks a debug build.');
  if (!hints.length) hints.push('No obvious SELinux signal for apps from these values.');
  hints.forEach(h => box.append(el('div', 'muted', h)));
};
$('#hLoad').onclick = async () => { const r = await sectl('history', '300'); show($('#hOut'), r.stdout || 'No changes recorded yet.'); };
$('#rpMake').onclick = async () => { const r = await sectl('report'); show($('#rpOut'), r.stdout + r.stderr); };
$('#rpCopy').onclick = () => {
  const txt = $('#rpOut').textContent; if (!txt) return toast('Build the report first');
  const done = () => toast('Copied');
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(txt).then(done, fallback); else fallback();
  function fallback() { const t = el('textarea'); t.value = txt; document.body.append(t); t.select(); try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed, select the text by hand'); } t.remove(); }
};

/* ---- safe tests ---- */
const tOut = $('#tOut');
$('#tPerm').onclick = async () => {
  const r = await sectl('permissive-for', '60'); await loadStatus();
  toast(/verified/.test(r.stdout) ? 'Permissive for 60 seconds, then enforcing again' : 'Not applied');
  setTimeout(loadStatus, 62000);
};
$('#tArm').onclick = async () => { if (!confirm('Arm the boot guard test? After the next reboot the module will be disabled on purpose.')) return; const r = await sectl('guard-arm'); await loadStatus(); toast(/armed/.test(r.stdout) ? 'Armed. Reboot to test.' : 'Failed'); };
$('#tDisarm').onclick = async () => { await sectl('guard-disarm'); await loadStatus(); toast('Disarmed'); };
$('#tFile').onclick = async () => {
  const r = await sectl('test-file'), k = Core.parseKV(r.stdout);
  show(tOut, r.stdout + r.stderr);
  if (k.path) { $('#fPath').value = k.path; toast('Created. Its path is in Inspect > Files.'); }
};
$('#tLog').onclick = async () => { const r = await sectl('trial-log'); show(tOut, r.stdout || 'No trial has run yet.'); };
$('#tClear').onclick = async () => { await sectl('trial-clear'); await loadStatus(); toast('Pending trial cancelled'); };
$('#rTrial').onclick = async () => {
  const lines = Core.ruleLines(ed.value);
  if (!lines.length) return toast('The editor has no rules');
  const r = await sectl('trial-write', b64(ed.value)); await loadStatus();
  toast(/trial=/.test(r.stdout) ? lines.length + ' rules will be tried once after the next boot' : 'Failed');
};

applyTheme(); loadStatus(); loadRules();
