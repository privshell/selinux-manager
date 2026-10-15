const assert = require('assert');
const C = require('../webroot/core.js');
let n = 0;
const ok = (name, f) => { f(); n++; console.log('ok -', name); };

const A1 = 'W fooapp : type=1400 audit(1700000000.100:42): avc: denied { read } for pid=900 comm="fooapp" name="cpu" scontext=u:r:untrusted_app:s0:c512,c768 tcontext=u:object_r:sysfs:s0 tclass=file permissive=0';
const A1d = '[ 12.3] audit: type=1400 audit(1700000000.100:42): avc: denied { read } for pid=900 comm="fooapp" name="cpu" scontext=u:r:untrusted_app:s0:c512,c768 tcontext=u:object_r:sysfs:s0 tclass=file permissive=0';
const A2 = 'audit(1700000100.000:43): avc: denied { open } for pid=901 comm="fooapp" path="/sys/x" scontext=u:r:untrusted_app:s0 tcontext=u:object_r:sysfs:s0 tclass=file permissive=1';
const A3 = 'audit(1700000200.000:44): avc: denied { search } for pid=1 comm="init" name="x" scontext=u:r:init:s0 tcontext=u:object_r:vendor_file:s0 tclass=dir permissive=0';

ok('one event in logcat and dmesg counts once', () => {
  const g = C.parseAvc([A1, A1d].join('\n'));
  assert.strictEqual(g.length, 1); assert.strictEqual(g[0].n, 1);
});
ok('groups and merges permissions, keeps pids and comm', () => {
  const g = C.parseAvc([A1, A2, A3].join('\n'));
  assert.strictEqual(g.length, 2);
  assert.strictEqual(g[0].rule, 'allow untrusted_app sysfs file { open read }');
  assert.strictEqual(g[0].permissive, true);
  assert.deepStrictEqual([...g[0].pids].sort(), ['900', '901']);
  assert.strictEqual(g[1].rule, 'allow init vendor_file dir search');
});
ok('since drops older events (recording)', () => {
  const g = C.parseAvc([A1, A2, A3].join('\n'), 1700000150);
  assert.strictEqual(g.length, 1); assert.strictEqual(g[0].s, 'init');
});
ok('dontaudit variant of a group', () => {
  const g = C.parseAvc(A3)[0];
  assert.strictEqual(C.ruleFor(g, 'dontaudit'), 'dontaudit init vendor_file dir search');
});
ok('builder', () => {
  assert.strictEqual(C.buildRule('allow', 'a', 'b', 'file', 'read open').rule, 'allow a b file { read open }');
  assert.strictEqual(C.buildRule('permissive', 'a').rule, 'permissive a');
  assert.strictEqual(C.buildRule('allow', 'a;rm', 'b', 'file', 'read').rule, null);
  assert.strictEqual(C.buildRule('allow', 'a', 'b', 'file', '').why, 'permissions');
});
ok('risk hints', () => {
  assert.strictEqual(C.riskOf('allow * b file read'), 'wide');
  assert.strictEqual(C.riskOf('permissive init'), 'permissive');
  assert.strictEqual(C.riskOf('allow untrusted_app sysfs file read'), 'app');
  assert.strictEqual(C.riskOf('allow init vendor_file dir search'), null);
});
ok('diff', () => {
  const d = C.diffRules('# c\nallow a b c d\nallow x y z w', 'allow a b c d\nallow n m o p');
  assert.deepStrictEqual(d, { added: ['allow n m o p'], removed: ['allow x y z w'] });
});
ok('ps and domains', () => {
  const ps = 'LABEL USER PID PPID VSZ RSS WCHAN ADDR S NAME\n' +
    'u:r:init:s0 root 1 0 1 1 0 0 S init\n' +
    'u:r:untrusted_app:s0:c1 u0_a1 900 1 1 1 0 0 S com.foo\n' +
    'u:r:untrusted_app:s0:c3 u0_a2 901 1 1 1 0 0 S com.bar\n';
  const d = C.domains(C.parsePs(ps));
  assert.strictEqual(d[0].type, 'untrusted_app'); assert.strictEqual(d[0].n, 2);
  assert.deepStrictEqual(d[0].names, ['com.foo', 'com.bar']);
});
ok('module scan finds shared and permissive rules', () => {
  const r = C.parseModuleScan('### a enabled\nallow x y file read\npermissive foo\n### b disabled\n# note\nallow x y file read\n');
  assert.strictEqual(r.mods.length, 2); assert.strictEqual(r.mods[1].enabled, false);
  assert.deepStrictEqual(r.shared, [{ rule: 'allow x y file read', ids: ['a', 'b'] }]);
  assert.deepStrictEqual(r.permissive, [{ id: 'a', rule: 'permissive foo' }]);
});
ok('owners and packages', () => {
  assert.deepStrictEqual(C.parseOwners('900|10123|com.foo|com.foo:bg\n|x|y|z'), { 900: { uid: '10123', pkg: 'com.foo', cmd: 'com.foo:bg' } });
  assert.deepStrictEqual(C.parsePackages('com.foo 10123 0 /data/user/0/com.foo default:targetSdkVersion=34 3003'),
    [{ pkg: 'com.foo', uid: '10123', seinfo: 'default:targetSdkVersion=34' }]);
});
ok('key=value', () => {
  assert.deepStrictEqual(C.parseKV('a=1\nb = x=y\nnoeq'), { a: '1', b: 'x=y' });
});
ok('pid from the logcat header when the avc line has none', () => {
  const L = '10-12 06:00:01.123  1834  2001 W SchedBoostServi: type=1400 audit(0.0:77): avc: denied { read } for name="233101" dev="dm-50" ino=9 scontext=u:r:system_server:s0 tcontext=u:object_r:system_data_root_file:s0 tclass=file permissive=1';
  const g = C.parseAvc(L)[0];
  assert.deepStrictEqual([...g.pids], ['1834']);
});
ok('path is preferred over name for the object', () => {
  const L = 'audit(1.0:78): avc: denied { read } for pid=5 name="x" path="/data/a/x" scontext=u:r:a:s0 tcontext=u:object_r:b:s0 tclass=file permissive=0';
  assert.deepStrictEqual([...C.parseAvc(L)[0].paths], ['/data/a/x']);
});
ok('recording uses the logcat header time when audit time is 0.0', () => {
  const y = new Date().getFullYear();
  const t0 = new Date(y, 9, 12, 6, 0, 0).getTime() / 1000;
  const old = '10-12 05:59:00.000  10  10 W a: type=1400 audit(0.0:90): avc: denied { read } for name="x" scontext=u:r:a:s0 tcontext=u:object_r:b:s0 tclass=file permissive=0';
  const neu = '10-12 06:01:00.000  11  11 W c: type=1400 audit(0.0:91): avc: denied { read } for name="y" scontext=u:r:c:s0 tcontext=u:object_r:d:s0 tclass=file permissive=0';
  const g = C.parseAvc(old + '\n' + neu, t0);
  assert.strictEqual(g.length, 1); assert.strictEqual(g[0].s, 'c');
});
console.log(n + ' tests passed');
