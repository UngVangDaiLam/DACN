// Kiem tra khung "Tang 5 - Trong tai" tren scan.html ma khong can trinh duyet.
// Chay:  node tests\test_arbiter_ui.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../web/templates/scan.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const script = scripts.find(s => s.includes('function renderArbiterSummary'));
assert.ok(script, 'khong tim thay renderArbiterSummary');
const helpers = script.slice(script.indexOf('const SEV ='), script.indexOf('function renderDeepSummary'));
const escape = script.match(/    function escapeHtml\(str\) \{[^\n]+/)[0];
const context = vm.createContext({window: {}});
vm.runInContext(helpers + '\n' + escape, context);

const fam = (key, extra) => ({key, label: 'Họ ' + key, available: true, partial: false, score: 0.7,
    raw_score: 0.7, threshold: 0.6, strong_threshold: 0.85, over: true, strength: 'weak',
    evidence: [], notes: [], ...extra});
const arbiter = {
    method: 'family_cross_confirmation', level: 'danger', verdict: 'NGUY HIỂM — <b>x</b>',
    action: 'Đề nghị gỡ <script>1</script>',
    families: [fam('A', {score: 0.6, raw_score: 0.7}),
               fam('B', {partial: true, evidence: [{capability: 'dynamic_code_loading<img>'}]}),
               {key: 'C', label: 'Họ C', available: false, notes: ['Tầng 4 chưa chạy'], evidence: []}],
    families_over: ['A', 'B'], families_absent: ['C'], reasons: ['Các họ A, B cùng vượt ngưỡng <i>'],
    thresholds_calibrated: true, thresholds_meta: {calibrated_families: ['A', 'B'], n_benign: 300, benign_source: 'F-Droid'},
    context_applied: true, context_delta: -0.1,
    context_items: [{key: 'known_signer', label: 'Chữ ký đã biết', delta: -0.1}], context_unknown: ['long_usage'],
};
const data = {arbiter};
const out = context.renderArbiterSummary(data);
assert.ok(out.includes('Tầng 5 — Xác nhận chéo theo họ bằng chứng'));
assert.ok(out.includes('NGUY HIỂM'));
assert.ok(out.includes('2/3 HỌ BẰNG CHỨNG'));
assert.ok(out.includes('Vắng mặt'));
assert.ok(out.includes('cận dưới'));
assert.ok(out.includes('gốc 0.70'));
assert.ok(out.includes('Chữ ký đã biết -0.10'));
assert.ok(out.includes('đã hiệu chỉnh trên 300'));
assert.ok(!out.includes('undefined') && !out.includes('NaN'));
for (const bad of ['<b>x</b>', '<script>1', '<img>', '<i>']) assert.ok(!out.includes(bad), bad);

// Chua hieu chinh + khong co ngu canh
const plain = context.renderArbiterSummary({arbiter: {...arbiter, thresholds_calibrated: false,
    context_applied: false, context_items: [], level: 'unknown', families_over: []}});
assert.ok(plain.includes('chưa hiệu chỉnh'));
assert.ok(plain.includes('CHƯA ĐỦ BẰNG CHỨNG'));
assert.ok(!plain.includes('Ngữ cảnh cài đặt'));

// Bao cao khong co khoi arbiter (ban cu) -> khong hien gi; khoi loi -> canh bao da escape
assert.equal(context.renderArbiterSummary({}), '');
const err = context.renderArbiterSummary({arbiter: {error: '<b>hong</b>'}});
assert.ok(err.includes('&lt;b&gt;hong') && !err.includes('<b>hong'));
console.log('PASS: khung xac nhan cheo theo ho (hien thi, escape HTML, bao cao cu)');
