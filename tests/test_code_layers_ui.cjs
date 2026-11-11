// Validate the existing template script and render layer evidence without a browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../web/templates/scan.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
scripts.forEach(script => new vm.Script(script));
const script = scripts.find(s => s.includes('function renderCodeLayers'));
const helpers = script.slice(script.indexOf('const SEV ='), script.indexOf('function renderDeepSummary'));
const escape = script.match(/    function escapeHtml\(str\) \{[^\n]+/)[0];
const context = vm.createContext({window: {}});
vm.runInContext(helpers + '\n' + escape, context);
const finding = {
    class_name: 'Lorg/example/<img src=x onerror=alert(1)>;', method_name: 'send',
    descriptor: '()V', origin: 'application', severity: 'medium',
    title: 'API nhạy cảm và API mạng cùng một hàm',
    sources: [{class_name: 'Location', method_name: 'getLatitude', descriptor: '()D', offset: 12}],
    sinks: [{class_name: 'HttpURLConnection', method_name: 'getOutputStream', descriptor: '()V', offset: 24}],
};
const layer = {finding_count: 1, methods_scanned: 2, status: 'completed',
    counts_by_origin: {application: 1}, findings: [finding], limitations: ['Chưa xác nhận luồng dữ liệu']};
const output = context.renderCodeLayers({deep: {layer2: layer, layer3: layer}});
assert.ok(output.includes('Tầng 2'));
assert.ok(output.includes('Tầng 3'));
assert.ok(output.includes('getLatitude'));
assert.ok(output.includes('getOutputStream'));
assert.ok(output.includes('&lt;img'));
assert.ok(!output.includes('<img'));
assert.ok(context.renderCodeLayers({deep_error: '<b>failure</b>'}).includes('&lt;b&gt;failure'));
assert.equal(context.renderCodeLayers({}), '');
assert.equal(context.escapeHtml('"\'&<>'), '&quot;&#39;&amp;&lt;&gt;');
const unavailable = {...layer, status: 'unavailable', available: false, score: null, findings: [], finding_count: 0,
    issues: [{component: 'yara', reason: '<script>bad</script>'}]};
const missing = context.renderCodeLayers({deep: {layer2: unavailable, layer3: unavailable}});
assert.ok(missing.includes('Không khả dụng'));
assert.ok(missing.includes('Chưa đủ dữ liệu'));
assert.ok(!missing.includes('<script>bad'));
const fileFinding = {rule_id: 'yara_test', file_path: 'assets/<img>.dex', title: 'YARA', severity: 'info',
    matches: [{identifier: '$dex', offset: 3, value: '<img>'}], origin: 'unknown'};
const artifactHtml = context.renderCodeLayers({deep: {layer2: {...layer, findings: [fileFinding]}, layer3: layer}});
assert.ok(artifactHtml.includes('assets/&lt;img&gt;.dex'));
assert.ok(artifactHtml.includes('$dex'));
assert.ok(!artifactHtml.includes('undefined-&gt;'));
assert.ok(artifactHtml.includes('downloadCodeLayers'));
console.log('PASS: template JavaScript syntax, layer rendering, evidence and HTML escaping');
const reversed = context.renderCodeLayers({deep: {layer2: {...layer, findings: [{...finding,
    string_proof: {original: '<img src=x>', decoded: 'getDeviceId', literal_offset: 56,
                   use_api: 'Class.getMethod', use_offset: 132}}]}, layer3: layer}});
assert.ok(reversed.includes('getDeviceId'));
assert.ok(reversed.includes('&lt;img src=x&gt;'));
assert.ok(!reversed.includes('<img src=x>'));
