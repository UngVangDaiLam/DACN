// Validate the existing template script and render layer evidence without a browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../web/templates/scan.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script); // Check the complete inline script, including upload/manager paths.
const helpers = script.slice(script.indexOf('const SEV ='), script.indexOf('function renderDeepSummary'));
const escape = script.match(/    function escapeHtml\(str\) \{[^\n]+/)[0];
const context = vm.createContext({});
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
console.log('PASS: template JavaScript syntax, layer rendering, evidence and HTML escaping');
