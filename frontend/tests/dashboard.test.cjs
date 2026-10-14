const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '../dashboard.html'), 'utf8');
const helpers = html.slice(html.indexOf('async function resolveDashboardScope'), html.indexOf('let dashboardLoading'));
const context = vm.createContext({ URLSearchParams, fetch: () => { throw new Error('Unexpected fetch'); } });
vm.runInContext(helpers, context);
const response = (body, ok = true) => ({ ok, json: async () => body });

test('lab URL resolves its own scan IDs rather than historical scans or stale explicit IDs', async () => {
    const calls = [];
    const filter = await context.resolveDashboardScope('?labId=lab-k8s&scanIds=1,2', async url => {
        calls.push(url);
        return response({ lab: { scan_ids: [22] } });
    });
    assert.equal(filter, '?scan_ids=22');
    assert.deepEqual(calls, ['/api/sandbox-labs/lab-k8s']);
});

test('pending and inaccessible labs never fall back to all scans', async () => {
    await assert.rejects(context.resolveDashboardScope('?labId=pending', async () => response({ lab: { scan_ids: [] } })), /no completed scan/);
    await assert.rejects(context.resolveDashboardScope('?labId=other-tenant', async () => response({ detail: 'Sandbox lab not found' }, false)), /not found/);
});

test('unscoped dashboard ignores previous session selection; scan links remain supported', async () => {
    assert.equal(await context.resolveDashboardScope('', async url => {
        assert.equal(url, '/api/dashboard-scope');
        return response({ status: 'success', scan_ids: [22] });
    }), '?scan_ids=22');
    assert.equal(await context.resolveDashboardScope('?scope=all', async () => response({ status: 'success', scan_ids: [22] })), '?scan_ids=22');
    assert.equal(await context.resolveDashboardScope('?scanIds=21,22'), '?scan_ids=21%2C22');
    assert.equal(await context.resolveDashboardScope('?scan_id=22'), '?scan_ids=22');
    await assert.rejects(context.resolveDashboardScope('?scanIds=invalid'), /Invalid scan/);
    assert.equal(html.includes("sessionStorage.getItem('last_scan_ids')"), false);
});

test('no completed scans and scope failures never expose historical totals', async () => {
    assert.equal(await context.resolveDashboardScope('', async () => response({ status: 'success', scan_ids: [] })), '?scan_ids=0');
    await assert.rejects(context.resolveDashboardScope('', async () => response({ status: 'error' }, false)), /Could not load the latest/);
    await assert.rejects(context.resolveDashboardScope('?scanIds='), /Invalid scan/);
});

test('severity chart counts only the selected scan findings without requesting history', () => {
    let config;
    const chartContext = vm.createContext({
        document: { getElementById: () => ({}) },
        Chart: function (_canvas, options) { config = options; },
    });
    vm.runInContext('let severityChart;\n' + html.slice(html.indexOf('function loadSeverityChart'), html.indexOf('async function loadCloudChart')), chartContext);
    chartContext.loadSeverityChart([{severity:'CRITICAL'}, {severity:'HIGH'}, {severity:'high'}, {severity:'INFO'}]);
    assert.deepEqual(Array.from(config.data.datasets[0].data), [1, 2, 0, 0, 1]);
});

test('all pages are retrieved with the same run scope, including more than 20 findings', async () => {
    const calls = [];
    const rows = Array.from({ length: 247 }, (_, id) => ({ id, cloud: 'kubernetes' }));
    const result = await context.fetchAllDashboardFindings('?scan_ids=22', async url => {
        calls.push(url);
        const offset = Number(new URL(url, 'https://test.invalid').searchParams.get('offset'));
        return response({ status: 'success', data: rows.slice(offset, offset + 200), has_more: offset + 200 < rows.length });
    });
    assert.equal(result.length, 247);
    assert.equal(new Set(result.map(row => row.id)).size, 247);
    assert.deepEqual(calls, ['/api/latest-findings?scan_ids=22&limit=200&offset=0', '/api/latest-findings?scan_ids=22&limit=200&offset=200']);
});

test('failed or empty intermediate pages cannot silently truncate findings', async () => {
    await assert.rejects(context.fetchAllDashboardFindings('', async () => response({ status: 'error', message: 'Database unavailable' })), /Database unavailable/);
    await assert.rejects(context.fetchAllDashboardFindings('', async () => response({ status: 'success', data: [], has_more: true })), /Incomplete/);
});
