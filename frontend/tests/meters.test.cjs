const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../cloudguard-ui.js'), 'utf8').split('/* End scan meters. */')[0];
const context = { window: {} };
vm.runInNewContext(source, context);
const { model, latestSnapshot } = context.window.CloudGuardMeters;
const summary = {total_resources:93,total_findings:47,public_resources:3,security_score:49.46};
const findings = Array.from({length:47},(_,i)=>({severity:i<4?'CRITICAL':i<6?'high':'MEDIUM'}));
const response = data => ({ok:true,json:async()=>data});

test('scan meters calculate posture, priority share and exposure from the same snapshot',()=>{
    const result=model(summary,findings);
    assert.deepEqual(Array.from(result,m=>m.value),[49,13,3]);
    assert.equal(result[1].direction,'Lower is better');
    assert.equal(result[1].detail,'6 of 47 findings need priority review');
});

test('a clean scanned environment has measured zeros, but an empty scan has no score',()=>{
    assert.deepEqual(Array.from(model({...summary,total_findings:0,public_resources:0,security_score:100},[]),m=>m.value),[100,0,0]);
    assert.deepEqual(Array.from(model({total_resources:0,total_findings:0,public_resources:0,security_score:100},[]),m=>m.value),[null,null,null]);
});

test('incomplete findings and invalid exposure counts cannot appear as healthy meters',()=>{
    assert.throws(()=>model(summary,findings.slice(0,20)),/Incomplete/);
    assert.throws(()=>model({...summary,public_resources:100},findings),/Incomplete/);
});

test('home meters pin every page to the last completed scan, without truncating results',async()=>{
    const calls=[];
    const rows=Array.from({length:247},()=>({severity:'LOW'}));
    const result=await latestSnapshot(async url=>{
        calls.push(url);
        if(url==='/api/dashboard-scope')return response({status:'success',scan_ids:[28]});
        if(url.startsWith('/posture/'))return response({...summary,total_findings:247});
        const offset=Number(new URL(url,'https://test.invalid').searchParams.get('offset'));
        return response({status:'success',data:rows.slice(offset,offset+200),has_more:offset+200<rows.length});
    });
    assert.equal(result.findings.length,247);
    assert.deepEqual(calls,['/api/dashboard-scope','/posture/dashboard?scan_ids=28','/api/latest-findings?scan_ids=28&limit=200&offset=0','/api/latest-findings?scan_ids=28&limit=200&offset=200']);
});

test('no completed scan never falls back to historical endpoints',async()=>{
    const calls=[];
    assert.equal(await latestSnapshot(async url=>{calls.push(url);return response({status:'success',scan_ids:[]});}),null);
    assert.deepEqual(calls,['/api/dashboard-scope']);
});

test('failed and empty intermediate pages fail explicitly',async()=>{
    await assert.rejects(latestSnapshot(async url=>url==='/api/dashboard-scope'?response({status:'success',scan_ids:[28]}):url.startsWith('/posture/')?response(summary):response({status:'success',data:[],has_more:true})),/complete scan/);
    await assert.rejects(latestSnapshot(async()=>response({status:'error'})),/latest scan/);
});
