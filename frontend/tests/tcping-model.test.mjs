import { test } from 'node:test';
import assert from 'node:assert/strict';
import { filterTargets, provinceSummary } from '../src/components/tcping/model.ts';

const target = (province, carrier, value, status = 'ok') => ({
  id: province + carrier, province, carrier,
  result: status === 'pending' ? null : { median_ms: value, success: value === null ? 0 : 1, status },
});
const nodes = [target('北京','telecom',20),target('北京','unicom',180),target('北京','mobile',40),
  target('广东','unicom',240),target('广东','telecom',null,'timeout'),target('台湾','custom',36),
  target('上海','mobile',null,'pending')];
const defaults = { province:'', carrier:'', status:'' };

test('default shows national/all-carrier results and a province median', () => {
  assert.equal(filterTargets(nodes,defaults).length,7);
  assert.equal(provinceSummary(nodes,'北京',defaults).value,40);
  assert.equal(provinceSummary(nodes,'台湾',defaults).value,36);
});
test('province selection removes other province colors without losing click targets', () => {
  const filters = { ...defaults, province:'北京' };
  assert.equal(filterTargets(nodes,filters).length,3);
  assert.equal(provinceSummary(nodes,'北京',filters).value,40);
  assert.equal(provinceSummary(nodes,'广东',filters).value,null);
  assert.equal(provinceSummary(nodes,'广东',filters).filteredOut,true);
});
test('carrier dropdown changes both table and map aggregation', () => {
  const filters = { ...defaults, carrier:'unicom' };
  assert.equal(filterTargets(nodes,filters).length,2);
  assert.equal(provinceSummary(nodes,'北京',filters).value,180);
  assert.equal(provinceSummary(nodes,'广东',filters).value,240);
  assert.equal(provinceSummary(nodes,'台湾',filters).filteredOut,true);
});
test('combined province/carrier/status filters stay identical across views', () => {
  for (const province of ['', '北京', '广东', '台湾']) {
    for (const carrier of ['', 'telecom', 'unicom', 'mobile', 'custom']) {
      for (const status of ['', 'ok', 'failed', 'pending']) {
        const filters = { province, carrier, status };
        for (const p of ['北京','广东','台湾','上海']) {
          assert.deepEqual(provinceSummary(nodes,p,filters).rows,filterTargets(nodes,filters).filter(n=>n.province===p));
        }
      }
    }
  }
});
test('pending, failure and zero-millisecond success remain distinct', () => {
  assert.equal(provinceSummary(nodes,'上海',defaults).completed,0);
  assert.equal(provinceSummary(nodes,'广东',{...defaults,carrier:'telecom'}).completed,1);
  assert.equal(provinceSummary([target('北京','mobile',0)],'北京',defaults).value,0);
});
