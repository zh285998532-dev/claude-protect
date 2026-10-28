'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { presentation } = require('../extension/status');

test('a healthy deployment never marks a normal VS Code window isolated', () => {
  const view = presentation({ kernel_ok: true, session_isolated: false }, { platform: 'linux' });
  assert.match(view.text, /此窗口未隔离/);
});
test('kernel failure overrides a stale session marker', () => {
  const view = presentation({ kernel_ok: false, session_isolated: true }, { platform: 'linux' });
  assert.match(view.text, /未就绪/);
});
test('remote and macOS sessions cannot display protection success', () => {
  const result = { kernel_ok: true, session_isolated: true };
  assert.match(presentation(result, { platform: 'darwin' }).text, /不支持/);
  assert.match(presentation(result, { platform: 'linux', remote: true }).text, /不支持/);
});
test('verified isolation is distinct from proxy availability and account safety', () => {
  const view = presentation({ kernel_ok: true, session_isolated: true, upstream_managed: true }, { platform: 'linux' });
  assert.match(view.text, /双层出站已核对/);
  assert.match(view.detail, /代理可达性需单独测试/);
  assert.match(view.detail, /不代表账号安全/);
});
test('external and test-only upstreams cannot display production policy success', () => {
  assert.match(presentation({ kernel_ok: true, session_isolated: true, upstream_managed: false }, { platform: 'linux' }).text, /上游未受控/);
  assert.match(presentation({ kernel_ok: true, session_isolated: true, upstream_managed: true, upstream_test_only: true }, { platform: 'linux' }).text, /测试上游/);
});
