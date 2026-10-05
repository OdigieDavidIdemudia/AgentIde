import { test } from 'node:test';
import assert from 'node:assert/strict';

// auth.js reads process.env at call time, so tests can tweak env freely.
const auth = await import('./auth.js');

test('session tokens are issued, validated, and revoked', () => {
  const token = auth.issueToken();
  assert.equal(auth.isValidSessionToken(token), true);
  assert.equal(auth.isValidSessionToken('not-a-real-token'), false);
  auth.revokeToken(token);
  assert.equal(auth.isValidSessionToken(token), false);
  assert.equal(auth.isValidSessionToken(null), false);
  assert.equal(auth.isValidSessionToken(''), false);
});

test('agent token validation fails closed when AGENT_TOKEN is unset', () => {
  delete process.env.AGENT_TOKEN;
  assert.equal(auth.isAgentTokenValid('anything'), false);
  process.env.AGENT_TOKEN = 'shared-secret';
  assert.equal(auth.isAgentTokenValid('shared-secret'), true);
  assert.equal(auth.isAgentTokenValid('wrong'), false);
  delete process.env.AGENT_TOKEN;
});

test('admin credentials come from env with dev defaults', () => {
  delete process.env.ADMIN_EMAIL;
  delete process.env.ADMIN_PASSWORD;
  assert.equal(auth.checkAdminCredentials('admin@agentide.local', 'agentide-dev'), true);
  assert.equal(auth.checkAdminCredentials('admin@agentide.local', 'nope'), false);
  process.env.ADMIN_PASSWORD = 'strong-password';
  assert.equal(auth.checkAdminCredentials('admin@agentide.local', 'strong-password'), true);
  assert.equal(auth.checkAdminCredentials('admin@agentide.local', 'agentide-dev'), false);
  delete process.env.ADMIN_PASSWORD;
});

test('login failures lock out after 5 attempts', () => {
  const ip = '10.0.0.99';
  for (let i = 0; i < 5; i++) {
    assert.equal(auth.isLoginAllowed(ip), true);
    auth.registerLoginFailure(ip);
  }
  assert.equal(auth.isLoginAllowed(ip), false, 'should be locked out after 5 failures');
});

test('per-agent tokens are UUIDs', () => {
  const token = auth.issueAgentToken();
  assert.match(token, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
});
