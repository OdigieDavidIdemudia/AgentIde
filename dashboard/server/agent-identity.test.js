import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveAgentIdentity, isUuid } from './agent-identity.js';

/**
 * Regression tests for the bug that made assessments never run.
 *
 * POST /api/assessments used to overwrite `agent_id` with the agents-table
 * UUID and then pass that UUID to registry.sendToAgent(). The registry keys
 * live sockets by hostname, so the lookup missed, the command was silently
 * dropped, and the persisted assessment sat at status 'running' forever with
 * zero results. These tests pin the two identifiers apart.
 */

const HOST = 'DESKTOP-L07M1SS';
const UUID = 'c46339e2-243f-460a-897b-8abb3c5d97eb';
const ROW = { id: UUID, hostname: HOST };

test('isUuid distinguishes a DB id from a hostname', () => {
  assert.equal(isUuid(UUID), true);
  assert.equal(isUuid(HOST), false);
  // Guard against a hostname that merely looks hex-ish.
  assert.equal(isUuid('deadbeefdeadbeefdeadbeefdeadbeef'), false);
});

test('a hostname resolves to both the DB id and the socket id', async () => {
  const identity = await resolveAgentIdentity(HOST, async () => ROW);
  assert.equal(identity.dbId, UUID);
  assert.equal(identity.socketId, HOST);
});

test('a UUID resolves to the hostname the registry is keyed on', async () => {
  // The UUID is what the UI actually sends (it holds agent.id from
  // /api/agents). Returning the UUID as socketId here is the regression.
  const identity = await resolveAgentIdentity(UUID, async () => ROW);
  assert.equal(identity.dbId, UUID);
  assert.equal(identity.socketId, HOST);
  assert.notEqual(identity.socketId, identity.dbId);
});

test('the socket id is always the hostname, never the UUID', async () => {
  for (const input of [HOST, UUID]) {
    const identity = await resolveAgentIdentity(input, async () => ROW);
    assert.equal(identity.socketId, HOST, `input ${input} produced a non-hostname socket id`);
  }
});

test('lookup is keyed by id for a UUID and by hostname otherwise', async () => {
  const seen = [];
  const spy = async (value, byUuid) => { seen.push({ value, byUuid }); return ROW; };

  await resolveAgentIdentity(UUID, spy);
  await resolveAgentIdentity(HOST, spy);

  assert.deepEqual(seen, [
    { value: UUID, byUuid: true },
    { value: HOST, byUuid: false },
  ]);
});

test('an unknown agent resolves to null so callers can 404', async () => {
  assert.equal(await resolveAgentIdentity('NOPE', async () => undefined), null);
});