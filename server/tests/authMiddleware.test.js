import test from 'node:test';
import assert from 'node:assert/strict';

import { attachUserContext, requireRole } from '../middlewares/authMiddleware.js';

function createResRecorder() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

test('attachUserContext uses header values when provided', () => {
  const req = {
    header(name) {
      if (name === 'X-User-Role') return 'editor';
      if (name === 'X-User-Name') return 'yosef';
      return undefined;
    },
  };

  attachUserContext(req, {}, () => {});

  assert.deepEqual(req.user, { role: 'editor', name: 'yosef' });
});

test('requireRole rejects insufficient permissions', () => {
  const req = { user: { role: 'viewer' } };
  const res = createResRecorder();
  let nextCalled = false;

  requireRole('editor')(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.match(res.body.message, /requires editor permissions/i);
});

test('requireRole allows elevated permissions', () => {
  const req = { user: { role: 'admin' } };
  const res = createResRecorder();
  let nextCalled = false;

  requireRole('editor')(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(res.body, null);
});
