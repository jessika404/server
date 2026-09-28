import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  decodeStreamCursor,
  encodeStreamCursor,
  getStreamMaxMs,
  MAX_REPLAY_MS,
  resolveStreamStart,
} from '../../src/utils/sseCursor';

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8');
const original = process.env.NOTIFICATION_STREAM_MAX_SECONDS;
afterEach(() => {
  if (original === undefined) delete process.env.NOTIFICATION_STREAM_MAX_SECONDS;
  else process.env.NOTIFICATION_STREAM_MAX_SECONDS = original;
});

const NOW = new Date('2026-09-28T10:00:00.000Z');
const cursor = {
  notifications: { createdAt: '2026-09-28T09:59:40.000Z', id: '11111111-1111-4111-8111-111111111111' },
  stock: { createdAt: '2026-09-28T09:59:30.000Z', id: '22222222-2222-4222-8222-222222222222' },
};

describe('Notification stream resume (Last-Event-ID)', () => {
  it('round-trips both feed cursors through the event id', () => {
    const id = encodeStreamCursor(cursor);
    assert.match(id, /^[A-Za-z0-9_-]+$/, 'safe for an SSE id line and a header');
    assert.deepEqual(decodeStreamCursor(id), cursor);
  });

  it('resumes from a recent id and reports resumed', () => {
    const start = resolveStreamStart(encodeStreamCursor(cursor), NOW);
    assert.deepEqual(start, { cursor, resumed: true });
  });

  it('starts from now, not resumed, without a usable id', () => {
    for (const value of [undefined, '', 'garbage', Buffer.from('[1,2]').toString('base64url'), 'x'.repeat(600)]) {
      const start = resolveStreamStart(value, NOW);
      assert.equal(start.resumed, false);
      assert.equal(start.cursor.notifications.createdAt, NOW.toISOString());
      assert.equal(start.cursor.notifications.id, '');
    }
    const injected = Buffer.from(JSON.stringify([cursor.notifications.createdAt, "x' or 1=1", cursor.stock.createdAt, ''])).toString('base64url');
    assert.equal(decodeStreamCursor(injected), null);
  });

  it('bounds replay to the last 10 minutes and ignores future cursors', () => {
    const old = encodeStreamCursor({ ...cursor, notifications: { createdAt: '2026-09-28T08:00:00.000Z', id: cursor.notifications.id } });
    const start = resolveStreamStart(old, NOW);
    assert.equal(start.resumed, false, 'the client must refetch its lists');
    assert.equal(start.cursor.notifications.createdAt, new Date(NOW.getTime() - MAX_REPLAY_MS).toISOString());
    assert.deepEqual(start.cursor.stock, cursor.stock);

    const future = encodeStreamCursor({ ...cursor, stock: { createdAt: '2026-09-28T11:00:00.000Z', id: '' } });
    const fromFuture = resolveStreamStart(future, NOW);
    assert.equal(fromFuture.resumed, false);
    assert.equal(fromFuture.cursor.stock.createdAt, NOW.toISOString());
  });

  it('ends each stream below the Netlify 26 s proxy cut', () => {
    delete process.env.NOTIFICATION_STREAM_MAX_SECONDS;
    assert.equal(getStreamMaxMs(), 20_000);
    assert.ok(getStreamMaxMs() < 26_000);
    process.env.NOTIFICATION_STREAM_MAX_SECONDS = '0';
    assert.equal(getStreamMaxMs(), 0);
    process.env.NOTIFICATION_STREAM_MAX_SECONDS = '-1';
    assert.throws(() => getStreamMaxMs(), /0 to 3600/);
  });

  it('tags every event with the resume id and ends with a reconnect event', () => {
    const controller = read('src/controllers/notifications/index.ts');
    assert.match(controller, /resolveStreamStart\(singleHeader\(request\.headers\['last-event-id'\]\)\)/);
    assert.match(controller, /writeEvent\(reply, 'notification', payload, currentId\(\)\)/);
    assert.match(controller, /occurred_at: stockChange\.created_at,\s*\}, currentId\(\)\)/);
    assert.match(controller, /resumed: start\.resumed,\s*\}, currentId\(\)\)/);
    assert.match(controller, /writeEvent\(reply, 'reconnect', \{ reason: 'max_duration' \}, currentId\(\)\);\s*reply\.raw\.end\(\);/);
    // The cursor moves before the id is written, so the id points past the event.
    assert.match(controller, /cursorId = cursorIdForRow;\s*writeEvent\(reply, 'notification'/);
    assert.match(read('src/routes/notifications/index.ts'), /getStreamMaxMs\(\);/);
  });
});
