/**
 * SSE event ids for the notification stream.
 *
 * The stream polls two ordered feeds by cursor (created_at, id): the user's
 * notifications and stock transactions. The event id is both cursors, encoded,
 * so a client that reconnects with `Last-Event-ID` resumes exactly where it
 * stopped and nothing emitted in between is lost. The Netlify proxy cuts
 * responses after 26 seconds, so the server ends each stream itself (see
 * NOTIFICATION_STREAM_MAX_SECONDS) and the client reconnects with the id.
 *
 * Replay is bounded: a cursor older than MAX_REPLAY_MS resumes from that bound
 * and the stream reports `resumed: false`, so the client refetches its lists.
 */
export interface FeedCursor {
  createdAt: string;
  id: string;
}

export interface StreamCursor {
  notifications: FeedCursor;
  stock: FeedCursor;
}

export const MAX_REPLAY_MS = 10 * 60_000;
const MAX_ID_LENGTH = 512;
const ROW_ID = /^[0-9a-f-]{0,64}$/i;

export const encodeStreamCursor = (cursor: StreamCursor): string =>
  Buffer.from(JSON.stringify([
    cursor.notifications.createdAt,
    cursor.notifications.id,
    cursor.stock.createdAt,
    cursor.stock.id,
  ])).toString('base64url');

const validFeed = (createdAt: unknown, id: unknown): FeedCursor | null =>
  typeof createdAt === 'string'
  && !Number.isNaN(Date.parse(createdAt))
  && typeof id === 'string'
  && ROW_ID.test(id)
    ? { createdAt, id }
    : null;

export const decodeStreamCursor = (value: string | undefined): StreamCursor | null => {
  if (!value || value.length > MAX_ID_LENGTH) return null;
  try {
    const parts = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as unknown;
    if (!Array.isArray(parts) || parts.length !== 4) return null;
    const notifications = validFeed(parts[0], parts[1]);
    const stock = validFeed(parts[2], parts[3]);
    return notifications && stock ? { notifications, stock } : null;
  } catch {
    return null;
  }
};

/**
 * Where a new stream starts: from `Last-Event-ID` when it is valid and recent,
 * otherwise from now. `resumed` tells the client whether it missed nothing.
 */
export const resolveStreamStart = (
  lastEventId: string | undefined,
  now: Date = new Date(),
): { cursor: StreamCursor; resumed: boolean } => {
  const nowIso = now.toISOString();
  const fresh = { createdAt: nowIso, id: '' };
  const decoded = decodeStreamCursor(lastEventId);
  if (!decoded) return { cursor: { notifications: fresh, stock: { ...fresh } }, resumed: false };

  const floor = now.getTime() - MAX_REPLAY_MS;
  const bound = (feed: FeedCursor): { feed: FeedCursor; clamped: boolean } => {
    const at = Date.parse(feed.createdAt);
    if (at < floor) return { feed: { createdAt: new Date(floor).toISOString(), id: '' }, clamped: true };
    // A cursor from the future (clock skew, tampering) would silence the feed.
    if (at > now.getTime()) return { feed: { ...fresh }, clamped: true };
    return { feed, clamped: false };
  };
  const notifications = bound(decoded.notifications);
  const stock = bound(decoded.stock);
  return {
    cursor: { notifications: notifications.feed, stock: stock.feed },
    resumed: !notifications.clamped && !stock.clamped,
  };
};

const DEFAULT_MAX_SECONDS = 20;

/**
 * How long one stream stays open before the server ends it. Below the Netlify
 * proxy's 26-second cut, so every close is a clean end with a known id rather
 * than a dropped connection. 0 keeps streams open (direct connections only).
 */
export const getStreamMaxMs = (): number => {
  const raw = process.env.NOTIFICATION_STREAM_MAX_SECONDS?.trim();
  const seconds = raw ? Number(raw) : DEFAULT_MAX_SECONDS;
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 3600) {
    throw new Error('NOTIFICATION_STREAM_MAX_SECONDS must be an integer from 0 to 3600');
  }
  return seconds * 1000;
};
