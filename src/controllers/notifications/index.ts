import type { FastifyReply, FastifyRequest } from 'fastify';
import type { NotificationListQuery } from '../../interfaces/notifications';
import { NOTIFICATION_DOMAIN } from '../../interfaces/notifications';
import { PERMISSION_CODE } from '../../domain/permission-codes';
import { permissionRequirementSatisfied } from '../../middleware/auth';
import {
  NotificationServiceError,
  NotificationsService,
} from '../../services/notifications.service';
import {
  isPaginatedResult,
  PaginationValidationError,
  toPaginatedResponse,
} from '../../utils/pagination';
import { getAllowedClientOrigins } from '../../config/auth';
import {
  encodeStreamCursor,
  getStreamMaxMs,
  resolveStreamStart,
} from '../../utils/sseCursor';

const respond = async (
  request: FastifyRequest,
  reply: FastifyReply,
  handler: () => Promise<unknown>,
) => {
  try {
    const result = await handler();
    if (isPaginatedResult(result)) {
      const response = toPaginatedResponse(result);
      const unreadCount = (result as { unreadCount?: number }).unreadCount ?? 0;
      return reply.send({ ...response, unread_count: unreadCount });
    }
    return reply.send({ data: result });
  } catch (error) {
    if (error instanceof PaginationValidationError
        || error instanceof NotificationServiceError) {
      return reply.code(error.statusCode).send({ error: error.message });
    }
    request.log.error(error);
    return reply.code(500).send({ error: 'Internal server error' });
  }
};

export const listNotifications = (request: FastifyRequest, reply: FastifyReply) =>
  respond(request, reply, () => new NotificationsService(request.server).list(
    request.user.id,
    request.query as NotificationListQuery,
  ));

export const markNotificationRead = (
  request: FastifyRequest,
  reply: FastifyReply,
) => respond(request, reply, () => new NotificationsService(request.server).markRead(
  request.user.id,
  (request.params as { id: string }).id,
));

/** Every event carries the resume id, so the client always knows where it is. */
const writeEvent = (
  reply: FastifyReply,
  event: string,
  payload: unknown,
  id?: string,
): void => {
  reply.raw.write(`${id ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
};

const singleHeader = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value[0] : value;

export const streamNotifications = (
  request: FastifyRequest,
  reply: FastifyReply,
) => {
  const requestOrigin = request.headers.origin;
  const allowedOrigins = getAllowedClientOrigins();
  if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    // `reply.hijack()` bypasses Fastify's normal response lifecycle, so the
    // CORS plugin cannot reliably add headers to this streamed response.
    reply.raw.setHeader('Access-Control-Allow-Origin', requestOrigin);
    reply.raw.setHeader('Access-Control-Allow-Credentials', 'true');
    reply.raw.setHeader('Vary', 'Origin');
  }

  reply.hijack();
  reply.raw.statusCode = 200;
  reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  reply.raw.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  reply.raw.setHeader('Connection', 'keep-alive');
  reply.raw.setHeader('X-Accel-Buffering', 'no');
  reply.raw.flushHeaders();
  reply.raw.write('retry: 1000\n\n');

  const service = new NotificationsService(request.server);
  // Resume after the last event the client saw (Last-Event-ID), else from now.
  const start = resolveStreamStart(singleHeader(request.headers['last-event-id']));
  let cursorCreatedAt = start.cursor.notifications.createdAt;
  let cursorId = start.cursor.notifications.id;
  let stockCursorCreatedAt = start.cursor.stock.createdAt;
  let stockCursorId = start.cursor.stock.id;
  let polling = false;
  let closed = false;
  const canReceiveStockSignals = permissionRequirementSatisfied(
    request.user,
    PERMISSION_CODE.SUPPLY_ORDER_CREATE,
  );
  const currentId = () => encodeStreamCursor({
    notifications: { createdAt: cursorCreatedAt, id: cursorId },
    stock: { createdAt: stockCursorCreatedAt, id: stockCursorId },
  });

  writeEvent(reply, 'connected', {
    connected_at: new Date().toISOString(),
    // false: the client may have missed events and should refetch its lists.
    resumed: start.resumed,
  }, currentId());

  const poll = async () => {
    if (closed || polling) return;
    polling = true;
    try {
      const signals = await service.listLiveSignals(
        request.user.id,
        cursorCreatedAt,
        cursorId,
      );
      for (const signal of signals) {
        if (closed) break;
        const { cursor_id: cursorIdForRow, ...payload } = signal;
        cursorCreatedAt = signal.created_at;
        cursorId = cursorIdForRow;
        writeEvent(reply, 'notification', payload, currentId());
      }
      if (canReceiveStockSignals && !closed) {
        const stockChange = await service.getLatestStockChange(
          stockCursorCreatedAt,
          stockCursorId,
        );
        if (stockChange) {
          stockCursorCreatedAt = stockChange.created_at;
          stockCursorId = stockChange.cursor_id;
          writeEvent(reply, 'stock_changed', {
            domain: NOTIFICATION_DOMAIN.SUPPLY,
            type: 'STOCK_CHANGED',
            occurred_at: stockChange.created_at,
          }, currentId());
        }
      }
    } catch (error) {
      request.log.error(error, 'Notification SSE poll failed');
      if (!closed) writeEvent(reply, 'sync_error', { retryable: true });
    } finally {
      polling = false;
    }
  };

  const pollTimer = setInterval(() => void poll(), 1500);
  const heartbeatTimer = setInterval(() => {
    if (!closed) reply.raw.write(': keep-alive\n\n');
  }, 15000);
  const accessTokenExpiryTimer = setTimeout(() => {
    if (!closed) reply.raw.end();
  }, Math.max(0, request.user.exp * 1000 - Date.now()));
  // End cleanly before the Netlify proxy's 26-second cut: the client reconnects
  // at once with the id of the last event and misses nothing. A last poll runs
  // first so nothing that arrived since the previous tick waits a whole cycle.
  const maxMs = getStreamMaxMs();
  const lifetimeTimer = maxMs > 0
    ? setTimeout(() => {
      void (async () => {
        while (polling && !closed) await new Promise((resolve) => setTimeout(resolve, 50));
        await poll();
        if (!closed) {
          writeEvent(reply, 'reconnect', { reason: 'max_duration' }, currentId());
          reply.raw.end();
        }
      })();
    }, maxMs)
    : null;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearInterval(pollTimer);
    clearInterval(heartbeatTimer);
    clearTimeout(accessTokenExpiryTimer);
    if (lifetimeTimer) clearTimeout(lifetimeTimer);
  };
  request.raw.once('close', cleanup);
  reply.raw.once('close', cleanup);
};
