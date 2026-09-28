import type { FastifyPluginAsync } from 'fastify';
import {
  listNotifications,
  markNotificationRead,
  streamNotifications,
} from '../../controllers/notifications';
import { verifyToken } from '../../middleware/auth';
import {
  notificationListSchema,
  notificationReadSchema,
  notificationStreamSchema,
} from '../../schemas/notifications';
import { getStreamMaxMs } from '../../utils/sseCursor';

const notificationRoutes: FastifyPluginAsync = async (fastify) => {
  // Validate NOTIFICATION_STREAM_MAX_SECONDS at boot, not on the first stream.
  getStreamMaxMs();

  fastify.get('/', {
    preHandler: [verifyToken],
    schema: notificationListSchema,
  }, listNotifications);

  fastify.patch('/:id/read', {
    preHandler: [verifyToken],
    schema: notificationReadSchema,
  }, markNotificationRead);

  fastify.get('/stream', {
    preHandler: [verifyToken],
    schema: notificationStreamSchema,
  }, streamNotifications);
};

export default notificationRoutes;
