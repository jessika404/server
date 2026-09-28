import rateLimit from '@fastify/rate-limit';
import fp from 'fastify-plugin';
import { resolveClientIp } from '../utils/clientIp';

export default fp(async (fastify) => {
  await fastify.register(rateLimit, {
    global: false,
    // One bucket per real user, not one per Netlify egress address.
    keyGenerator: (request) => resolveClientIp(request),
    errorResponseBuilder: (_request, context) => ({
      statusCode: 429,
      error: 'Too Many Requests',
      message: `Quá nhiều lần thử. Vui lòng thử lại sau ${context.after}.`,
    }),
  });
});

