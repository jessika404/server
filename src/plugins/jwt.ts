import jwt from '@fastify/jwt';
import fp from 'fastify-plugin';
import type { PermissionCode } from '../domain/permission-codes';
import { assertAuthConfiguration } from '../config/auth';
import { getNetlifyProxySecret } from '../utils/clientIp';

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: {
      sub: string;
      sid: string;
    };
    user: {
      sub: string;
      sid: string;
      exp: number;
      id: string;
      email?: string;
      areaId: string;
      roleIds: string[];
      permissions: PermissionCode[];
      isSystemAdmin: boolean;
    };
  }
}

export default fp(async (fastify) => {
  // Fails the boot on any missing or inconsistent auth setting.
  const config = assertAuthConfiguration();
  const secret = process.env.APP_JWT_SECRET as string;
  // Behind Netlify every request arrives from a Netlify address; without the
  // signature secret all users would share one rate-limit bucket.
  if (!getNetlifyProxySecret() && process.env.NODE_ENV === 'production') {
    throw new Error('NETLIFY_PROXY_SIGNATURE_SECRET is required in production (see client/netlify.toml)');
  }

  await fastify.register(jwt, {
    secret,
    sign: {
      algorithm: 'HS256',
      expiresIn: config.accessTokenTtl,
      iss: config.issuer,
      aud: config.audience,
    },
    verify: {
      algorithms: ['HS256'],
      allowedIss: config.issuer,
      allowedAud: config.audience,
    },
  });
});
