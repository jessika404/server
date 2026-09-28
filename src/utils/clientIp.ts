import { createHmac, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import type { FastifyRequest } from 'fastify';

/**
 * Real client IP behind the Netlify proxy.
 *
 * Browser → Netlify edge → Railway edge → this server. `request.ip` (with
 * TRUST_PROXY=1 for the Railway hop) is the address that reached Railway, i.e.
 * a Netlify egress IP shared by every user. Netlify names the real client in
 * `x-nf-client-connection-ip`, but anyone can send that header straight to
 * Railway, so it is trusted only on a request Netlify signed: the proxy rule in
 * netlify.toml has `signed = "NETLIFY_PROXY_SIGNATURE_SECRET"`, which adds an
 * `x-nf-sign` JWS (HS256, iss "netlify") keyed with that shared secret.
 *
 * Used for every rate-limit bucket and for auth_sessions.ip_address.
 */
export const NETLIFY_SIGNATURE_HEADER = 'x-nf-sign';
export const NETLIFY_CLIENT_IP_HEADER = 'x-nf-client-connection-ip';

const MIN_SECRET_LENGTH = 32;

export const getNetlifyProxySecret = (): string | null => {
  const secret = process.env.NETLIFY_PROXY_SIGNATURE_SECRET?.trim();
  if (!secret) return null;
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error(`NETLIFY_PROXY_SIGNATURE_SECRET must contain at least ${MIN_SECRET_LENGTH} characters`);
  }
  return secret;
};

const decodeJson = (part: string): Record<string, unknown> | null => {
  try {
    const value = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as unknown;
    return value && typeof value === 'object' ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
};

/** Verifies Netlify's x-nf-sign JWS: HS256, issuer "netlify", not expired. */
export const isValidNetlifySignature = (
  token: string | undefined,
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean => {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [headerPart, payloadPart, signaturePart] = parts;

  const header = decodeJson(headerPart);
  if (header?.alg !== 'HS256') return false;

  const expected = createHmac('sha256', secret).update(`${headerPart}.${payloadPart}`).digest();
  let actual: Buffer;
  try {
    actual = Buffer.from(signaturePart, 'base64url');
  } catch {
    return false;
  }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return false;

  const payload = decodeJson(payloadPart);
  if (payload?.iss !== 'netlify') return false;
  return typeof payload.exp === 'number' && payload.exp > nowSeconds;
};

const singleHeader = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value[0] : value;

const resolved = new WeakMap<FastifyRequest, string>();

export const resolveClientIp = (
  request: FastifyRequest,
  secret: string | null = getNetlifyProxySecret(),
): string => {
  const cached = resolved.get(request);
  if (cached) return cached;

  let ip = request.ip;
  if (secret && isValidNetlifySignature(singleHeader(request.headers[NETLIFY_SIGNATURE_HEADER]), secret)) {
    const forwarded = singleHeader(request.headers[NETLIFY_CLIENT_IP_HEADER])?.trim();
    if (forwarded && isIP(forwarded)) ip = forwarded;
  }
  resolved.set(request, ip);
  return ip;
};
