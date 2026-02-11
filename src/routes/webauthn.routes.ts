
import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { webauthnService } from '../services/webauthn.service.js';
import { securityService } from '../services/security.service.js';
import { logger } from '../lib/logger.js';
import crypto from 'crypto';
import redis from '../lib/redis.js';
import { config } from '../config.js';

const SetupSchema = z.object({
    user: z.string().min(3),
});

// Helper: Create Session (Duplicated from auth.routes.ts - consider extracting to session.service.ts later if needed)
async function createSession(reply: any, user: string, ip: string, userAgent: string, method: string) {
    const sessionId = crypto.randomUUID();
    const sessionKey = `session:${sessionId}`;

    await redis.set(sessionKey, JSON.stringify({ user, ip, userAgent, method, createdAt: new Date().toISOString() }), 'EX', config.redis.ttl.session);

    reply.setCookie('session', sessionId, {
        path: '/',
        httpOnly: true,
        secure: config.env.isProduction,
        sameSite: 'lax',
        maxAge: config.redis.ttl.session,
        signed: true
    });

    // Refresh User TTLs
    await redis.expire(`user:${user}`, config.redis.ttl.user);
    await redis.expire(`recovery:${user}`, config.redis.ttl.user);
    await redis.expire(`webauthn:credentials:${user}`, config.redis.ttl.user);

    return sessionId;
}

export async function webauthnRoutes(fastify: FastifyInstance) {

    fastify.post('/webauthn/register/challenge', async (request, reply) => {
        const { user } = SetupSchema.parse(request.body);
        const ip = request.ip;

        const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
        if (!ipLimit.allowed) {
            return reply.status(429).send({ success: false, message: 'Too many attempts.' });
        }

        const options = await webauthnService.generateRegisterOptions(user);
        return options;
    });

    fastify.post('/webauthn/register/verify', async (request, reply) => {
        const { user, ...body } = request.body as any;
        const ip = request.ip;

        const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
        if (!ipLimit.allowed) {
            return reply.status(429).send({ success: false, message: 'Too many attempts.' });
        }

        try {
            const success = await webauthnService.verifyRegister(user, body);
            return { success, message: success ? 'Passkey saved!' : 'Failed to save Passkey.' };
        } catch (err: any) {
            reply.status(400);
            return { success: false, message: err.message };
        }
    });

    fastify.post('/webauthn/login/challenge', async (request, reply) => {
        const { user } = SetupSchema.parse(request.body);
        const ip = request.ip;

        const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
        if (!ipLimit.allowed) {
            logger.warn({ event: 'RATE_LIMIT_IP', message: 'WebAuthn Challenge Rate limit', user, ip });
            return reply.status(429).send({ success: false, message: 'Too many attempts.' });
        }
        try {
            const options = await webauthnService.generateLoginOptions(user);
            return options;
        } catch {
            // Fallthrough
        }
    });

    fastify.post('/webauthn/login/verify', async (request, reply) => {
        const { user, ...body } = request.body as any;
        const ip = request.ip;
        const userAgent = request.headers['user-agent'] || 'unknown';

        const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
        const userLimit = await securityService.checkRateLimit(`user:${user}`);

        if (!ipLimit.allowed || !userLimit.allowed) {
            logger.warn({ event: 'RATE_LIMIT_IP', message: 'WebAuthn Verify Rate limit', user, ip });
            return reply.status(429).send({ success: false, message: 'Too many attempts.' });
        }

        try {
            const success = await webauthnService.verifyLogin(user, body);
            if (success) {
                await createSession(reply, user, ip, userAgent, 'WEBAUTHN_PASSKEY');

                logger.info({ event: 'AUTH_SUCCESS_WEBAUTHN', message: 'User authenticated via WebAuthn', user, ip });
                return {
                    success: true,
                    message: 'Login with Passkey successful!',
                    meta: {
                        method: 'WEBAUTHN_PASSKEY',
                        user, ip, userAgent,
                        timestamp: new Date().toISOString()
                    }
                };
            }
            return reply.status(401).send({ success: false, message: 'Passkey validation failed.' });
        } catch (err: any) {
            logger.warn({ event: 'AUTH_FAIL', message: 'WebAuthn logic error', user, ip, meta: { error: err.message } });
            return reply.status(400).send({ success: false, message: err.message });
        }
    });
}
