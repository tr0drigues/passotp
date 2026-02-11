
import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import crypto from 'crypto';
import { totpService } from '../services/totp.service.js';
import { securityService } from '../services/security.service.js';
import { recoveryService } from '../services/recovery.service.js';
import { encryptionService } from '../services/encryption.service.js';
import redis from '../lib/redis.js';
import { config } from '../config.js';
import { logger } from '../lib/logger.js';

const LoginSchema = z.object({
    user: z.string().min(3),
    token: z.string().regex(/^[0-9]{6}$|^[a-zA-Z0-9-]{9,}$/, "Invalid token format"),
});

// Helper: Create Session
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

export async function authRoutes(fastify: FastifyInstance) {

    // Development Verification Endpoint
    fastify.post('/verify', async (request, reply) => {
        const { enableDevVerify, confirmsRisk } = config.security;
        const isEnabled = enableDevVerify && confirmsRisk;

        if (config.env.isProduction && !isEnabled) {
            return reply.status(404).send({ error: 'Not Found', message: 'Endpoint disabled in production.' });
        }

        if (isEnabled && config.env.isProduction) {
            logger.warn({ event: 'SECURITY_ALERT', message: 'Verify endpoint enabled in PRODUCTION', meta: { user: (request.body as any)['user'] } });
        }

        const { token, secret } = request.body as any;

        if (!token || !secret) {
            return reply.status(400).send({ success: false, message: 'Token and Secret are required.' });
        }

        const isValid = totpService.verifyToken(token, secret);

        if (isValid) {
            return { success: true, message: 'Code verified successfully!' };
        } else {
            return reply.status(400).send({ success: false, message: 'Invalid code.' });
        }
    });

    fastify.post('/login', async (request, reply) => {
        const { user, token } = LoginSchema.parse(request.body);
        const ip = request.ip;
        const userAgent = request.headers['user-agent'] || 'unknown';

        logger.info({
            event: 'AUTH_ATTEMPT',
            message: 'Login attempt',
            user, ip, userAgent
        });

        // 1. IP Rate Limit (Anti-DDoS)
        const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
        if (!ipLimit.allowed) {
            logger.warn({ event: 'RATE_LIMIT_IP', message: 'IP Rate limit exceeded', user, ip, meta: { banExpires: ipLimit.banExpires } });
            return reply.status(429).send({
                success: false,
                message: `Too many attempts. Try again in ${Math.ceil(ipLimit.banExpires!)} seconds.`
            });
        }

        // 2. User Rate Limit (Anti-Credential Stuffing)
        const userLimit = await securityService.checkRateLimit(`user:${user}`);
        if (!userLimit.allowed) {
            logger.warn({ event: 'RATE_LIMIT_USER', message: 'User Rate limit exceeded', user, ip, meta: { banExpires: userLimit.banExpires } });
            return reply.status(429).send({
                success: false,
                message: `Too many attempts for this user. Wait ${Math.ceil(userLimit.banExpires!)} seconds.`
            });
        }

        // Recovery Code Flow
        if (token.includes('-') || token.length > 6) {
            const isRecoveryValid = await recoveryService.validateAndConsumeCode(user, token);
            if (isRecoveryValid) {
                logger.warn({ event: 'RECOVERY_USE', message: 'User logged in with recovery code', user, ip });
                await createSession(reply, user, ip, userAgent, 'RECOVERY_CODE');

                return {
                    success: true,
                    message: 'Login successful (Recovery Code)',
                    meta: {
                        method: 'RECOVERY_CODE',
                        user, ip, userAgent,
                        timestamp: new Date().toISOString()
                    }
                };
            }
        }

        // 3. TOTP Flow
        const userData = await redis.hgetall(`user:${user}`);
        const GENERIC_ERROR = 'Invalid credentials.';

        if (!userData || !userData.secret) {
            logger.warn({ event: 'AUTH_FAIL', message: 'User not found', user, ip });
            await new Promise(resolve => setTimeout(resolve, 200));
            return reply.status(401).send({ success: false, message: GENERIC_ERROR });
        }

        let secret: string;
        try {
            secret = encryptionService.decrypt(userData.secret);
        } catch {
            logger.error({ event: 'AUTH_FAIL', message: 'Decryption error', user });
            await new Promise(resolve => setTimeout(resolve, 200));
            return reply.status(401).send({ success: false, message: GENERIC_ERROR });
        }

        const isValid = totpService.verifyToken(token, secret);
        if (!isValid) {
            logger.warn({ event: 'AUTH_FAIL', message: 'Invalid TOTP code', user, ip });
            await new Promise(resolve => setTimeout(resolve, 200));
            return reply.status(401).send({ success: false, message: GENERIC_ERROR });
        }

        // 4. Replay Check
        const isFresh = await securityService.checkReplay(user);
        if (!isFresh) {
            logger.warn({ event: 'REPLAY_ATTACK', message: 'Replay attack detected', user, ip });
            await new Promise(resolve => setTimeout(resolve, 200));
            return reply.status(401).send({ success: false, message: GENERIC_ERROR });
        }

        await createSession(reply, user, ip, userAgent, 'TOTP_APP');

        logger.info({ event: 'AUTH_SUCCESS_TOTP', message: 'User authenticated successfully', user, ip });
        return {
            success: true,
            message: 'Login successful!',
            meta: {
                method: 'TOTP_APP',
                user, ip, userAgent,
                timestamp: new Date().toISOString()
            }
        };
    });
}
