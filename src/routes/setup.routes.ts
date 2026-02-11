
import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { totpService } from '../services/totp.service.js';
import { encryptionService } from '../services/encryption.service.js';
import { recoveryService } from '../services/recovery.service.js';
import redis from '../lib/redis.js';
import { config } from '../config.js';
import { logger } from '../lib/logger.js';

const SetupSchema = z.object({
    user: z.string().min(3),
});

export async function setupRoutes(fastify: FastifyInstance) {
    fastify.post('/setup', async (request, _reply) => {
        logger.info({ event: 'SETUP_INIT', message: 'Setup requested', meta: { ip: request.ip } });

        const { user } = SetupSchema.parse(request.body);

        const secret = totpService.generateSecret();
        const otpAuthKey = totpService.getOtpAuthKey(user, secret);
        const qrCode = await totpService.generateQRCode(otpAuthKey);
        const recoveryCodes = totpService.generateRecoveryCodes();

        const encryptedSecret = encryptionService.encrypt(secret);
        await redis.hset(`user:${user}`, { secret: encryptedSecret });

        await recoveryService.saveRecoveryCodes(user, recoveryCodes);

        // Set Expiration
        await redis.expire(`user:${user}`, config.redis.ttl.user);
        await redis.expire(`recovery:${user}`, config.redis.ttl.user);
        await redis.expire(`webauthn:credentials:${user}`, config.redis.ttl.user);

        // Security Check: Only return secret in Debug Mode with explicit confirmation
        const { allowDebugSetup, confirmsRisk } = config.security;
        const allowDebugOutput = allowDebugSetup && confirmsRisk;

        if (config.env.isProduction && !allowDebugOutput) {
            return {
                qrCode,
                recoveryCodes
            };
        }

        if (allowDebugOutput && config.env.isProduction) {
            logger.warn({ event: 'SECURITY_ALERT', message: 'Debug output enabled in PRODUCTION', meta: { user } });
        }

        return {
            secret,
            otpAuth: otpAuthKey,
            qrCode,
            recoveryCodes
        };
    });
}
