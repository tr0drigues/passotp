
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import path from 'path';
import { fileURLToPath } from 'url';
import { z } from 'zod';
import { totpService } from './services/totp.service.js';
import { securityService } from './services/security.service.js';
import { recoveryService } from './services/recovery.service.js'; // New Service
import { webauthnService } from './services/webauthn.service.js'; // New Service
import { logger } from './lib/logger.js'; // New Logger
import redis from './lib/redis.js';
import { encryptionService } from './services/encryption.service.js';
import fastifyCookie from '@fastify/cookie';
import fastifyHelmet from '@fastify/helmet';

// Setup paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Redis TTL: 50 days in seconds
const USER_TTL = 50 * 24 * 60 * 60;

const fastify = Fastify({
    logger: false // Disable default logger to use custom JSON logger
});

// Plugins
fastify.register(cors);
fastify.register(fastifyHelmet, { contentSecurityPolicy: false }); // Disable CSP for simplicity in this demo, or configure it.
fastify.register(fastifyCookie, {
    secret: process.env.SESSION_SECRET || 'supersecret-fallback-key-change-me', // User should set this
    hook: 'onRequest',
});

fastify.register(fastifyStatic, {
    root: path.join(__dirname, '../public'),
    prefix: '/',
});

// Schema Validation
const SetupSchema = z.object({
    user: z.string().min(3),
});

const LoginSchema = z.object({
    user: z.string().min(3),
    token: z.string().min(6), // Pode ser 6 (TOTP) ou 9 (Recovery XXXX-XXXX)
});

// Routes
fastify.post('/setup', async (request, reply) => {
    logger.info({ event: 'SETUP_INIT', message: 'Setup requested', meta: { ip: request.ip } });

    const { user } = SetupSchema.parse(request.body);

    // 1. Gerar Segredo
    const secret = totpService.generateSecret();

    // 2. Gerar Key URI
    const otpAuthKey = totpService.getOtpAuthKey(user, secret);

    // 3. Gerar QR Code
    const qrCode = await totpService.generateQRCode(otpAuthKey);

    // 4. Gerar Recovery Codes
    const recoveryCodes = totpService.generateRecoveryCodes();

    // 5. Salvar Segredo no Redis (Encriptado)
    const encryptedSecret = encryptionService.encrypt(secret);
    await redis.hset(`user:${user}`, { secret: encryptedSecret });

    // 6. Salvar Recovery Codes (Hashed)
    // 6. Salvar Recovery Codes (Hashed)
    await recoveryService.saveRecoveryCodes(user, recoveryCodes);

    // 7. Set Expiration (50 days)
    await redis.expire(`user:${user}`, USER_TTL);
    await redis.expire(`recovery:${user}`, USER_TTL);
    await redis.expire(`webauthn:credentials:${user}`, USER_TTL);

    return { secret, qrCode, recoveryCodes };
});

fastify.post('/login', async (request, reply) => {
    const { user, token } = LoginSchema.parse(request.body);
    const ip = request.ip;
    const userIdentifier = `${user}:${ip}`;
    const userAgent = request.headers['user-agent'] || 'unknown';

    // 0. Context Awareness (Simple Check)
    // Em produção, compararíamos com IPs passados do usuário
    logger.info({
        event: 'AUTH_SUCCESS', // Tentativa, ainda não sucesso
        message: 'Login attempt',
        user, ip, userAgent
    });

    // 1. Check Rate Limit (Dual Layer: IP & User)
    // Layer 1: IP Rate Limit (DDoS / Brute Force protection)
    const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
    if (!ipLimit.allowed) {
        logger.warn({ event: 'RATE_LIMIT_IP', message: 'IP Rate limit exceeded', user, ip, meta: { banExpires: ipLimit.banExpires } });
        return reply.status(429).send({
            success: false,
            message: `Muitas tentativas. Tente novamente em ${Math.ceil(ipLimit.banExpires!)} segundos.`
        });
    }

    // Layer 2: User Rate Limit (Credential Stuffing protection)
    const userLimit = await securityService.checkRateLimit(`user:${user}`);
    if (!userLimit.allowed) {
        logger.warn({ event: 'RATE_LIMIT_USER', message: 'User Rate limit exceeded', user, ip, meta: { banExpires: userLimit.banExpires } });
        // We generically blame "credentials" or "attempts" to not confirm user existence,
        // but 429 is clearly a rate limit.
        return reply.status(429).send({
            success: false,
            message: `Muitas tentativas para este usuário. Aguarde ${Math.ceil(userLimit.banExpires!)} segundos.`
        });
    }

    // Se token tem formato de recovery (contém traço ou tamanho > 6)
    if (token.includes('-') || token.length > 6) {
        const isRecoveryValid = await recoveryService.validateAndConsumeCode(user, token);
        if (isRecoveryValid) {
            logger.warn({ event: 'RECOVERY_USE', message: 'User logged in with recovery code', user, ip });
            return {
                success: true,
                message: 'Login realizado com Código de Recuperação!',
                meta: {
                    method: 'RECOVERY_CODE',
                    user,
                    ip,
                    userAgent,
                    timestamp: new Date().toISOString()
                }
            };
        }
        // Se falhar recovery, continua fluxo normal (vai falhar no TOTP também)
    }

    // 2. Buscar Segredo do Usuário
    const userData = await redis.hgetall(`user:${user}`);

    // Generic error message for Account Enumeration prevention
    // We should ideally use constant time comparison or random delay, but for now generic message is step 1.
    const GENERIC_ERROR = 'Credenciais inválidas.';

    if (!userData || !userData.secret) {
        // User not found
        logger.warn({ event: 'AUTH_FAIL', message: 'User not found (Generic logic)', user, ip });
        // Fake verification time? 
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    let secret: string;
    try {
        secret = encryptionService.decrypt(userData.secret);
    } catch (e) {
        // Generic Error for decryption failure to avoid Oracle
        logger.error({ event: 'AUTH_FAIL', message: 'Internal decryption error', user });
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    // 3. Validar Token TOTP
    const isValid = totpService.verifyToken(token, secret);
    if (!isValid) {
        logger.warn({ event: 'AUTH_FAIL', message: 'Invalid TOTP code', user, ip });
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    // 4. Replay Check (Atomic User Step)
    // Pass just user ID, not the secret.
    // Logic: `replay:{user}:{step}`
    const isFresh = await securityService.checkReplay(user);
    if (!isFresh) {
        logger.warn({ event: 'REPLAY_ATTACK', message: 'Replay attack detected (Step Reuse)', user, ip });
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    // Success - Set Session Cookie
    reply.setCookie('session', user, {
        path: '/',
        httpOnly: true,
        secure: true, // Requires HTTPS (or localhost)
        sameSite: 'strict',
        maxAge: 3600 // 1 hour
    });

    // Refresh TTL on successful login
    await redis.expire(`user:${user}`, USER_TTL);
    await redis.expire(`recovery:${user}`, USER_TTL);
    await redis.expire(`webauthn:credentials:${user}`, USER_TTL);

    logger.info({ event: 'AUTH_SUCCESS', message: 'User authenticated successfully', user, ip });
    return {
        success: true,
        message: 'Login realizado com sucesso!',
        meta: {
            method: 'TOTP_APP',
            user,
            ip,
            userAgent,
            timestamp: new Date().toISOString()
        }
    };
});


// --- WebAuthn Routes ---

// 1. Register Challenge
fastify.post('/webauthn/register/challenge', async (request, reply) => {
    const { user } = SetupSchema.parse(request.body); // Use SetupSchema (only user required)
    const options = await webauthnService.generateRegisterOptions(user);
    return options;
});

// 2. Register Verify
fastify.post('/webauthn/register/verify', async (request, reply) => {
    const { user, ...body } = request.body as any; // Body contains the attestation response
    try {
        const success = await webauthnService.verifyRegister(user, body);
        return { success, message: success ? 'Passkey salva com sucesso!' : 'Falha ao salvar Passkey.' };
    } catch (err: any) {
        reply.status(400);
        return { success: false, message: err.message };
    }
});

// 3. Login Challenge
fastify.post('/webauthn/login/challenge', async (request, reply) => {
    const { user } = SetupSchema.parse(request.body);
    try {
        const options = await webauthnService.generateLoginOptions(user);
        return options;
    } catch (err: any) {
        // Se usuário não tiver passkeys, retornamos erro genérico para evitar user enumeration
        // Idealmente, deveríamos retornar um challenge "falso" para o browser abrir o prompt e falhar depois,
        // mas por enquanto vamos padronizar a mensagem.
        reply.status(400); // Bad Request ou 401
        return { success: false, message: 'Não foi possível iniciar a autenticação.' };
    }
});

// 4. Login Verify
fastify.post('/webauthn/login/verify', async (request, reply) => {
    const { user, ...body } = request.body as any;
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] || 'unknown';

    try {
        const success = await webauthnService.verifyLogin(user, body);
        if (success) {
            logger.info({ event: 'AUTH_SUCCESS', message: 'User authenticated via WebAuthn', user, ip });
            return {
                success: true,
                message: 'Login com Passkey realizado!',
                meta: {
                    method: 'WEBAUTHN_PASSKEY',
                    user,
                    ip,
                    userAgent,
                    timestamp: new Date().toISOString()
                }
            };
        }
        return reply.status(401).send({ success: false, message: 'Validação da Passkey falhou.' });
    } catch (err: any) {
        logger.warn({ event: 'AUTH_FAIL', message: 'WebAuthn logic error', user, ip, meta: { error: err.message } });
        return reply.status(400).send({ success: false, message: err.message });
    }
});

// Start
const start = async () => {
    try {
        await fastify.listen({ port: 3000, host: '0.0.0.0' });
        logger.info({ event: 'SYSTEM_START', message: 'Server running at http://localhost:3000' });
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();
