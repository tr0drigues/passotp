
import 'dotenv/config'; // Load .env
import Fastify from 'fastify';
import crypto from 'crypto'; // Native Node.js crypto
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
    logger: false, // Disable default logger to use custom JSON logger
    trustProxy: true // Trust Nginx proxy for correct IP rate limiting
});

// Plugins
fastify.register(cors, {
    origin: (origin, cb) => {
        const isProd = process.env.NODE_ENV === 'production';
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return cb(null, true);

        if (isProduction) {
            // In production, strictly allow only allowed origins
            const allowedOrigins = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : [];
            const frontendOrigin = process.env.FRONTEND_ORIGIN;
            if (frontendOrigin) allowedOrigins.push(frontendOrigin);

            if (allowedOrigins.includes(origin)) {
                return cb(null, true);
            }
            // If no CORS_ORIGIN is set, we might want to default to false or log a warning.
            // For now, let's strictly fail if not matched.
            return cb(new Error("Not allowed by CORS"), false);
        }

        // Dev: Allow all
        return cb(null, true);
    }
});
// Enforce SESSION_SECRET in production
if (!process.env.SESSION_SECRET) {
    console.error('FATAL: SESSION_SECRET is required.');
    process.exit(1);
}

const isProduction = process.env.NODE_ENV === 'production';

fastify.register(fastifyHelmet, {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts (onclick, <script>)
            scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers (onclick)
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"], // Allow inline styles & Fonts
            fontSrc: ["'self'", "https://fonts.gstatic.com"], // Allow Google Fonts
            imgSrc: ["'self'", "data:"], // Allow QR Code (data:image/png)
            objectSrc: ["'none'"],
            baseUri: ["'none'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            connectSrc: ["'self'"], // Allow fetch to self
            upgradeInsecureRequests: null // Disable auto-upgrade to HTTPS (fixes localhost issue)
        }
    },
    // Disable HSTS in development to avoid HTTPS redirection on localhost
    // We send maxAge: 0 to clear any browser cache if it was previously set.
    hsts: isProduction ? true : { maxAge: 0 }
});

fastify.register(fastifyCookie, {
    secret: process.env.SESSION_SECRET,
    hook: 'onRequest',
    parseOptions: {
        httpOnly: true,
        // Secure cookie: Required for HTTPS. 
        // In dev (localhost), browsers treat it as secure context, but HSTS breaks http.
        // We set secure: true ONLY in production to avoid issues.
        secure: isProduction,
        sameSite: 'lax', // Relaxed for better compatibility during dev (Safari localhost issues)
        path: '/'
    }
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
    token: z.string().regex(/^[0-9]{6}$|^[a-zA-Z0-9-]{9,}$/, "Token inválido (Formato incorreto)"), // Regex Validation
});

// Helper: Create Session
// Standardizes session creation across all auth methods (TOTP, WebAuthn, Recovery)
async function createSession(reply: any, user: string, ip: string, userAgent: string, method: string) {
    const sessionId = crypto.randomUUID();
    const sessionKey = `session:${sessionId}`;

    // Store session in Redis
    await redis.set(sessionKey, JSON.stringify({ user, ip, userAgent, method, createdAt: new Date().toISOString() }), 'EX', 3600);

    // Set Cookie
    reply.setCookie('session', sessionId, {
        path: '/',
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        maxAge: 3600,
        signed: true
    });

    // Refresh User TTLs
    await redis.expire(`user:${user}`, USER_TTL);
    await redis.expire(`recovery:${user}`, USER_TTL);
    await redis.expire(`webauthn:credentials:${user}`, USER_TTL);

    return sessionId;
}

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

    // Only return the QRCode (which contains the secret) and Recovery Codes.
    // [HARDENING] In production, NEVER return secret/otpAuth unless explicitly allowed for debugging.
    // [FINAL REVIEW] Added Double-Lock: Must confirm knowledge of risk.

    const isDebugMode = process.env.ALLOW_DEBUG_SETUP_OUTPUT === 'true';
    const confirmsRisk = process.env.I_KNOW_WHAT_IM_DOING === 'true';
    const allowDebugOutput = isDebugMode && confirmsRisk;

    if (isProduction && !allowDebugOutput) {
        return {
            qrCode,
            recoveryCodes
        };
    }

    if (allowDebugOutput && isProduction) {
        logger.warn({ event: 'SECURITY_ALERT', message: 'Debug output enabled in PRODUCTION', meta: { user } });
    }

    // Dev mode OR Explicit Debug allowed
    return {
        secret,
        otpAuth: otpAuthKey,
        qrCode,
        recoveryCodes
    };
});

// [HARDENING] This endpoint is stateless and allows verifying a token if you know the secret.
// In production, secrets are stored securely in Redis and verified via /login.
// We disable this endpoint in production to prevent misuse, unless explicitly enabled for testing.
fastify.post('/verify', async (request, reply) => {
    const isDevVerify = process.env.ENABLE_DEV_VERIFY_ENDPOINT === 'true';
    const confirmsRisk = process.env.I_KNOW_WHAT_IM_DOING === 'true';
    const enableDevVerify = isDevVerify && confirmsRisk;

    if (isProduction && !enableDevVerify) {
        return reply.status(404).send({ error: 'Not Found', message: 'Endpoint disabled in production.' });
    }

    if (enableDevVerify && isProduction) {
        logger.warn({ event: 'SECURITY_ALERT', message: 'Verify endpoint enabled in PRODUCTION', meta: { user: (request.body as any)['user'] } });
    }

    const { token, secret, user } = request.body as any; // Frontend sends plain secret
    /* 
       Note: ideally we should fetch from Redis to ensure we verify against 
       what we stored, but for this simple setup flow, verifying against 
       the secret the client just received is acceptable for "did I scan it right?".
       
       However, to be robust, let's verify if the token matches the secret provided.
    */

    if (!token || !secret) {
        return reply.status(400).send({ success: false, message: 'Token e Segredo são obrigatórios.' });
    }

    const isValid = totpService.verifyToken(token, secret);

    if (isValid) {
        return { success: true, message: 'Código verificado com sucesso!' };
    } else {
        return reply.status(400).send({ success: false, message: 'Código inválido. Tente novamente.' });
    }
});

fastify.post('/login', async (request, reply) => {
    const { user, token } = LoginSchema.parse(request.body);
    const ip = request.ip;
    const userIdentifier = `${user}:${ip}`;
    const userAgent = request.headers['user-agent'] || 'unknown';

    // 0. Context Awareness (Simple Check)
    // Em produção, compararíamos com IPs passados do usuário
    logger.info({
        event: 'AUTH_ATTEMPT', // Tentativa, ainda não sucesso
        message: 'Login attempt',
        user, ip, userAgent
    });
    // console.log('[DEBUG] Login Request:', { user, tokenLength: token.length }); // [HARDENING] Removed debug log

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

            // [UPDATE] Create Session for Recovery Login too
            await createSession(reply, user, ip, userAgent, 'RECOVERY_CODE');

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
        // Constant Time Delay (Fake verification time)
        // Increased to 200ms to match other operations roughly
        await new Promise(resolve => setTimeout(resolve, 200));
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    let secret: string;
    try {
        secret = encryptionService.decrypt(userData.secret);
    } catch (e) {
        // Generic Error for decryption failure to avoid Oracle
        logger.error({ event: 'AUTH_FAIL', message: 'Internal decryption error', user });
        // Delay before return
        await new Promise(resolve => setTimeout(resolve, 200));
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    // 3. Validar Token TOTP
    const isValid = totpService.verifyToken(token, secret);
    if (!isValid) {
        logger.warn({ event: 'AUTH_FAIL', message: 'Invalid TOTP code', user, ip });
        // Delay before return
        await new Promise(resolve => setTimeout(resolve, 200));
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    // 4. Replay Check (Atomic User Step)
    // Pass just user ID, not the secret.
    // Logic: `replay:{user}:{step}`
    const isFresh = await securityService.checkReplay(user);
    if (!isFresh) {
        logger.warn({ event: 'REPLAY_ATTACK', message: 'Replay attack detected (Step Reuse)', user, ip });
        // Delay to match generic error time
        await new Promise(resolve => setTimeout(resolve, 200));
        return reply.status(401).send({ success: false, message: GENERIC_ERROR });
    }

    // Success - Create Secure Session (Standardized)
    await createSession(reply, user, ip, userAgent, 'TOTP_APP');

    logger.info({ event: 'AUTH_SUCCESS_TOTP', message: 'User authenticated successfully', user, ip }); // Changed event name for clarity
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
    const { user } = SetupSchema.parse(request.body);
    const ip = request.ip;

    // [UPDATE] Add Rate Limit for Register Challenge
    const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
    if (!ipLimit.allowed) {
        return reply.status(429).send({ success: false, message: 'Muitas tentativas (Register Challenge).' });
    }

    const options = await webauthnService.generateRegisterOptions(user);
    return options;
});

// 2. Register Verify
fastify.post('/webauthn/register/verify', async (request, reply) => {
    const { user, ...body } = request.body as any;
    const ip = request.ip;

    // [UPDATE] Add Rate Limit for Register Verify
    const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
    if (!ipLimit.allowed) {
        return reply.status(429).send({ success: false, message: 'Muitas tentativas (Register Verify).' });
    }

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
    const ip = request.ip;

    // Rate Limit for WebAuthn Challenge
    const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
    if (!ipLimit.allowed) {
        logger.warn({ event: 'RATE_LIMIT_IP', message: 'WebAuthn Challenge Rate limit', user, ip });
        return reply.status(429).send({ success: false, message: 'Muitas tentativas.' });
    }
    try {
        const options = await webauthnService.generateLoginOptions(user);
        return options;
    } catch (err: any) {
        // ... err handling
    }
});

// 4. Login Verify
fastify.post('/webauthn/login/verify', async (request, reply) => {
    const { user, ...body } = request.body as any;
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] || 'unknown';

    // Rate Limit for WebAuthn Verify
    // Check BOTH IP and User (to prevent brute force on a specific user's passkey)
    const ipLimit = await securityService.checkRateLimit(`ip:${ip}`);
    const userLimit = await securityService.checkRateLimit(`user:${user}`);

    if (!ipLimit.allowed || !userLimit.allowed) {
        logger.warn({ event: 'RATE_LIMIT_IP', message: 'WebAuthn Verify Rate limit', user, ip });
        return reply.status(429).send({ success: false, message: 'Muitas tentativas.' });
    }

    try {
        const success = await webauthnService.verifyLogin(user, body);
        if (success) {
            // [UPDATE] Create Session for WebAuthn Login
            await createSession(reply, user, ip, userAgent, 'WEBAUTHN_PASSKEY');

            logger.info({ event: 'AUTH_SUCCESS_WEBAUTHN', message: 'User authenticated via WebAuthn', user, ip });
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
        logger.info({ event: 'SYSTEM_START', message: 'Server running at http://localhost' });
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();
