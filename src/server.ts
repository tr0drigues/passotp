
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

// Setup paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fastify = Fastify({
    logger: false // Disable default logger to use custom JSON logger
});

// Plugins
fastify.register(cors);
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

    // 5. Salvar Segredo no Redis
    await redis.hset(`user:${user}`, { secret });

    // 6. Salvar Recovery Codes (Hashed)
    await recoveryService.saveRecoveryCodes(user, recoveryCodes);

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

    // 1. Check Rate Limit
    const { allowed, banExpires } = await securityService.checkRateLimit(userIdentifier);
    if (!allowed) {
        logger.warn({ event: 'RATE_LIMIT', message: 'Rate limit exceeded', user, ip, meta: { banExpires } });
        return reply.status(429).send({
            success: false,
            message: `Muitas tentativas. Tente novamente em ${Math.ceil(banExpires!)} segundos.`
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
    if (!userData || !userData.secret) {
        logger.error({ event: 'AUTH_FAIL', message: 'User not found', user, ip });
        return reply.status(404).send({
            success: false,
            message: 'Usuário não encontrado ou 2FA não configurado.'
        });
    }
    const secret = userData.secret;

    // 3. Validar Token TOTP
    const isValid = totpService.verifyToken(token, secret);
    if (!isValid) {
        logger.warn({ event: 'AUTH_FAIL', message: 'Invalid TOTP code', user, ip });
        return reply.status(401).send({
            success: false,
            message: 'Código inválido.'
        });
    }

    // 4. Replay Check
    const isFresh = await securityService.checkReplay(secret, token);
    if (!isFresh) {
        logger.warn({ event: 'REPLAY_ATTACK', message: 'Replay attack detected', user, ip });
        return reply.status(401).send({
            success: false,
            message: 'Este código já foi utilizado.'
        });
    }

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
        // Se usuário não tiver passkeys, retornamos 400 para o frontend saber e dar msg amigável
        reply.status(400);
        return { success: false, message: 'Nenhuma Passkey encontrada para este usuário.' };
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
