
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import path from 'path';
import { fileURLToPath } from 'url';
import { z } from 'zod';
import { totpService } from './services/totp.service.js';
import { securityService } from './services/security.service.js';
import redis from './lib/redis.js';

// Setup paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fastify = Fastify({ logger: true });

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

const VerifySchema = z.object({
    token: z.string().length(6),
    secret: z.string().min(10).optional(), // Opcional no login, obrigatório no teste manual
    user: z.string().min(3),
});

const LoginSchema = z.object({
    user: z.string().min(3),
    token: z.string().length(6),
});

// Routes
fastify.post('/setup', async (request, reply) => {
    const { user } = SetupSchema.parse(request.body);

    // 1. Gerar Segredo
    const secret = totpService.generateSecret();

    // 2. Gerar Key URI
    const otpAuthKey = totpService.getOtpAuthKey(user, secret);

    // 3. Gerar QR Code
    const qrCode = await totpService.generateQRCode(otpAuthKey);

    // 4. Salvar Segredo no Redis (Persistência)
    // Chave: user:{email}, Campo: secret
    await redis.hset(`user:${user}`, { secret });

    return { secret, qrCode };
});

fastify.post('/login', async (request, reply) => {
    const { user, token } = LoginSchema.parse(request.body);
    const ip = request.ip;
    const userIdentifier = `${user}:${ip}`;

    // 1. Check Rate Limit
    const allowed = await securityService.checkRateLimit(userIdentifier);
    if (!allowed) {
        return reply.status(429).send({
            success: false,
            message: 'Muitas tentativas. Tente novamente em alguns minutos.'
        });
    }

    // 2. Buscar Segredo do Usuário
    const userData = await redis.hgetall(`user:${user}`);
    if (!userData || !userData.secret) {
        return reply.status(404).send({
            success: false,
            message: 'Usuário não encontrado ou 2FA não configurado.'
        });
    }
    const secret = userData.secret;

    // 3. Validar Token
    const isValid = totpService.verifyToken(token, secret);
    if (!isValid) {
        return reply.status(401).send({
            success: false,
            message: 'Código inválido.'
        });
    }

    // 4. Replay Check
    const isFresh = await securityService.checkReplay(secret, token);
    if (!isFresh) {
        return reply.status(401).send({
            success: false,
            message: 'Este código já foi utilizado.'
        });
    }

    return { success: true, message: 'Login realizado com sucesso!' };
});

fastify.post('/verify', async (request, reply) => {
    const { token, secret, user } = VerifySchema.parse(request.body);
    const ip = request.ip;
    const userIdentifier = `${user}:${ip}`; // Rate limit por usuário+IP

    // 1. Check Rate Limit (Bloqueia Brute Force)
    const allowed = await securityService.checkRateLimit(userIdentifier);
    if (!allowed) {
        return reply.status(429).send({
            success: false,
            message: 'Muitas tentativas. Tente novamente em alguns minutos.'
        });
    }

    // 2. Verifica Validade Matemática do Token
    const isValid = totpService.verifyToken(token, secret);
    if (!isValid) {
        return reply.status(401).send({
            success: false,
            message: 'Código inválido.'
        });
    }

    // 3. Check Replay Attack (Impede reuso do mesmo token na mesma janela)
    const isFresh = await securityService.checkReplay(secret, token);
    if (!isFresh) {
        return reply.status(401).send({
            success: false,
            message: 'Este código já foi utilizado.'
        });
    }

    return { success: true, message: 'Autenticado com sucesso!' };
});

// Start
const start = async () => {
    try {
        await fastify.listen({ port: 3000, host: '0.0.0.0' });
        console.log('Server running at http://localhost:3000');
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();
