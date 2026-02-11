
import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import path from 'path';
import { fileURLToPath } from 'url';
import fastifyCookie from '@fastify/cookie';
import fastifyHelmet from '@fastify/helmet';
import { config } from './config.js';
import { logger } from './lib/logger.js';
import { setupRoutes } from './routes/setup.routes.js';
import { authRoutes } from './routes/auth.routes.js';
import { webauthnRoutes } from './routes/webauthn.routes.js';

// Setup paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fastify = Fastify({
    logger: false, // Using custom logger
    trustProxy: true // Trust Nginx proxy for IP rate limiting
});

// Plugins
fastify.register(cors, {
    origin: (origin, cb) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return cb(null, true);

        if (config.env.isProduction) {
            const { allowedOrigins, frontendOrigin } = config.security.cors;
            if (frontendOrigin) allowedOrigins.push(frontendOrigin);

            if (allowedOrigins.includes(origin)) {
                return cb(null, true);
            }

            // Debugging Production CORS
            console.error(`[CORS BLOCK] Blocked Origin: '${origin}'`);
            console.error(`[CORS BLOCK] Allowed Origins: ${JSON.stringify(allowedOrigins)}`);

            logger.warn({ event: 'CORS_BLOCK', message: 'Blocked request from unauthorized origin', meta: { origin, allowed: allowedOrigins } });
            return cb(new Error("Not allowed by CORS"), false);
        }

        // Dev: Allow all
        return cb(null, true);
    }
});

// Enforce SESSION_SECRET in production
if (!config.security.sessionSecret) {
    if (config.env.isProduction) {
        console.error('FATAL: SESSION_SECRET is required.');
        process.exit(1);
    } else {
        console.warn('⚠️  WARNING: SESSION_SECRET not found. Using insecure default for DEVELOPMENT only.');
    }
}

fastify.register(fastifyHelmet, {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:"],
            objectSrc: ["'none'"],
            baseUri: ["'none'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            connectSrc: ["'self'"],
            upgradeInsecureRequests: null
        }
    },
    // Disable HSTS in development to often avoid HTTPS redirection on localhost
    hsts: config.env.isProduction ? true : { maxAge: 0 }
});

fastify.register(fastifyCookie, {
    secret: config.security.sessionSecret || 'dev-secret-do-not-use-in-prod',
    hook: 'onRequest',
    parseOptions: {
        httpOnly: true,
        secure: config.env.isProduction,
        sameSite: 'lax',
        path: '/'
    }
});

fastify.register(fastifyStatic, {
    root: path.join(__dirname, '../public'),
    prefix: '/',
});

// Health Check
fastify.get('/health', async () => {
    return { status: 'ok' };
});

// Register Routes
fastify.register(setupRoutes);
fastify.register(authRoutes);
fastify.register(webauthnRoutes);

const start = async () => {
    try {
        await fastify.listen({ port: config.env.port, host: config.env.host });
        logger.info({ event: 'SYSTEM_START', message: `Server running at http://localhost:${config.env.port}` });
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();
