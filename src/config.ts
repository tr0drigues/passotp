import 'dotenv/config';

const isProduction = process.env.NODE_ENV === 'production';

export const config = {
    env: {
        isProduction,
        port: Number(process.env.PORT) || 3000,
        host: '0.0.0.0',
    },

    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: Number(process.env.REDIS_PORT) || 6379,
        ttl: {
            user: 50 * 24 * 60 * 60, // 50 days
            session: 3600, // 1 hour
            temp: 60, // 60 seconds (challenges/replay)
        }
    },

    security: {
        sessionSecret: process.env.SESSION_SECRET,
        encryptionKey: process.env.ENCRYPTION_KEY,
        allowDebugSetup: process.env.ALLOW_DEBUG_SETUP_OUTPUT === 'true',
        enableDevVerify: process.env.ENABLE_DEV_VERIFY_ENDPOINT === 'true',
        confirmsRisk: process.env.I_KNOW_WHAT_IM_DOING === 'true',
        cors: {
            allowedOrigins: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(o => o.trim()) : [],
            frontendOrigin: process.env.FRONTEND_ORIGIN
        }
    },

    webauthn: {
        rpId: process.env.WEBAUTHN_RP_ID || 'localhost',
        rpName: process.env.WEBAUTHN_RP_NAME || 'PassOTP',
        origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost',
        // Default to strict UV in production unless explicitly overridden
        requireUv: process.env.WEBAUTHN_REQUIRE_UV !== undefined
            ? process.env.WEBAUTHN_REQUIRE_UV === 'true'
            : isProduction,
    }
};
