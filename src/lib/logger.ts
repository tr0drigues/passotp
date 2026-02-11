
export type LogLevel = 'info' | 'warn' | 'error' | 'fatal';

// Standardized Security Events
export type SecurityEvent =
    | 'AUTH_ATTEMPT'
    | 'AUTH_SUCCESS'
    | 'AUTH_SUCCESS_TOTP'
    | 'AUTH_SUCCESS_WEBAUTHN'
    | 'AUTH_FAIL'
    | 'RATE_LIMIT_IP'
    | 'RATE_LIMIT_USER'
    | 'REPLAY_ATTACK'
    | 'SETUP_INIT'
    | 'SETUP_COMPLETE'
    | 'RECOVERY_USE'
    | 'SYSTEM_START'
    | 'SECURITY_ALERT'
    | 'CORS_BLOCK';

interface LogPayload {
    event: SecurityEvent;
    user?: string;
    ip?: string;
    userAgent?: string;
    message: string;
    meta?: Record<string, any> & { banExpires?: number };
}

class SecurityLogger {
    private log(level: LogLevel, payload: LogPayload) {
        const entry = {
            timestamp: new Date().toISOString(),
            level,
            ...payload
        };
        // In production, log aggregation tools (Datadog, Splunk) capture stdout.
        console.log(JSON.stringify(entry));
    }

    info(payload: LogPayload) { this.log('info', payload); }
    warn(payload: LogPayload) { this.log('warn', payload); }
    error(payload: LogPayload) { this.log('error', payload); }
    fatal(payload: LogPayload) { this.log('fatal', payload); }
}

export const logger = new SecurityLogger();
