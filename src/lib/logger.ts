
export type LogLevel = 'info' | 'warn' | 'error' | 'fatal';
export type SecurityEvent = 'AUTH_SUCCESS' | 'AUTH_FAIL' | 'SETUP_INIT' | 'SETUP_COMPLETE' | 'RATE_LIMIT' | 'REPLAY_ATTACK' | 'RECOVERY_USE' | 'NEW_DEVICE' | 'SYSTEM_START';

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
        // Em produção, isso iria para stdout para ser coletado por Datadog/Splunk
        // Para dev, console.log é suficiente
        console.log(JSON.stringify(entry));
    }

    info(payload: LogPayload) { this.log('info', payload); }
    warn(payload: LogPayload) { this.log('warn', payload); }
    error(payload: LogPayload) { this.log('error', payload); }
    fatal(payload: LogPayload) { this.log('fatal', payload); }
}

export const logger = new SecurityLogger();
