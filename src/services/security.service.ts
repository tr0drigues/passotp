
import redis from '../lib/redis.js';
import { authenticator } from 'otplib';

export class SecurityService {
    /**
     * Verifica Rate Limit (Tentativas de Login/Validação)
     * Janela de tempo: 5 minutos
     * Limite: 5 tentativas
     * Retorna true se estiver permitido, false se bloqueado
     */
    /**
     * Verifica Rate Limit (Tentativas de Login/Validação)
     * Janela de tempo: 5 minutos
     * Limite: 5 tentativas
     * Retorna true se estiver permitido, false se bloqueado
     */
    async checkRateLimit(identifier: string, limit: number = 5, windowSeconds: number = 300): Promise<{ allowed: boolean; banExpires?: number }> {
        const key = `ratelimit:${identifier}`;

        // Check if currently banned
        const banKey = `ban:${identifier}`;
        const banTTL = await redis.ttl(banKey);
        if (banTTL > 0) {
            return { allowed: false, banExpires: banTTL };
        }

        const current = await redis.incr(key);

        if (current === 1) {
            await redis.expire(key, windowSeconds);
        }

        if (current > limit) {
            // Exponential Backoff: Ban time increases with excess attempts
            // 1st excess: 30s, 2nd: 60s, 3rd: 120s... max 1 hour.
            const excess = current - limit;
            const power = Math.min(excess, 7); // Cap at 2^7 * 30s = 3840s (~1h)
            const banTime = 30 * Math.pow(2, power - 1);

            await redis.set(banKey, 'banned', 'EX', banTime);
            return { allowed: false, banExpires: banTime };
        }

        return { allowed: true };
    }

    /**
     * Prevenção de Replay Attack (Refatorado)
     * Utiliza ID do usuário + Time Step para chave de controle.
     * Chave: `replay:{userId}:{step}`
     * Atomicidade: SET ... NX EX 60
     */
    async checkReplay(userId: string): Promise<boolean> {
        // Calculate current step (30s window)
        const step = Math.floor(Date.now() / 1000 / 30);
        const key = `replay:${userId}:${step}`;

        // Attempt to set key. If it exists (0), it fails (returns null/0).
        // 60s TTL to ensure it covers the window + skew.
        const result = await redis.set(key, '1', 'EX', 60, 'NX');

        return result === 'OK';
    }
}

export const securityService = new SecurityService();

