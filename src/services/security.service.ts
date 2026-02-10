
import redis from '../lib/redis.js';

export class SecurityService {
    /**
     * Verifica Rate Limit (Tentativas de Login/Validação)
     * Janela de tempo: 5 minutos
     * Limite: 5 tentativas
     * Retorna true se estiver permitido, false se bloqueado
     */
    async checkRateLimit(ipOrUser: string, limit: number = 5, windowSeconds: number = 300): Promise<{ allowed: boolean; banExpires?: number }> {
        const key = `ratelimit:${ipOrUser}`;

        // Check if currently banned
        const banKey = `ban:${ipOrUser}`;
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
     * Prevenção de Replay Attack
     * Armazena o token usado no Redis com TTL igual à janela do TOTP (30s)
     * Retorna true se o token validou e NÃO foi usado antes.
     * Retorna false se o token já foi usado.
     */
    async checkReplay(secret: string, token: string): Promise<boolean> {
        const key = `replay:${secret}:${token}`;

        // Tenta setar a chave apenas se não existir (NX)
        // Expira em 30s (janela padrão do TOTP) + margem de segurança (totais 60s)
        const result = await redis.set(key, '1', 'EX', 60, 'NX');

        return result === 'OK';
    }
}

export const securityService = new SecurityService();

