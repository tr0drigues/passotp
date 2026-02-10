
import redis from '../lib/redis.js';

export class SecurityService {
    /**
     * Verifica Rate Limit (Tentativas de Login/Validação)
     * Janela de tempo: 5 minutos
     * Limite: 5 tentativas
     * Retorna true se estiver permitido, false se bloqueado
     */
    async checkRateLimit(ipOrUser: string, limit: number = 5, windowSeconds: number = 300): Promise<boolean> {
        const key = `ratelimit:${ipOrUser}`;

        // Incrementa contador
        const current = await redis.incr(key);

        // Se for a primeira vez, define expiração
        if (current === 1) {
            await redis.expire(key, windowSeconds);
        }

        return current <= limit;
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

