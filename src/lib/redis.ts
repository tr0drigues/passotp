
import Redis from 'ioredis';

// Conexão com Redis
// Em produção, usar process.env.REDIS_URL
const redis = new Redis({
    host: 'localhost',
    port: 6379,
    retryStrategy: (times) => {
        // Retry indefinidamente com delay crescente até 2s
        const delay = Math.min(times * 50, 2000);
        return delay;
    },
});

redis.on('error', (err) => {
    console.error('Redis Error:', err);
});

redis.on('connect', () => {
    console.log('Redis Connected');
});

export default redis;
