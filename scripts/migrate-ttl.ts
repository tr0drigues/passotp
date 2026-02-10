
import redis from '../src/lib/redis.js';

// 50 days in seconds
const USER_TTL = 50 * 24 * 60 * 60;

async function migrate() {
    console.log('--- Starting TTL (Inactivity Expiration) Migration ---');
    console.log(`Target TTL: ${USER_TTL} seconds (50 days)`);

    let cursor = '0';
    let count = 0;

    // We need to scan for:
    // 1. user:*
    // 2. recovery:*
    // 3. webauthn:credentials:*

    const patterns = ['user:*', 'recovery:*', 'webauthn:credentials:*'];

    for (const pattern of patterns) {
        console.log(`\nScanning pattern: ${pattern}`);
        cursor = '0'; // Reset cursor for each pattern
        do {
            const result = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
            cursor = result[0];
            const keys = result[1];

            for (const key of keys) {
                // Check if key already has a TTL
                const ttl = await redis.ttl(key);

                // If TTL is -1 (persistent), set it. 
                // If it has a TTL, we can choose to update it to 50 days from now (refresh) 
                // or leave it. The requirement implies "apply the rule", so let's reset to 50 days.

                await redis.expire(key, USER_TTL);
                if (ttl === -1) {
                    console.log(`[SET TTL] ${key} (was persistent)`);
                } else {
                    console.log(`[REFRESH TTL] ${key} (was ${ttl}s)`);
                }
                count++;
            }

        } while (cursor !== '0');
    }

    console.log(`\n--- Migration Complete ---`);
    console.log(`Keys updated: ${count}`);
    process.exit(0);
}

migrate().catch(err => {
    console.error(err);
    process.exit(1);
});
