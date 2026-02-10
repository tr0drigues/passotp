
import redis from '../src/lib/redis.js';
import { encryptionService } from '../src/services/encryption.service.js';

async function migrate() {
    console.log('--- Starting Encryption Migration ---');

    let cursor = '0';
    let migratedCount = 0;
    let skippedCount = 0;

    do {
        const result = await redis.scan(cursor, 'MATCH', 'user:*', 'COUNT', 100);
        cursor = result[0];
        const keys = result[1];

        for (const key of keys) {
            const userData = await redis.hgetall(key);
            if (!userData || !userData.secret) continue;

            const secret = userData.secret;

            // Simple check: Encrypted secrets are in format iv:tag:cipher (hex strings)
            // IV is 16 bytes (32 hex chars), Tag is 16 bytes (32 hex chars)
            // Pattern: ^[a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]+$
            const isEncrypted = /^[a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]+$/.test(secret);

            if (isEncrypted) {
                console.log(`[SKIP] ${key} is already encrypted.`);
                skippedCount++;
            } else {
                console.log(`[MIGRATE] Encrypting secret for ${key}...`);
                try {
                    const encrypted = encryptionService.encrypt(secret);
                    await redis.hset(key, { secret: encrypted });
                    migratedCount++;
                } catch (err) {
                    console.error(`[ERROR] Failed to encrypt ${key}:`, err);
                }
            }
        }

    } while (cursor !== '0');

    console.log('\n--- Migration Complete ---');
    console.log(`Migrated: ${migratedCount}`);
    console.log(`Skipped (Already Encrypted): ${skippedCount}`);
    process.exit(0);
}

migrate().catch(err => {
    console.error(err);
    process.exit(1);
});
