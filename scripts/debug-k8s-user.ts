
import 'dotenv/config';
import { Redis } from 'ioredis';
import { EncryptionService } from '../src/services/encryption.service.js';
import { authenticator } from 'otplib';

// MOCK CONFIG for EncryptionService to work
// We will modify the prototype or just instantiate a new one with the key?
// efficient way: set process.env.ENCRYPTION_KEY before importing, but import is cached.
// We will assume the script is run with ENCRYPTION_KEY=... tsx scripts/debug-prod-user.ts

const redis = new Redis({
    host: 'localhost',
    port: 6379
});

async function main() {
    const user = 'thiago.720@gmail.com';
    console.log(`Checking user: ${user}`);

    // 1. Fetch from Redis
    const userData = await redis.hgetall(`user:${user}`);
    console.log('Redis Data:', userData);

    if (!userData || !userData.secret) {
        console.error('User not found or no secret.');
        process.exit(1);
    }

    // 2. Decrypt
    // We need to use the EncryptionService logic. 
    // Since we can't easily inject the key into the imported singleton efficiently without env vars,
    // let's replicate the decrypt logic here or ensure we run this script with correct ENV.

    // We will use the imported service, assuming the process.env was set correctly before running.
    // However, EncryptionService reads config on import. 
    // So we will instantiate a fresh logic here to be 100% sure what we are doing.

    const crypto = await import('crypto');

    const KEY = process.env.ENCRYPTION_KEY!;
    console.log(`Using Key (len=${KEY?.length}): ${KEY}`);

    const decrypt = (text: string) => {
        const SAFE_KEY = KEY;
        const ALGORITHM = 'aes-256-gcm';

        const parts = text.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encryptedText = parts[2];

        let masterKey: Buffer;
        if (SAFE_KEY.length === 64) {
            masterKey = Buffer.from(SAFE_KEY, 'hex');
        } else {
            masterKey = crypto.createHash('sha256').update(SAFE_KEY).digest();
        }

        const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    };

    let secret;
    try {
        secret = decrypt(userData.secret);
        console.log('Decrypted Secret (Base32):', secret);
    } catch (e) {
        console.error('Decryption Failed!', e);
        process.exit(1);
    }

    // 3. Generate TOTP
    const token = authenticator.generate(secret);
    console.log('------------------------------------------------');
    console.log(`Current Server Time: ${new Date().toISOString()}`);
    console.log(`Generated TOTP Token: ${token}`);
    console.log('------------------------------------------------');

    // 4. Check Window
    const isValid = authenticator.check(token, secret);
    console.log(`Is Valid (window 0): ${isValid}`);

    redis.disconnect();
}

main();
