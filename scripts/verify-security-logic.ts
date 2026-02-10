
import { encryptionService } from '../src/services/encryption.service.js';
import { securityService } from '../src/services/security.service.js';
import { totpService } from '../src/services/totp.service.js';
import redis from '../src/lib/redis.js';

async function main() {
    console.log('--- Verifying Security Logic ---');

    // 1. Encryption
    console.log('\n1. Testing Encryption Service...');
    const original = 'my-super-secret-key';
    const encrypted = encryptionService.encrypt(original);
    const decrypted = encryptionService.decrypt(encrypted);

    console.log('Original:', original);
    console.log('Encrypted:', encrypted);
    console.log('Decrypted:', decrypted);

    if (original === decrypted && original !== encrypted) {
        console.log('✅ Encryption verification passed');
    } else {
        console.error('❌ Encryption verification failed');
        process.exit(1);
    }

    // 2. Replay Protection
    console.log('\n2. Testing Replay Protection...');
    const secret = totpService.generateSecret();
    const token = '123456'; // Fake token

    const isFresh1 = await securityService.checkReplay(secret, token);
    console.log('First use (should be true):', isFresh1);

    const isFresh2 = await securityService.checkReplay(secret, token);
    console.log('Second use (should be false):', isFresh2);

    if (isFresh1 === true && isFresh2 === false) {
        console.log('✅ Replay protection verification passed');
    } else {
        console.error('❌ Replay protection verification failed');
        process.exit(1);
    }

    // Cleanup
    const step = Math.floor(Date.now() / 1000 / 30);
    await redis.del(`replay:${secret}:${step}`);

    console.log('\n🎉 All checks passed!');
    process.exit(0);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
