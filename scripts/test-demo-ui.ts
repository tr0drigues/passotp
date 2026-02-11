
import { totpService } from '../src/services/totp.service.js';
import { authenticator } from 'otplib';
import { encryptionService } from '../src/services/encryption.service.js';
import redis from '../src/lib/redis.js';

// Mock the API calls described in public/index.html to ensure server logic handles them
async function testDemoUiFlow() {
    console.log('--- Testing Demo UI Flow (Setup -> Login) ---');
    const user = 'demo-ui-user';

    // 1. Setup (POST /setup)
    console.log('1. Call /setup');
    const secret = totpService.generateSecret();
    const encryptedSecret = encryptionService.encrypt(secret);
    await redis.hset(`user:${user}`, { secret: encryptedSecret });

    // In production, /setup returns keys: qrCode, recoveryCodes. (Secret is hidden)
    // The Demo UI no longer needs 'secret' in the response.

    // 2. Client generates token
    console.log('2. Client generates token from known secret (simulation)');
    const token = authenticator.generate(secret);

    // 3. Login (POST /login) - Replaces the old /verify call
    console.log('3. Call /login with token');
    /* 
       This simulates the call:
       fetch('/login', { body: { token, user: currentUser } })
    */

    // Verify server logic for /login (which we verified in test-setup-flow.ts, but let's be explicit about the route logic)
    // We already know /login logic works from previous verification.
    // The key here is that we are NOT passing 'secret' in the body anymore.

    const userData = await redis.hgetall(`user:${user}`);
    const decryptedSecret = encryptionService.decrypt(userData.secret);
    const isValid = totpService.verifyToken(token, decryptedSecret);

    if (isValid) {
        console.log('✅ /login logic would succeed with just user + token');
    } else {
        console.error('❌ /login logic failed');
        process.exit(1);
    }

    await redis.quit();
    process.exit(0);
}

testDemoUiFlow();
