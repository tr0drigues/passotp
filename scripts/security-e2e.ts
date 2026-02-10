
import { authenticator } from 'otplib';
import redis from '../src/lib/redis.js';

// Configuration
const API_URL = 'http://localhost:3000';
const USER = `test-sec-${Date.now()}`;

async function main() {
    console.log(`Starting E2E Security Check for user: ${USER}`);

    // 1. SETUP
    console.log('\n--- 1. Setup ---');
    const setupRes = await fetch(`${API_URL}/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: USER })
    });

    if (!setupRes.ok) throw new Error(`Setup failed: ${setupRes.status}`);
    const setupData = await setupRes.json();
    const { secret } = setupData;
    console.log('✅ Setup successful. Secret received:', secret);

    // 2. VERIFY ENCRYPTION IN REDIS
    console.log('\n--- 2. Verify Encryption ---');
    const redisData = await redis.hgetall(`user:${USER}`);
    const storedSecret = redisData.secret;
    console.log('Stored Secret in Redis:', storedSecret);

    if (storedSecret === secret) {
        console.error('❌ FAILURE: Secret is stored in PLAIN TEXT!');
        process.exit(1);
    }
    if (!storedSecret.includes(':')) {
        console.error('❌ FAILURE: Secret does not look encrypted (no IV:Tag:Cipher format)!');
        process.exit(1);
    }
    console.log('✅ Secret is encrypted in Redis.');

    // 3. GENERATE TOTP
    const token = authenticator.generate(secret);
    console.log(`\n--- 3. Login with Token: ${token} ---`);

    // 4. LOGIN (Valid)
    const loginRes = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: USER, token })
    });

    if (loginRes.status !== 200) {
        console.error(`❌ Login failed: ${loginRes.status}`);
        const err = await loginRes.json();
        console.error(err);
        process.exit(1);
    }

    const cookie = loginRes.headers.get('set-cookie');
    console.log('Set-Cookie Header:', cookie);

    if (!cookie || !cookie.includes('session=') || !cookie.includes('HttpOnly')) {
        console.error('❌ FAILURE: Session cookie not set or not HttpOnly!');
        process.exit(1);
    }
    console.log('✅ Login successful & Session Cookie received.');

    // 5. REPLAY ATTACK (Same Token)
    console.log('\n--- 5. Replay Attack Test ---');
    const replayRes = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: USER, token })
    });

    const replayData = await replayRes.json();
    console.log('Replay Result:', replayRes.status, replayData);

    if (replayRes.status !== 401 || !replayData.message.includes('Credenciais inválidas')) {
        console.error('❌ FAILURE: Replay did not return generic 401 error!');
        process.exit(1);
    }
    console.log('✅ Replay blocked with generic error.');

    // 6. ACCOUNT ENUMERATION - INVALID USER
    console.log('\n--- 6. Enumeration: Invalid user ---');
    const enumRes = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: 'non-existent-user-123', token: '123456' })
    });
    const enumData = await enumRes.json();
    console.log('Invalid User Result:', enumRes.status, enumData);

    if (enumRes.status !== 401 || !enumData.message.includes('Credenciais inválidas')) {
        console.error('❌ FAILURE: Invalid user did not return generic 401 error!');
        process.exit(1);
    }
    console.log('✅ Invalid user returned generic error.');

    // 7. WEBAUTHN ENUMERATION
    console.log('\n--- 7. WebAuthn Enumeration ---');
    const waRes = await fetch(`${API_URL}/webauthn/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: 'non-existent-user-123' })
    });
    const waData = await waRes.json();
    console.log('WebAuthn Challenge Result:', waRes.status, waData);

    // Check for explicit "Nenhuma Passkey encontrada" (Bad) vs "Não foi possível iniciar" (Good)
    if (waData.message && waData.message.includes('Nenhuma Passkey')) {
        console.error('❌ FAILURE: WebAuthn reveals user existence!');
        process.exit(1);
    }
    console.log('✅ WebAuthn returned generic error.');

    console.log('\n🎉 ALL SECURITY CHECKS PASSED!');
    process.exit(0);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
