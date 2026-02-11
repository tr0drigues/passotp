
import { spawn } from 'child_process';
import fetch from 'node-fetch';

async function run() {
    console.log('--- Testing Robust CORS ---');

    // Simulate "messy" env var with spaces
    const MESSY_CORS_ENV = ' http://localhost:3002 , http://127.0.0.1:3002 ';

    // Start Server
    const server = spawn('npx', ['tsx', 'src/server.ts'], {
        env: {
            ...process.env,
            NODE_ENV: 'production',
            PORT: '3002',
            SESSION_SECRET: 'prod-secret-must-be-long-enough-123',
            ENCRYPTION_KEY: '0'.repeat(64),
            CORS_ORIGIN: MESSY_CORS_ENV
        },
        stdio: 'inherit',
        detached: false
    });

    await new Promise(resolve => setTimeout(resolve, 3000));

    try {
        console.log(`\n1. Testing Origin: 'http://localhost:3002' (Should pass despite env spaces)`);
        const res = await fetch('http://localhost:3002/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Origin': 'http://localhost:3002'
            },
            body: JSON.stringify({ user: 'cors-test' })
        });

        if (res.ok) {
            console.log('✅ Success! Robust trimming working.');
        } else {
            console.error('❌ Failed! Status:', res.status);
        }

    } catch (err: any) {
        console.error('❌ Request failed:', err.message);
    } finally {
        server.kill();
        process.exit(0);
    }
}

run();
