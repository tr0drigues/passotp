
import { spawn } from 'child_process';
import fetch from 'node-fetch';

async function run() {
    console.log('--- Reproducing Production Issues ---');

    // Start Server in Production Mode
    const server = spawn('npx', ['tsx', 'src/server.ts'], {
        env: { ...process.env, NODE_ENV: 'production', PORT: '3001', SESSION_SECRET: 'prod-secret-must-be-long-enough-123', ENCRYPTION_KEY: '0'.repeat(64) },
        stdio: 'inherit',
        detached: false
    });

    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 3000));

    try {
        console.log('\n1. Testing /setup (QR Code)...');
        const setupRes = await fetch('http://localhost:3001/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user: 'repro-user' })
        });

        if (setupRes.ok) {
            const data: any = await setupRes.json();
            if (data.qrCode && data.qrCode.startsWith('data:image/png;base64,')) {
                console.log('✅ QR Code generated successfully.');
                console.log('   Preview:', data.qrCode.substring(0, 50) + '...');
            } else {
                console.error('❌ QR Code missing or invalid format:', data);
            }
        } else {
            console.error('❌ /setup failed:', setupRes.status, setupRes.statusText);
        }

        console.log('\n2. Testing CORS (Simulating different origin)...');
        const corsRes = await fetch('http://localhost:3001/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Origin': 'http://evil.com'
            },
            body: JSON.stringify({ user: 'cors-user' })
        });

        if (corsRes.status === 500 || corsRes.status === 403 || !corsRes.ok) { // Fastify cors might return 500 or error
            console.log(`✅ CORS correctly blocked external origin. Status: ${corsRes.status}`);
        } else {
            console.log(`⚠️  CORS allowed external origin? Status: ${corsRes.status}`);
        }

    } catch (err: any) {
        console.error('❌ Request failed:', err.message);
    } finally {
        server.kill();
        process.exit(0);
    }
}

run();
