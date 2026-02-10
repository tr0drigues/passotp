
import { totpService } from './src/services/totp.service.js';

async function runTest() {
    const baseUrl = 'http://localhost:3000';
    const user = 'test-user-' + Date.now();

    console.log('--- Iniciando Testes de Verificação ---');

    // 1. Setup
    console.log('\n[1] Testando /setup...');
    const setupRes = await fetch(`${baseUrl}/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user })
    });
    const setupData = await setupRes.json();

    if (!setupData.secret) {
        console.error('❌ Falha no setup:', setupData);
        process.exit(1);
    }
    console.log('✅ Setup OK. Secret:', setupData.secret);
    const secret = setupData.secret;

    // 2. Generating Valid Token Locally
    const token = import('otplib').then(m => m.authenticator.generate(secret));
    const validToken = (await token);
    console.log('🔑 Gerado token válido localmente:', validToken);

    // 3. Verify Success
    console.log('\n[2] Testando validação com sucesso...');
    const verifyRes = await fetch(`${baseUrl}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            token: validToken,
            secret,
            user
        })
    });
    const verifyData = await verifyRes.json();
    if (verifyData.success) {
        console.log('✅ Validação OK');
    } else {
        console.error('❌ Falha na validação:', verifyData);
    }

    // 4. Verify Replay Attack (Mesmo token)
    console.log('\n[3] Testando Replay Attack (mesmo token)...');
    const replayRes = await fetch(`${baseUrl}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            token: validToken,
            secret,
            user
        })
    });
    const replayData = await replayRes.json();
    if (!replayData.success && replayData.message.includes('já foi utilizado')) {
        console.log('✅ Replay bloqueado corretamente');
    } else {
        console.error('❌ Replay não foi bloqueado!', replayData);
    }

    // 5. Verify Rate Limit
    console.log('\n[4] Testando Rate Limit (5 tentativas falhas)...');
    for (let i = 0; i < 6; i++) {
        const res = await fetch(`${baseUrl}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                token: '000000', // Inválido
                secret,
                user
            })
        });
        const data = await res.json();
        console.log(`Tentativa ${i + 1}: status ${res.status} - ${data.message}`);

        if (res.status === 429) {
            console.log('✅ Rate limit atingido e bloqueado com sucesso!');
            break;
        }
    }
}

// Pequeno delay para garantir que o server subiu
setTimeout(runTest, 2000);
