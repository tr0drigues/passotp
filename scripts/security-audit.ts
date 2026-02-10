
import { chromium } from 'playwright';
import { authenticator } from 'otplib';

// Configurações
const BASE_URL = 'http://localhost:3000';
const ATTACKER_USER = `attacker-${Date.now()}@evil.com`;

async function main() {
    console.log('🔒 INICIANDO AUDITORIA DE SEGURANÇA (OWASP TOP 10 - AUTHENTICATION)\n');

    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();

    // --- PREPARAÇÃO: CRIAR CONTA LEGÍTIMA ---
    console.log('[SETUP] Criando conta alvo...');
    await page.goto(`${BASE_URL}/`);
    await page.fill('#username', ATTACKER_USER);
    await page.click('#btnSetup');

    // Aguardar QR code aparecer
    await page.waitForSelector('#qrImage', { state: 'visible' });
    const secret = await page.textContent('#secretText');
    console.log(`[SETUP] Alvo criado. User: ${ATTACKER_USER}, Secret: ${secret}\n`);

    if (!secret) throw new Error("Falha ao obter segredo");

    // --- CENÁRIO 1: BRUTE FORCE ATTACK ---
    console.log('⚔️  TESTE 1: BRUTE FORCE (RATE LIMITING)');
    console.log('    Tentativa de quebrar a senha testando múltiplos códigos errados...');

    let blocked = false;
    for (let i = 1; i <= 8; i++) {
        // Tenta validar direto na API de login para ser mais rápido
        const res = await context.request.post(`${BASE_URL}/login`, {
            data: { user: ATTACKER_USER, token: '000000' }
        });

        if (res.status() === 429) {
            console.log(`    ✅ Bloqueado na tentativa ${i} com HTTP 429 (Too Many Requests)`);
            blocked = true;
            break;
        } else {
            process.stdout.write('.');
        }
    }

    if (!blocked) {
        console.error('    ❌ FALHA CRÍTICA: Rate Limit não ativado após 8 tentativas!');
    } else {
        console.log('    🛡️  Proteção de Rate Limit: OK');
    }

    // Esperar o rate limit expirar (simulado, restartando contexto ou mudando IP se possível, 
    // mas aqui vamos apenas criar um NOVO usuário para o próximo teste para não esperar 5 min)

    console.log('\n[SETUP] Criando novo usuário para teste de Replay...');
    const REPLAY_USER = `replay-${Date.now()}@test.com`;
    await page.goto(`${BASE_URL}/`);
    await page.fill('#username', REPLAY_USER);
    await page.click('#btnSetup');
    await page.waitForSelector('#qrImage');
    const replaySecret = (await page.textContent('#secretText')) || '';

    // --- CENÁRIO 2: REPLAY ATTACK ---
    console.log('\n⚔️  TESTE 2: REPLAY ATTACK (IDEMPOTÊNCIA)');
    // Gerar token válido
    const validToken = authenticator.generate(replaySecret);

    // Uso 1: Login Legítimo
    const res1 = await context.request.post(`${BASE_URL}/login`, {
        data: { user: REPLAY_USER, token: validToken }
    });
    console.log(`    Token ${validToken} usado 1ª vez: HTTP ${res1.status()}`);

    // Uso 2: Atacante interceptou e tenta usar de novo
    const res2 = await context.request.post(`${BASE_URL}/login`, {
        data: { user: REPLAY_USER, token: validToken }
    });
    console.log(`    Token ${validToken} usado 2ª vez: HTTP ${res2.status()}`);

    if (res1.status() === 200 && res2.status() === 401) {
        console.log('    🛡️  Proteção de Replay: OK (Token duplicado recusado)');
    } else {
        console.error('    ❌ FALHA CRÍTICA: Token reutilizado com sucesso ou primeiro falhou!');
    }

    // --- CENÁRIO 3: NOSQL INJECTION ---
    console.log('\n⚔️  TESTE 3: INPUT INJECTION (NOSQL/REDIS)');
    // Tentar injetar comandos Redis ou quebrar a chave
    const maliciousUser = `user:${REPLAY_USER}`;
    const res3 = await context.request.post(`${BASE_URL}/login`, {
        data: { user: maliciousUser, token: '123456' }
    });

    // Esperamos que o sistema trate isso como string literal e apenas não ache o usuário
    // Se o servidor crashar ou retornar 500, falhou.
    if (res3.status() === 500) {
        console.error('    ❌ FALHA: Servidor crashou com input malicioso');
    } else {
        console.log(`    Input "${maliciousUser}" tratado como: HTTP ${res3.status()} (Esperado 404/401/429)`);
        console.log('    🛡️  Proteção de Input: OK (Sem crash)');
    }

    await browser.close();
    console.log('\n🔒 AUDITORIA CONCLUÍDA.');
}

main().catch(console.error);
