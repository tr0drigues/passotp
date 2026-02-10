
import { chromium } from 'playwright';

(async () => {
    console.log('🔑 INICIANDO TESTE WEB AUTH (PASSKEYS)');

    // Launch browser
    const browser = await chromium.launch({ headless: true }); // Headless works with virtual authenticator
    const context = await browser.newContext();
    const page = await context.newPage();

    // Create a CDPSession to talk to Chrome DevTools Protocol
    const client = await context.newCDPSession(page);

    // Enable WebAuthn Environment and Create Virtual Authenticator
    await client.send('WebAuthn.enable');
    const result = await client.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            transport: 'usb', // Simulates YubiKey
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true
        }
    });
    const authenticatorId = result.authenticatorId;
    console.log(`📱 Virtual Authenticator Created (ID: ${authenticatorId})`);

    try {
        // 1. REGISTER FLOW
        const userEmail = `passkey-user-${Date.now()}@test.com`;
        console.log(`\n📝 [REGISTER] Acessando setup para ${userEmail}...`);

        await page.goto('http://localhost:3000/');
        await page.fill('#username', userEmail);

        // Click Register Passkey
        console.log('   Clicando em "Registrar Passkey"...');

        // Listener para dialogos/logs se houver
        page.on('console', msg => console.log('   Browser Log:', msg.text()));

        await page.click('#btnPasskey');

        // A espera é pelo status de sucesso
        await page.waitForSelector('#passkeyStatus.success', { timeout: 10000 });
        const successMsg = await page.textContent('#passkeyStatus');

        if (successMsg?.includes('sucesso')) {
            console.log('   ✅ Registro de Passkey concluído com sucesso!');
        } else {
            throw new Error('Falha no registro: Mensagem de sucesso não encontrada.');
        }

        // 2. LOGIN FLOW
        console.log(`\n🔓 [LOGIN] Tentando login com Passkey...`);
        await page.goto('http://localhost:3000/login.html');

        await page.fill('#username', userEmail);

        console.log('   Clicando em "Sign In with Passkey"...');
        await page.click('#btnPasskey'); // Botão de login tem mesmo ID no login.html? Sim, usei btnPasskey.

        // Espera redirecionar para dashboard
        await page.waitForURL('**/dashboard.html', { timeout: 10000 });
        console.log('   ✅ Redirecionado para Dashboard!');

        // 3. VERIFY METADATA
        const method = await page.textContent('#methodVal');
        const user = await page.textContent('#userVal');

        console.log(`   Dashboard Info: User=${user}, Method=${method}`);

        if (method?.includes('WEBAUTHN') && user === userEmail) {
            console.log('   ✅ Metadados corretos (WEBAUTHN_PASSKEY).');
        } else {
            console.error('   ❌ Metadados incorretos:', { method, user });
            process.exit(1);
        }

    } catch (err) {
        console.error('❌ ERRO NO TESTE:', err);
        process.exit(1);
    } finally {
        await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
        await browser.close();
        console.log('\n🏁 Teste finalizado.');
    }
})();
