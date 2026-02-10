
// Configuration
const BASE_URL = 'http://localhost:3000';
const USER = `race-test-${Date.now()}@test.com`;

async function testRaceCondition() {
    console.log('--- Starting Race Condition Test ---');

    console.log(`1. Setting up user: ${USER}`);
    try {
        const setupRes = await fetch(`${BASE_URL}/setup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user: USER })
        });

        if (!setupRes.ok) throw new Error(`Setup failed: ${setupRes.status}`);
        const { secret } = await setupRes.json() as any;

        console.log('2. Generating valid TOTP...');
        // We need otplib here to generate a valid token
        const { authenticator } = await import('otplib');
        const token = authenticator.generate(secret);

        console.log(`Token generated: ${token}`);

        console.log('3. Firing 10 simultaneous login requests...');
        const promises = [];
        for (let i = 0; i < 10; i++) {
            promises.push(
                fetch(`${BASE_URL}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user: USER, token })
                })
                    .then(async res => {
                        const data = await res.json() as any;
                        return { status: res.status, success: data.success, index: i };
                    })
                    .catch(err => ({ status: 500, success: false, index: i, error: err.message }))
            );
        }

        const results = await Promise.all(promises);

        const successes = results.filter(r => r.success);
        const failures = results.filter(r => !r.success);

        console.log('--- Results ---');
        console.log(`Total Requests: ${results.length}`);
        console.log(`Successes: ${successes.length}`);
        console.log(`Failures: ${failures.length}`);

        if (successes.length === 1 && failures.length === 9) {
            console.log('✅ PASS: Only ONE request succeeded. Race condition invalid.');
            process.exit(0);
        } else {
            console.error('❌ FAIL: More than one request succeeded, or all failed.');
            console.log(successes);
            process.exit(1); // Fail
        }

    } catch (err: any) {
        console.error('Test failed:', err.message);
        process.exit(1);
    }
}

testRaceCondition();
