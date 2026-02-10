
import { authenticator } from 'otplib';

async function debug() {
    const secret = authenticator.generateSecret();
    console.log('Secret:', secret);

    const token = authenticator.generate(secret);
    console.log('Generated Token:', token);

    const isValid = authenticator.check(token, secret);
    console.log('Is Valid (Direct Check):', isValid);

    const isValidVerify = authenticator.verify({ token, secret });
    console.log('Is Valid (Verify Object):', isValidVerify);

    // Test with a delay to see if window is an issue
    console.log('Waiting 2 seconds...');
    await new Promise(r => setTimeout(r, 2000));

    const isValidDelayed = authenticator.check(token, secret);
    console.log('Is Valid (Delayed):', isValidDelayed);
}

debug();
