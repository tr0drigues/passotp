
import crypto from 'crypto';
import { config } from '../config.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
// Strict Key Management
const KEY = config.security.encryptionKey;
const ALLOW_INSECURE = process.env.ALLOW_INSECURE_DEV_KEY === 'true';

if (!KEY) {
    if (config.env.isProduction || !ALLOW_INSECURE) {
        throw new Error(
            'FATAL: ENCRYPTION_KEY is missing. In production, this is required. ' +
            'In dev, set ALLOW_INSECURE_DEV_KEY=true to bypass (NOT RECOMMENDED).'
        );
    }
    console.warn('⚠️  WARNING: Using insecure fallback key. DO NOT USE IN PRODUCTION.');
}

const SAFE_KEY = KEY || '0'.repeat(64);

export class EncryptionService {

    encrypt(text: string): string {
        const iv = crypto.randomBytes(IV_LENGTH);

        let masterKey: Buffer;
        if (SAFE_KEY.length === 64) {
            // Assume hex string if length is 64
            masterKey = Buffer.from(SAFE_KEY, 'hex');
        } else {
            // Hash passphrase to 32 bytes
            masterKey = crypto.createHash('sha256').update(SAFE_KEY).digest();
        }

        const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        // Format: IV:AuthTag:Encrypted
        return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    }

    decrypt(text: string): string {
        const parts = text.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid ciphertext format');
        }

        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encryptedText = parts[2];

        let masterKey: Buffer;
        if (SAFE_KEY.length === 64) {
            masterKey = Buffer.from(SAFE_KEY, 'hex');
        } else {
            masterKey = crypto.createHash('sha256').update(SAFE_KEY).digest();
        }

        const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }
}

export const encryptionService = new EncryptionService();
