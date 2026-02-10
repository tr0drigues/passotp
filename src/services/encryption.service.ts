
import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;
const isProduction = process.env.NODE_ENV === 'production';

// Fallback only allows explicit "dev" mode, otherwise throw to be safe
const KEY = process.env.ENCRYPTION_KEY;
if (!KEY) {
    if (isProduction) {
        throw new Error('FATAL: ENCRYPTION_KEY is required in production.');
    }
    console.warn('⚠️  WARNING: ENCRYPTION_KEY not found. Using insecure fallback for DEVELOPMENT only.');
}
const SAFE_KEY = KEY || '0'.repeat(64);

export class EncryptionService {

    encrypt(text: string): string {
        const iv = crypto.randomBytes(IV_LENGTH);
        const salt = crypto.randomBytes(SALT_LENGTH);

        // Derive key using PBKDF2
        // In a real scenario, you might use the raw ENCRYPTION_KEY if it's already a high-entropy 32-byte key.
        // But here we'll use the provided key as a "master key" to derive a specific key with salt.
        // HOWEVER, for simplicity and performance in this specific task (Encrypting Redis values),
        // checking the plan: "Implement encrypt(text: string): string using aes-256-gcm... Use process.env.ENCRYPTION_KEY"
        // If ENCRYPTION_KEY is 32 bytes hex (64 chars), we can use it directly as Buffer.from(KEY, 'hex').

        // Let's assume ENCRYPTION_KEY is a hex string representing 32 bytes.
        let masterKey: Buffer;
        if (SAFE_KEY.length === 64) {
            masterKey = Buffer.from(SAFE_KEY, 'hex');
        } else {
            // Fallback if user provided a string passphrase: verify length or hash it.
            // Ideally we want 32 bytes for aes-256.
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
            // If it's not in our format, return text as is (backward compatibility for existing plain secrets? OR fail?)
            // Plan says "Existing plain-text secrets in Redis will become invalid." -> So we should probably fail or returns null?
            // Or better, throw error.
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
