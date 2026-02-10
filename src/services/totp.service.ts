
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

export class TotpService {
    /**
     * Gera um segredo TOTP novo e único
     */
    generateSecret() {
        return authenticator.generateSecret();
    }

    /**
     * Gera a URI de autenticação (otpauth://) para ser usada em QR Codes
     */
    getOtpAuthKey(user: string, secret: string) {
        // Alterar 'SecureAuth-2FA' para o nome da sua aplicação
        return authenticator.keyuri(user, 'SecureAuth-2FA', secret);
    }

    /**
     * Gera um QR Code em Base64 para ser exibido no frontend
     */
    async generateQRCode(otpAuthKey: string): Promise<string> {
        return QRCode.toDataURL(otpAuthKey);
    }

    /**
     * Valida o token matematicamente contra o segredo
     * Nota: A verificação de replay e rate limit deve ser feita antes/depois no SecurityService
     */
    verifyToken(token: string, secret: string): boolean {
        return authenticator.check(token, secret);
    }

    /**
     * Gera 10 códigos de recuperação no formato XXXX-XXXX
     */
    generateRecoveryCodes(quantity: number = 10): string[] {
        const codes: string[] = [];
        for (let i = 0; i < quantity; i++) {
            const hex = authenticator.generateSecret(8).toUpperCase(); // ~6-8 chars
            // Format as XXXX-XXXX for readability
            const code = `${hex.substring(0, 4)}-${hex.substring(4, 8)}`;
            codes.push(code);
        }
        return codes;
    }
}

export const totpService = new TotpService();
