
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
        return authenticator.keyuri(user, 'MyApp-2FA', secret);
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
}

export const totpService = new TotpService();
