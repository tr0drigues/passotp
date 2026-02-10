
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { logger } from '../lib/logger.js';
import redis from '../lib/redis.js';

// Configuration
const RP_ID = process.env.WEBAUTHN_RP_ID || 'localhost';
const ORIGIN = process.env.WEBAUTHN_ORIGIN || 'http://localhost';

// [HARDENING] User Verification is safer by default in Production
const isProduction = process.env.NODE_ENV === 'production';
let REQUIRE_UV = false;

if (process.env.WEBAUTHN_REQUIRE_UV !== undefined) {
    REQUIRE_UV = process.env.WEBAUTHN_REQUIRE_UV === 'true';
} else {
    REQUIRE_UV = isProduction; // Default: true in Prod, false in Dev
}

export class WebAuthnService {

    /**
     * 1. REGISTRATION: Generate Options (Challenge)
     * Frontend pede um desafio para criar uma nova credencial.
     */
    async generateRegisterOptions(user: string) {
        // Busca credenciais existentes para não registrar a mesma 2x no mesmo autenticador
        const userCredentials = await this.getUserCredentials(user);

        const options = await generateRegistrationOptions({
            rpName: RP_NAME,
            rpID: RP_ID,
            userName: user,
            // RFC 8812: COSE Algorithms
            // -7: ES256 (ECDSA w/ P-256)
            // -257: RS256 (RSA Signature w/ SHA-256)
            // -8: EdDSA (Ed25519)
            supportedAlgorithmIDs: [-7, -257, -8],
            // Don't prompt if user already has a credential on this device
            excludeCredentials: userCredentials.map(cred => ({
                id: cred.id,
                transports: cred.transports,
            })),
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: REQUIRE_UV ? 'required' : 'preferred',
                // authenticatorAttachment: 'cross-platform', 
            },
        });

        // Salva o challenge temporariamente no Redis (TTL 60s)
        await redis.set(`webauthn:challenge:${user}`, options.challenge, 'EX', 60);

        return options;
    }

    /**
     * 2. REGISTRATION: Verify Response
     * Frontend assina o desafio e envia de volta.
     */
    async verifyRegister(user: string, body: any) {
        const expectedChallenge = await redis.get(`webauthn:challenge:${user}`);

        if (!expectedChallenge) {
            throw new Error('Challenge expirado ou não encontrado.');
        }

        let verification;
        try {
            verification = await verifyRegistrationResponse({
                response: body,
                expectedChallenge,
                expectedOrigin: ORIGIN,
                expectedRPID: RP_ID,
                requireUserVerification: REQUIRE_UV,
            });
        } catch (error) {
            logger.error({ event: 'AUTH_FAIL', message: 'WebAuthn verification failed', user, meta: { error } });
            throw error;
        }

        const { verified, registrationInfo } = verification;

        if (verified && registrationInfo) {
            const { credential } = registrationInfo;
            const { id, publicKey, counter } = credential;

            // Salvar nova credencial no Redis
            const newCredential = {
                id,
                publicKey,
                counter,
                transports: body.response.transports,
            };

            await this.saveCredential(user, newCredential);

            // Limpa o challenge
            await redis.del(`webauthn:challenge:${user}`);

            logger.info({ event: 'SETUP_COMPLETE', message: 'Passkey registered successfully', user });

            // Refresh/Set TTL (50 days)
            const USER_TTL = 50 * 24 * 60 * 60;
            await redis.expire(`webauthn:credentials:${user}`, USER_TTL);
            // We should also refresh the main user record if it exists, to keep them in sync
            await redis.expire(`user:${user}`, USER_TTL);

            return true;
        }

        return false;
    }

    /**
     * 3. LOGIN: Generate Options (Challenge)
     */
    async generateLoginOptions(user: string) {
        const userCredentials = await this.getUserCredentials(user);

        if (userCredentials.length === 0) {
            // Se usuário não tem passkeys, não dá pra logar com isso.
            // Mas para privacidade, não deveríamos falhar imediatamente (user enumeration).
            // Por simplicidade aqui, vamos retornar erro ou options vazio.
            // throw new Error('No passkeys found for user');
        }

        const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            allowCredentials: userCredentials.map(cred => ({
                id: cred.id,
                transports: cred.transports,
            })),
            userVerification: REQUIRE_UV ? 'required' : 'preferred',
        });

        await redis.set(`webauthn:challenge:${user}`, options.challenge, 'EX', 60);

        return options;
    }

    /**
     * 4. LOGIN: Verify Response
     */
    async verifyLogin(user: string, body: any) {
        const expectedChallenge = await redis.get(`webauthn:challenge:${user}`);
        const userCredentials = await this.getUserCredentials(user);

        // Encontra a credencial que o usuário usou (pelo ID retornado no body)
        const credentialObj = userCredentials.find(cred => cred.id === body.id);

        if (!expectedChallenge || !credentialObj) {
            throw new Error('Challenge inválido ou credencial não encontrada.');
        }

        let verification;
        try {
            verification = await verifyAuthenticationResponse({
                response: body,
                expectedChallenge,
                expectedOrigin: ORIGIN,
                expectedRPID: RP_ID,
                credential: {
                    id: credentialObj.id,
                    publicKey: new Uint8Array(Object.values(credentialObj.publicKey)),
                    counter: credentialObj.counter,
                    transports: credentialObj.transports,
                },
                requireUserVerification: REQUIRE_UV,
            });
        } catch (error) {
            logger.error({ event: 'AUTH_FAIL', message: 'WebAuthn verification failed', user, meta: { error } });
            throw error;
        }

        const { verified, authenticationInfo } = verification;

        if (verified) {
            // Atualizar o counter da credencial para prevenir clonagem
            credentialObj.counter = authenticationInfo.newCounter;
            await this.updateCredential(user, credentialObj);

            await redis.del(`webauthn:challenge:${user}`);

            // Refresh TTL (50 days)
            const USER_TTL = 50 * 24 * 60 * 60;
            await redis.expire(`webauthn:credentials:${user}`, USER_TTL);
            await redis.expire(`user:${user}`, USER_TTL);
            await redis.expire(`recovery:${user}`, USER_TTL);

            return true;
        }

        return false;
    }

    // --- Helpers de Persistência (Redis) ---

    // Armazena lista de credenciais em uma chave do tipo SET ou STRING (JSON array)
    // Vamos usar String com JSON array por simplicidade de serialização do Uint8Array
    private async getUserCredentials(user: string): Promise<any[]> {
        const data = await redis.get(`webauthn:credentials:${user}`);
        return data ? JSON.parse(data) : [];
    }

    private async saveCredential(user: string, credential: any) {
        const creds = await this.getUserCredentials(user);
        creds.push(credential);
        await redis.set(`webauthn:credentials:${user}`, JSON.stringify(creds));
    }

    private async updateCredential(user: string, updatedCred: any) {
        let creds = await this.getUserCredentials(user);
        creds = creds.map(c => c.id === updatedCred.id ? updatedCred : c);
        await redis.set(`webauthn:credentials:${user}`, JSON.stringify(creds));
    }
}

export const webauthnService = new WebAuthnService();
