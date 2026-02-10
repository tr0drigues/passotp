# Sistema de Autenticação (TOTP + Passkeys) - Security by Design

Este projeto implementa um sistema de Autenticação Multi-Fator (MFA) suportando **TOTP** (RFC 6238) e **WebAuthn/Passkeys** (FIDO2), seguindo rigorosamente os padrões de segurança da indústria e especificações IETF.

Desenvolvido com foco em segurança ("Security by Design"), performance e melhor experiência do desenvolvedor/usuário.

## 🚀 Tecnologias

*   **Node.js (v20+) & TypeScript**: Backend performático e tipado.
*   **Fastify**: Framework web de alta performance.
*   **Redis (via Docker)**: Armazenamento de estado volátil, controle de *Rate Limiting* e prevenção de *Replay Attacks*.
*   **Playwright**: Suite de testes automatizados de segurança.
*   **Frontend**: Interface moderna com Glassmorphism e animações (HTML/CSS/JS puro).

## 🛡️ Funcionalidades de Segurança

1.  **Algoritmo TOTP Padrão**: Compatível com Google Authenticator, Authy, Microsoft Authenticator, etc.
2.  **Rate Limiting**: Proteção contra ataques de força bruta (limite de 5 tentativas a cada 5 minutos por usuário/IP).
3.  **Replay Protection**: Impede que um código válido seja utilizado mais de uma vez (idempotência).
4.  **NoSQL Injection Safe**: Sanitização e tratamento adequado de chaves no Redis.
5.  **Recovery Codes**: Códigos de backup criptografados (bcrypt) para recuperação de conta.
6.  **Security Obsevability**: Logs estruturados (JSON) com eventos de segurança (SIEM-ready).
7.  **Context Awareness**: Monitoramento de IP e User-Agent para detecção de logins suspeitos.
8.  **WebAuthn (Passkeys)**: Suporte completo a autenticação *passwordless* (FIDO2/WebAuthn) com validação de assinatura e proteção contra clonagem.


## 📦 Como Rodar

### Pré-requisitos

*   Docker e Docker Compose
*   Node.js (v20 ou superior)

### Passo a Passo

1.  **Clone o repositório**
    ```bash
    git clone <seu-repositorio>
    cd otp-system
    ```

2.  **Suba a infraestrutura (Redis)**
    ```bash
    docker-compose up -d
    ```

3.  **Configure o Ambiente**
    Crie um arquivo `.env` baseado no exemplo:
    ```bash
    cp .env.example .env
    ```
    *Dica: Para testar WebAuthn localmente, as configurações padrão funcionam. Em produção, você precisará de HTTPS e ajustar `WEBAUTHN_ORIGIN`.*

4.  **Instale as dependências**
    ```bash
    npm install
    ```

5.  **Inicie o servidor de desenvolvimento**
    ```bash
    npm run dev
    ```

6.  **Acesse a aplicação**
    Abra `http://localhost:3000` no seu navegador.
    
    *   **Login com Senha/TOTP**: Fluxo padrão.
    *   **Login com Passkey**: Registre uma chave (TouchID/FaceID) no setup e use o botão "Sign In with Passkey".

> **Nota sobre WebAuthn**: A API de Credenciais (Passkeys) requer um contexto seguro (HTTPS) ou `localhost`. Se você acessar via IP (ex: `192.168.x.x`), o navegador bloqueará o registro.


## 🧪 Como Testar

### Fluxo de Usuário (TOTP)
1.  Acesse a página inicial para configurar o 2FA.
2.  Digite seu e-mail e clique em "Enable 2FA".
3.  Escaneie o QR Code com seu aplicativo autenticador.
4.  Para validar o login recorrente, clique em "Log in here" no rodapé ou acesse `/login.html`.

### Fluxo de Usuário (WebAuthn / Passkeys)
1.  No setup inicial, após digitar o email, clique em **"Registrar Passkey"**.
2.  Siga as instruções do navegador (TouchID, FaceID, Windows Hello, etc).
3.  Vá para a tela de Login (`/login.html`).
4.  Digite o email e clique em **"🔑 Sign In with Passkey"**.
5.  Valide sua biometria e entre sem senha.

### Testes de Segurança Avançados
Além da auditoria básica, você pode validar o fluxo de recuperação e WebAuthn:
```bash
# Teste de Recuperação (TOTP + Recovery Codes)
npx tsx scripts/test-recovery.ts

# Teste E2E de WebAuthn (Simula TouchID virtual)
npx tsx scripts/test-webauthn.ts
```

Para rodar a auditoria de segurança completa (Rate Limit, Injection, Replay):
```bash
# Instale os navegadores do Playwright (apenas na primeira vez)
npx playwright install chromium

# Execute o script de auditoria
npx tsx scripts/security-audit.ts
```

### Dashboard de Validação (Developer Mode)
Ao realizar o login com sucesso no ambiente de desenvolvimento, você será redirecionado para `dashboard.html`.
Esta página exibe os metadados da sessão:
- **Método**: `TOTP`, `RECOVERY_CODE` ou `WEBAUTHN_PASSKEY`.
- **User Agent & IP**: Para conferência de fingerprinting.

> **⚠️ Para Produção**:
> Edite o arquivo `public/login.html` (linha ~360) e altere o redirecionamento:
> ```javascript
> // De:
> window.location.href = '/dashboard.html';
> // Para:
> window.location.href = '/app'; // Sua rota real
> ```
> E remova o arquivo `public/dashboard.html`.

## 📚 API Endpoints

### `POST /setup`
Inicia o processo de vínculo 2FA.
- **Body**: `{ "user": "email@exemplo.com" }`
- **Retorno**: `{ "secret": "...", "qrCode": "data:image/...", "recoveryCodes": [...] }`
- **Ação**: Gera segredo TOTP + Códigos de Recuperação e salva no Redis.

### `POST /login`
Valida um token para login.
- **Body**: `{ "user": "email@exemplo.com", "token": "123456" }`
- **Retorno**: `{ "success": true, "message": "Login realizado...", "meta": { ... } }`
- **Segurança**: Verifica TOTP ou Recovery Code, aplica Rate Limit e checa Replay.

### `POST /webauthn/register/*` & `/webauthn/login/*`
Endpoints para fluxo FIDO2 de registro e autenticação.
- **Challenge**: Gera desafio criptográfico.
- **Verify**: Valida assinatura do dispositivo e salva/autentica credencial.

## 📊 Logs de Auditoria

Os logs são gerados em formato JSON no stdout, ideais para ingestão em Datadog, Elastic ou Splunk.
Exemplo:
```json
{
  "timestamp": "2024-02-10T03:00:00.000Z",
  "level": "warn",
  "event": "RATE_LIMIT",
  "message": "Rate limit exceeded",
  "user": "attacker@evil.com",
  "ip": "1.2.3.4"
}
```

## ⚠️ Notas de Produção

Este projeto é uma implementação de referência. Para uso em produção, considere:
1.  **HTTPS**: Obrigatório para proteger o tráfego de segredos.
2.  **Variáveis de Ambiente**: Mova configurações sensíveis (host do Redis, portas) para um arquivo `.env` (exemplo não incluído por segurança).
3.  **Redis Password**: Configure uma senha forte no `docker-compose.yml` e no cliente Redis.

## ⚙️ Customização

### Alterar Nome da Aplicação (Authenticator Label)
Para alterar o nome que aparece no aplicativo autenticador do usuário (ex: "SuaEmpresa" ao invés de "SecureAuth-2FA"):

1.  Edite o arquivo `src/services/totp.service.ts`.
2.  Localize o método `getOtpAuthKey`.
3.  Altere o segundo parâmetro da função `authenticator.keyuri`:

```typescript
// src/services/totp.service.ts
getOtpAuthKey(user: string, secret: string) {
    // Altere 'SecureAuth-2FA' para o nome desejado (sem espaços ou caracteres especiais recomendados)
    return authenticator.keyuri(user, 'NomeDaSuaApp', secret);
}
```

---
