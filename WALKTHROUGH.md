
# Walkthrough - Sistema de Autenticação TOTP

Implementação completa de um sistema de autenticação de dois fatores (2FA) utilizando **TOTP** (RFC 6238) com **Node.js, TypeScript e Redis**.

## O que foi construído
1.  **API REST (Fastify)**:
    - `POST /setup`: Gera segredo e QR Code.
    - `POST /verify`: Valida o token gerado pelo app autenticador.
2.  **Segurança (Redis)**:
    - **Rate Limiting**: Bloqueia IP/Usuário após 5 tentativas falhas.
    - **Replay Protection**: Impede que o mesmo token seja usado duas vezes.
3.  **Frontend de Teste**: Interface web simples para gerar QR Code e validar tokens.

## Como Executar

### Pré-requisitos
- Node.js (v20+)
- Docker (para o Redis)

### Passos
1.  **Subir Infraestrutura (Redis)**
    ```bash
    docker-compose up -d
    ```

2.  **Instalar Dependências**
    ```bash
    npm install
    ```

3.  **Rodar o Servidor**
    ```bash
    npm run dev
    ```

4.  **Acessar Interface**
    Abra `http://localhost:3000` no navegador.

## Verificação e Testes

### 1. Teste Automatizado
Rodamos um script de teste (`test-verification.ts`) cobrindo todos os cenários.
Resultados:
- **Setup**: ✅ Sucesso (Segredo gerado)
- **Validação**: ✅ Sucesso (Token válido aceito)
- **Replay Attack**: ✅ Bloqueado (Token duplicado recusado)
- **Rate Limit**: ✅ Bloqueado (Após 5 tentativas falhas)

### 2. Teste Manual (Interface)
1.  Acesse `http://localhost:3000`.
2.  Digite um email e clique em "Gerar QR Code".
3.  Escaneie com Google Authenticator ou Authy.
4.  Digite o código gerado.
    - **Primeira vez**: Deve mostrar "Autenticado com sucesso!".
    - **Segunda vez (mesmo código)**: Deve mostrar erro "Este código já foi utilizado.".

## Arquitetura de Arquivos
- `src/server.ts`: Ponto de entrada e rotas da API.
- `src/services/totp.service.ts`: Lógica do algoritmo TOTP (otplib).
- `src/services/security.service.ts`: Lógica de Rate Limit e Replay (Redis).
- `src/lib/redis.ts`: Cliente Redis Singleton.

## Auditoria de Segurança (Webapp Testing Skill)
Executamos uma bateria de testes automatizados (`scripts/security-audit.ts`) simulando ataques reais:

### 1. Brute Force / Rate Limiting (Exponential Backoff)
- **Cenário**: Atacante tenta advinhar o código múltiplas vezes.
- **Resultado**: ✅ **Bloqueado**. O sistema pune a insistência.
    - Tentativas 1-5: Permitidas.
    - Tentativa 6: Bloqueio de 30s.
    - Tentativa 7 (se insistir): Bloqueio de 60s.
    - ... até o teto de ~1 hora.

### 2. Replay Attack
- **Cenário**: Atacante intercepta um token válido e tenta usar novamente.
- **Resultado**: ✅ **Bloqueado**. O sistema aceitou a 1ª vez (Login) e recusou a 2ª vez (HTTP 401).

### 3. NoSQL Injection
- **Cenário**: Injeção de chaves maliciosas no campo de usuário (`user:attacker`).
- **Resultado**: ✅ **Seguro**. O sistema tratou como string literal e não expôs dados ou crashou.

## Novas Funcionalidades (Inspiradas em Authelia/Logto)

### 🛡️ Exponential Backoff (Authelia)
Implementamos uma lógica de "castigo progressivo". Diferente de um rate limit fixo, este método torna ataques de força bruta matematicamente inviáveis, pois o tempo de espera cresce exponencialmente (2^n) a cada erro consecutivo.

### 🕵️ Session Fingerprinting (Logto)
O sistema agora registra a "impressão digital" da sessão (IP + User-Agent) no momento do login.
Esses dados são exibidos no **Dashboard de Validação** para que o usuário possa confirmar se o acesso veio de um dispositivo legítimo.

### 🔑 WebAuthn (Passkeys)
Implementação completa de autenticação passwordless (FIDO2/WebAuthn):
- **Registro**: Permite cadastrar TouchID, FaceID ou YubiKey na tela de setup.
- **Login**: Novo botão "Entrar com Passkey" para autenticação segura e sem senha.
- **Backend**: Utiliza `@simplewebauthn/server` com persistência em Redis.
- **Segurança**: Validação de desafios (challenges) assinados criptograficamente, proteção contra replay (counters) e verificação de origem.

## Próximos Passos Sugeridos
1.  Implementar HTTPS (obrigatório para WebAuthn em produção, exceto localhost).
2.  Adicionar suporte a múltiplos authenticators por usuário.
3.  Implementar fluxo de revogação de Passkeys.

