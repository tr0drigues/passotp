# Sistema de Autenticação (TOTP + Passkeys) - Security by Design

Este projeto implementa um sistema de Autenticação Multi-Fator (MFA) suportando **TOTP** (RFC 6238) e **WebAuthn/Passkeys** (FIDO2), seguindo rigorosamente os padrões de segurança da indústria e especificações IETF.

Desenvolvido com foco em segurança ("Security by Design"), performance e privacidade.

## 🏗️ Arquitetura da Solução

```mermaid
graph TD
    Client(["User / Browser"]) -->|HTTPS| Server["Node.js (Fastify)"]
    
    subgraph "Server Core"
        Server --> Auth[Auth Service]
        Server --> TOTP[TOTP Service]
        Server --> WebAuthn[WebAuthn Service]
        Server --> Sec[Security Service]
        Server --> Enc[Encryption Service]
    end

    subgraph "Storage (Redis)"
        Auth -->|Read/Write Encrypted Secrets| Redis[(Redis Data)]
        Sec -->|Rate Limits / Replay Protection| Redis
        WebAuthn -->|Store Credentials| Redis
    end

    Enc -.->|Encrypt/Decrypt| Auth
```

## 🚀 Tecnologias

*   **Node.js (v20+) & TypeScript**: Backend performático e tipado.
*   **Fastify**: Framework web de alta performance (v5).
*   **Redis**: Armazenamento de estado volátil, segredos (encriptados) e controle de segurança.
*   **WebAuthn/FIDO2**: Autenticação sem senha (TouchID, FaceID, Windows Hello).
*   **AES-256-GCM**: Criptografia de dados sensíveis em repouso.

## 🛡️ Funcionalidades de Segurança

1.  **Criptografia em Repouso**: Segredos TOTP são encriptados com **AES-256-GCM** (chave de 32 bytes) antes de serem salvos no Redis.
2.  **Proteção de Replay Atômica**: Bloqueio de uso único baseado em Time-Step (`replay:{userId}:{step}`) utilizando operações atômicas no Redis (`SET NX`), prevenindo condições de corrida.
3.  **Privacidade (Account Enumeration)**: Respostas genéricas (`401 Credenciais inválidas`) e tempos constantes (delay artificial de 100ms) impedem a enumeração de usuários.
4.  **Sessão Segura**: 
    - IDs de sessão aleatórios (UUIDv4) armazenados no Redis (`session:{id}`).
    - Cookie `session` assinado, `HttpOnly`, `Secure` e `SameSite=Strict`.
    - Proteção contra Session Fixation.
5.  **Auto-Remoção de Inatividade**: Dados de usuários inativos por 50 dias são automaticamente excluídos (TTL renovável).
6.  **WebAuthn Hardening**: Validação estrita de `userVerification` (Biometria/PIN), Challenge e Integridade de Counters.
7.  **Dual Rate Limiting**:
    - **IP**: Proteção contra DDoS/Brute-Force (5 tentativas/5min).
    - **Usuário**: Proteção contra Credential Stuffing (limite separado por conta).
    - **Usuário**: Proteção contra Credential Stuffing (limite separado por conta).
8.  **Hardening HTTP**: 
    - **CSP (Content Security Policy)**: Política restritiva (`default-src 'self'`) previne XSS.
    - Headers de segurança via `@fastify/helmet` (HSTS, No-Sniff, Frameguard).
9.  **Validação de Input**: Regex estrito em Tokens (6 dígitos ou Recovery Code).

## 📦 Como Rodar

### Pré-requisitos
*   Docker e Docker Compose
*   Node.js (v20+)

### Passo a Passo

1.  **Clone o repositório**
    ```bash
    git clone <seu-repositorio>
    cd otp-system
    ```

2.  **Suba a infraestrutura**
    ```bash
    docker-compose up -d
    ```

3.  **Configure o Ambiente**
    Crie o arquivo `.env`:
    ```bash
    cp .env.example .env
    ```
    > **Importante**: Gere chaves seguras para `ENCRYPTION_KEY` (32 bytes hex) e `SESSION_SECRET`.
    
    ### 🔐 Gestão de Segredos em Produção
    
    Embora arquivos `.env` sejam padrão em desenvolvimento, para **produção** recomendamos não escrever esses arquivos em disco. Utilize injeção de variáveis de ambiente segura:
    
    1.  **Docker Swarm / Kubernetes Secrets**: Injete como arquivos em `/run/secrets` ou variáveis de ambiente em memória.
    2.  **Secret Managers (AWS SSM / Vault / Google Secret Manager)**: A aplicação lê os valores na inicialização.
    3.  **CI/CD Injection**: Variáveis injetadas durante o deploy (GitLab CI / GitHub Actions Secrets).
    
    > **Nunca comite o arquivo .env no Git!**

4.  **Instale e Rode**
    ```bash
    npm install
    npm run dev
    ```

5.  **Acesse**: `http://localhost:3000`

## 🧪 Desenvolvimento

A pasta `scripts/` contém utilitários para manutenção e migração:
- `migrate-encryption.ts`: Criptografa usuários legados.
- `migrate-ttl.ts`: Aplica política de expiração (50 dias).

> **Nota**: Testes e relatórios de verificação não são incluídos no repositório por questões de segurança e limpeza.

## ⚠️ Notas de Produção

- **HTTPS**: É obrigatório para WebAuthn e Cookies Secure. Em localhost funciona, mas em produção use um Reverse Proxy (Nginx/Traefik) com SSL.
- **Configuração**: Garanta que `WEBAUTHN_ORIGIN` corresponda exatamente ao seu domínio.
