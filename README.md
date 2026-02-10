# Sistema de Autenticação (TOTP + Passkeys) - Security by Design

Este projeto implementa um sistema de Autenticação Multi-Fator (MFA) moderno, suportando **TOTP** (RFC 6238) e **WebAuthn/Passkeys** (FIDO2).

**Destaques:**
- 🔒 **Security by Design**: Criptografia AES-256 em repouso, proteção contra replay, rate limiting.
- 🐳 **Docker Native**: Infraestrutura completa containerizada (App + Redis + Nginx).
- 🎨 **Premium UI**: Interface moderna com Dark Mode e Glassmorphism.

## 🏗️ Arquitetura de Referência

A solução adota uma arquitetura de "Defense in Depth", onde cada camada possui responsabilidades de segurança específicas.

```mermaid
graph TD
    Client(["👤 User / Browser"]) 
    
    subgraph "Infrastructure (Docker Compose)"
        style Nginx fill:#f9f9f9,stroke:#009639,stroke-width:2px
        Nginx["🌐 <b>Nginx Reverse Proxy</b><br/>(Port 80)<br/>Termination SSL / Header"]
        
        subgraph "Application Layer"
            style Node fill:#eff,stroke:#339933,stroke-width:2px
            Node["🟢 <b>Node.js (Fastify)</b><br/>(Internal: 3000)"]
        end
        
        subgraph "Persistence Layer"
            style Redis fill:#ffe,stroke:#DC382D,stroke-width:2px
            Redis[("🔴 <b>Redis</b><br/>(Session / Secrets / Cache)")]
        end
    end

    Client -->|HTTPS| Nginx
    Nginx -->|Proxy Pass| Node
    Node -->|Read/Write| Redis

    %% Logic Flow
    Node --> Auth["🛡️ Auth Service"]
    Node --> TOTP["🔢 TOTP Service"]
    Node --> WebAuthn["🔑 WebAuthn Service"]
```

## 🚀 Tecnologias

| Componente | Tecnologia | Função |
|------------|------------|--------|
| **Backend** | ![NodeJS](https://img.shields.io/badge/-Node.js-339933?style=flat&logo=node.js&logoColor=white) ![TypeScript](https://img.shields.io/badge/-TypeScript-3178C6?style=flat&logo=typescript&logoColor=white) | Lógica de negócios e API segura. |
| **Framework** | ![Fastify](https://img.shields.io/badge/-Fastify-000000?style=flat&logo=fastify&logoColor=white) | Servidor web de alta performance. |
| **Database** | ![Redis](https://img.shields.io/badge/-Redis-DC382D?style=flat&logo=redis&logoColor=white) | Sessões, Rate Limiting e Segredos (Encriptados). |
| **Infra** | ![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat&logo=docker&logoColor=white) ![Nginx](https://img.shields.io/badge/-Nginx-009639?style=flat&logo=nginx&logoColor=white) | Containerização e Proxy Reverso. |
| **Auth** | ![WebAuthn](https://img.shields.io/badge/-WebAuthn-orange?style=flat) | Autenticação Biométrica FIDO2. |

## 🛡️ Funcionalidades de Segurança (Deep Dive)

Abaixo detalhamos as implementações de segurança para fins educativos:

1.  **Criptografia em Repouso**: Segredos TOTP nunca são salvos em texto plano. Utilizamos **AES-256-GCM** com uma chave de 32 bytes (`ENCRYPTION_KEY`) antes da persistência no Redis.
2.  **Proteção de Replay Atômica**: Prevenimos reutilização de tokens OTP usando uma chave `replay:{userId}:{step}` no Redis com operação atômica `SET NX`.
3.  **Privacidade (Account Enumeration)**:
    - Respostas genéricas (`401 Credenciais inválidas`).
    - **Timing Attack Protection**: Delay artificial constante (ex: 200ms) em *todas* as falhas de autenticação.
4.  **Sessão Segura**: 
    - IDs de sessão aleatórios (UUIDv4).
    - Cookie `session` assinado, `HttpOnly`, `Secure` e `SameSite=Strict` (ou `Lax` dependendo do fluxo).
5.  **Auto-Remoção de Inatividade**: Dados de usuários inativos são automaticamente expurgados do Redis via TTL (Time-To-Live).
6.  **WebAuthn Hardening**: Validação estrita de Challenge e Integridade de Counters para evitar clonagem de autenticadores.
7.  **Rate Limiting Duplo**:
    - **Por IP**: Proteção contra DDoS/Brute-Force.
    - **Por Usuário**: Proteção contra Credential Stuffing.
8.  **Hardening HTTP (Nginx + Helmet)**:
    - **Nginx**: Atua como *TLS Termination Proxy*, removendo a carga de criptografia da aplicação Node.js.
    - **CSP (Content Security Policy)**: Prevenção de XSS.

## 📦 Como Rodar (Local)

Utilizamos Docker Compose para simular o ambiente de produção.

1.  **Configure o Ambiente**:
    ```bash
    cp .env.example .env
    ```
    > Ajuste `WEBAUTHN_ORIGIN=http://localhost` para rodar localmente via Nginx.

2.  **Suba a infraestrutura**:
    ```bash
    docker-compose up -d --build
    ```

3.  **Acesse**:
    👉 **http://localhost** (Porta 80)
    
    *O Nginx redirecionará internamente para o Node.js na porta 3000.*

## 🔌 Arquitetura de Integração (Como Consumir)

Este serviço foi projetado para operar como um **Microserviço de Autenticação** independente. Sua aplicação principal ("Consumer App") delega a responsabilidade de MFA e Passkeys para ele via API REST.

### Fluxo de Validação (Sequence Diagram)

O diagrama abaixo ilustra como uma aplicação legada ou nova deve consumir este serviço para validar um login:

```mermaid
sequenceDiagram
    participant User as 👤 Usuário
    participant Frontend as 📱 Sua App (Frontend)
    participant Backend as ⚙️ Sua App (Backend)
    participant Auth as 🛡️ Auth Service (Este Projeto)

    User->>Frontend: Digita Login + Senha
    Frontend->>Backend: POST /login (credenciais básicas)
    Backend->>Backend: Valida Senha (LDAP/DB)
    
    rect rgb(20, 20, 20)
        note right of Backend: 🔓 Início do Fluxo MFA
        Backend-->>Frontend: 200 OK (Requer 2FA)
        
        Frontend->>User: Solicita Token TOTP ou Biometria
        User->>Frontend: Insere Token / TouchID
        
        Frontend->>Backend: POST /verify-2fa { token, user }
        
        Backend->>Auth: POST /verify (backend-to-backend)
        Note over Backend,Auth: Payload: { token, secret, user }
        Auth-->>Backend: { success: true }
    end
    
    Backend->>Frontend: 200 OK (Login Completo + JWT)
    Frontend->>User: Redireciona para Dashboard
```

### Endpoints Principais para Integração

| Método | Endpoint | Descrição | Integração Sugerida |
|--------|----------|-----------|---------------------|
| `POST` | `/setup` | Gera Segredo TOTP e QR Code | Chamado pelo seu Backend quando o usuário ativa 2FA. |
| `POST` | `/verify` | Valida um token TOTP (6 dígitos) | Chamado pelo seu Backend a cada login. Seu Backend armazena o `secret`. |
| `POST` | `/webauthn/*` | Fluxo completo de Passkeys | Chamado diretamente pelo Frontend (ou via proxy) para registro/login biométrico. |

> **Nota**: Para **WebAuthn**, o `Auth Service` gerencia o estado das credenciais (public keys, counters) internamente no Redis, simplificando a lógica no seu Backend.

Ao levar esta arquitetura para produção (AWS, Azure, DigitalOcean), considere:

### 1. HTTPS & SSL
Em produção, o Nginx (ou Load Balancer como AWS ALB) deve tratar o SSL.
- A aplicação Node.js continua rodando em HTTP (porta interna).
- Configure o Nginx para passar o header `X-Forwarded-Proto: https`.
- A aplicação confiará neste header devido à configuração `trustProxy: true`.

### 2. Gestão de Segredos Segura
**Jamais use arquivos `.env` em produção.**
- **Docker Swarm / K8s**: Use *Secrets* (`/run/secrets/encryption_key`).
- **Cloud (AWS/GCP)**: Use *Parameter Store* ou *Secret Manager* e injete como variáveis de ambiente em tempo de execução.
- **Rotação de Chaves**: A `ENCRYPTION_KEY` é crítica. Se for comprometida, todos os segredos TOTP precisarão ser re-gerados (ou re-encriptados).

### 3. Persistência
O Redis configurado neste docker-compose não tem persistência em disco habilitada por padrão (`appendonly no`).
- **Produção**: Use AWS ElastiCache ou configure o Redis com volumes persistentes (`AOF` ou `RDB`) para não perder sessões/cadastros ao reiniciar.

### 4. CORS
Configure `CORS_ORIGIN` estritamente para o domínio do seu frontend (ex: `https://app.suaempresa.com`).

## 🧪 Ferramentas de Desenvolvimento

A pasta `scripts/` contém utilitários para testar e auditar o sistema:
- `migration-ttl.ts`: Ajusta políticas de expiração.
- `test-recovery.ts`: Simula o fluxo de recuperação de conta (E2E).
