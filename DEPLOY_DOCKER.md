# Guia de Deploy com Docker Compose

Este guia descreve como colocar o PassOTP em produção usando Docker Compose.

## Pré-requisitos

1.  Docker e Docker Compose instalados no servidor.
2.  Domínio configurado apontando para o IP do servidor (DNS A Record).

## Passos para Deploy

### 1. Configurar Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto (use o `.env.example` como base):

```bash
cp .env.example .env
nano .env
```

**Configurações Críticas de Produção:**

| Variável | Descrição | Exemplo |
| :--- | :--- | :--- |
| `NODE_ENV` | Define o ambiente (use `production`). | `production` |
| `SESSION_SECRET` | Chave para assinar cookies de sessão via Crypto. | (Gere com `openssl rand -base64 32`) |
| `ENCRYPTION_KEY` | Chave para criptografar segredos no banco (32 bytes). | (Gere com `openssl rand -base64 32`) |
| `CORS_ORIGIN` | Domínios permitidos para requisições API. | `https://otp.seudominio.com` |
| `FRONTEND_ORIGIN`| URL do frontend (para validação de origem segura). | `https://otp.seudominio.com` |
| `WEBAUTHN_RP_ID` | Domínio onde o WebAuthn é válido (sem protocolo). | `otp.seudominio.com` |
| `WEBAUTHN_ORIGIN`| Origem completa do WebAuthn. | `https://otp.seudominio.com` |

### 2. Ajustar o `docker-compose.yml` (Segurança)

Por padrão, o arquivo `docker-compose.yml` expõe a porta `6379` do Redis para facilitar o desenvolvimento. **Em produção, isso é um risco de segurança.**

Edite o arquivo `docker-compose.yml` e comente a exposição da porta do Redis:

```yaml
  redis:
    image: redis:alpine
    # ...
    # ports:           <-- Comente estas linhas
    #   - "6379:6379"  <-- Comente estas linhas
```

A aplicação (`app`) continuará acessando o Redis internamente pela rede `otp-network`.

### 3. Iniciar a Aplicação

Execute o comando para construir e subir os containers em segundo plano (detached):

```bash
docker-compose up -d --build
```

### 4. Verificar Status

```bash
docker-compose ps
docker-compose logs -f app
```

## Persistência de Dados

O `docker-compose.yml` já está configurado com um volume nomeado `redis-data`.
Isso garante que, mesmo se você reiniciar os containers (`docker-compose down` e `up`) ou reiniciar o servidor, os dados dos usuários (segredos TOTP, WebAuthn) **SERÃO PRESERVADOS**.

## Configuração de SSL (HTTPS)

O container `nginx` incluído no docker-compose expõe apenas a porta `80` (HTTP). Para produção segura com HTTPS, você tem duas opções principais:

1.  **Reverse Proxy Externo (Recomendado):**
    Use um Nginx instalado no host, Traefik, ou Cloudflare na frente do Docker. Configure-o para tratar o SSL (Terminação SSL) e encaminhar o tráfego para a porta `80` localhost ou para o IP do container.

2.  **Certbot no Container Nginx:**
    Você precisaria modificar a configuração do `nginx/nginx.conf` e montar volumes para os certificados Let's Encrypt.
