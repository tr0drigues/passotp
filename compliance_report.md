
# Relatório de Conformidade RFC 4226 / 6238

Este documento valida a implementação do sistema OTP em relação aos padrões da Internet (IETF RFCs) e aos princípios detalhados no artigo [The Guts of 2FA](https://geeklaunch.io/blog/the-guts-of-two-factor-authentication/).

## 1. RFC 4226: HMAC-Based One-Time Password (HOTP)
Esta RFC define o algoritmo fundamental de criptografia e truncamento.

| Requisito RFC 4226 | Implementação (`src/services/totp.service.ts`) | Status |
| :--- | :--- | :--- |
| **Algoritmo HMAC-SHA1** | Utilizado via biblioteca `otplib` (padrão da indústria). | ✅ Conforme |
| **Truncamento Dinâmico** | O algoritmo de extração de 31 bits do hash (offset dinâmico) é tratado internamente pela lib. | ✅ Conforme |
| **Valores de 6-8 Dígitos** | Configurado para 6 dígitos (padrão Google Authenticator). | ✅ Conforme |
| **Integridade do Segredo** | Segredos gerados com entropia criptográfica segura (`authenticator.generateSecret()`). | ✅ Conforme |

## 2. RFC 6238: Time-Based One-Time Password (TOTP)
Esta RFC estende o HOTP substituindo o contador incremental pelo tempo.

| Requisito RFC 6238 | Implementação (`src/services/totp.service.ts`) | Status |
| :--- | :--- | :--- |
| **Time Step (X)** | Padrão de 30 segundos (compatível com apps autenticadores). | ✅ Conforme |
| **Tempo de Referência (T0)** | Unix Epoch (Jan 1 1970), tratado pela `otplib`. | ✅ Conforme |
| **Unicidade ("Not Used Before")** | A RFC exige que um token validado não possa ser reusado. Implementamos isso no `SecurityService` usando Redis com TTL. | ✅ Conforme |
| **Clock Drift (Desvio)** | A validação permite leve margem (geralmente ±1 janela) para compensar dessincronia de relógio entre cliente/servidor. | ✅ Conforme |

## 3. Análise do Artigo "The Guts of 2FA"
O artigo destaca a importância de entender o "Dynamic Truncation" e a vulnerabilidade de Replay Attacks.

*   **Ponto Chave do Artigo**: "A simple implementation might accept the same code multiple times within the 30s window."
*   **Nossa Solução**: Diferente de implementações ingênuas, nós adicionamos explicitamente o `checkReplay(secret, token)` no [server.ts](file:///Volumes/DADOS/Projetos/otp/src/server.ts). Isso armazena o hash do token usado no Redis por 60s. Se o usuário tentar reenviar o mesmo token (ataque de interceptação), o Redis bloqueia (`NX` set fails), cumprindo rigorosamente a recomendação de segurança do artigo.

## 4. RFC 8812: WebAuthn Algorithms (COSE)
Esta RFC registra os algoritmos de assinatura e criptografia (COSE) usados em WebAuthn.

| Requisito RFC 8812 / WebAuthn L3 | Implementação (`src/services/webauthn.service.ts`) | Status |
| :--- | :--- | :--- |
| **Algoritmos COSE** | Explicitamente configurados: **ES256 (-7)**, **RS256 (-257)** e **EdDSA (-8)**. | ✅ Conforme |
| **User Verification** | Configurado como `preferred` (exige Biometria/PIN se disponível, mas não falha se indisponível, garantindo UX). | ✅ Conforme |
| **Challenge-Response** | Challenges de 32 bytes gerados criptograficamente e armazenados com TTL (60s) no Redis. | ✅ Conforme |
| **Origin Validation** | Validação estrita de `RP_ID` e `Expected Origin` (agora configuráveis via ENV para produção). | ✅ Conforme |
| **Clone Detection** | Validamos o `signCount` (contador) da credencial. Se o contador decrescer ou for reutilizado, detectamos clonagem. | ✅ Conforme |

## Conclusão
O sistema é **100% Compliant** com as RFCs 4226, 6238 e **8812**. Além disso, excede a especificação básica ao implementar proteções de camada de aplicação (Rate Limiting, Replay Protection, Logging) que são sugeridas mas não obrigatórias nas RFCs.
