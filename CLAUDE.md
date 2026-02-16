## Contexto do Projeto

Este é o repositório **mfa-credential-provider** (fork do privacyidea-credential-provider), 
um Windows Credential Provider escrito em C++ que adiciona MFA (Multi-Factor Authentication) 
ao login do Windows.

### Arquitetura Geral do Sistema MFA-Zerobox

O sistema MFA-Zerobox é multi-tenant e composto por:
- **Backend**: Express.js + Prisma + PostgreSQL (repositório separado: MFA-Zerobox)
- **Frontend**: React + TypeScript (mesmo repositório MFA-Zerobox)
- **Agents**: CP (este repo), PAM (Linux), RADIUS Agent (Go) — instalados nos endpoints dos clientes

### O que este CP Agent faz
- Intercepta a tela de login do Windows via Credential Provider DLL
- Após o usuário digitar a senha do AD, solicita código TOTP
- Valida via REST API no backend MFA-Zerobox em POST /validate/check
- Configuração via Registry do Windows (HKLM\SOFTWARE\...)
- Deployment via MSI installer (manual ou GPO)

### Fase 1B - Objetivos de Customização

Este fork precisa ser adaptado do privacyIDEA para funcionar com o backend MFA-Zerobox.
As mudanças necessárias são:

#### 1. Rebranding
- Renomear referências de "PrivacyIDEA" para "MFA-Zerobox" ou "MFA Gruppen"
- Alterar registry path de `Netknights GmbH\PrivacyIDEA-CP\` para path próprio
- Atualizar User-Agent string para formato: `mfa-zerobox-cp/{version} Windows/{HOSTNAME}`
- Atualizar textos da UI de login (prompts, labels)
- Atualizar metadata do MSI installer (WiXSetup)

#### 2. Agent Registration (NOVO)
- No startup do serviço/DLL, fazer POST para `/api/agents/register` com:
  - hostname, osType, osVersion, agentVersion, agentType: "CP"
  - Auth via API Key (header: `Authorization: Bearer mfa_xxxxx`)
- Receber de volta o agentId para usar em comunicações futuras
- Armazenar agentId no Registry

#### 3. Heartbeat (NOVO)
- Timer periódico (a cada 5 min) fazendo POST `/api/agents/{agentId}/heartbeat`
- Enviar: status, uptime, lastAuthTime, systemInfo
- Auth via API Key

#### 4. Policy/Config Sync (NOVO)
- No startup e periodicamente, GET `/api/agents/{agentId}/config`
- Receber configuração centralizada (CpConfigPolicy) do backend:
  - TOTP digits, issuer, algorithm
  - Login behavior settings
  - Update URLs
- Aplicar config recebida (override do Registry local quando policy existe)
- Armazenar configVersion para saber quando atualizar

#### 5. Compatibilidade com Backend Existente
- O endpoint POST /validate/check JÁ FUNCIONA com o CP atual
- User-Agent é parseado pelo backend para auto-discovery de endpoints
- A API Key auth já está implementada no backend (prefixo mfa_)
- authType 'CP' já é detectado e registrado nos endpoints

### Estrutura do Repositório (C++)
- CppClient/ — HTTP client library (onde fica a comunicação com API)
- CredentialProvider/ — Core credential provider DLL
- CredentialProviderFilter/ — Filtro de credenciais
- RegistryHelpers/ — Utilitários de Registry
- Shared/ — Código compartilhado
- WiXSetup/ — MSI installer (WiX Toolset)
- doc/ — Documentação
- locales/ — Traduções

### Build
- Visual Studio 2019/2022 com C++ desktop workload
- WiX Toolset para MSI
- Dependências: libfido2, nlohmann/json (header-only)

### Padrões a Seguir
- Manter compatibilidade com Windows 10/11 e Windows Server 2016+
- Código C++ limpo, seguir estilo existente do projeto
- Testar com build Debug antes de Release
- Documentar mudanças no Changelog.md
- Manter funcionalidades existentes (FIDO2, offline mode, push tokens) funcionando

### API Keys do Backend (para referência)
- Header: `Authorization: Bearer mfa_<hex>`
- O backend valida via tabela ApiKey (model Prisma)
- Cada tenant tem suas API keys
- O CP usa a API key para se autenticar (não JWT)

### Endpoints do Backend Relevantes (para referência)
- POST /validate/check — Validação de TOTP (já existe e funciona)
- POST /api/agents/register — Registro de agent (será criado na Fase 1A do backend)
- POST /api/agents/:id/heartbeat — Heartbeat (será criado na Fase 1A do backend)  
- GET /api/agents/:id/config — Buscar config/policy (será criado na Fase 1A do backend)

### Prioridade de Implementação
1. Primeiro: Rebranding (mais simples, garante que o fork compila)
2. Segundo: Agent Registration + Heartbeat
3. Terceiro: Policy/Config Sync
4. Por último: Testes end-to-end com backend MFA-Zerobox
