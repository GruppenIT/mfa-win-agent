# Guia de Configuração: IdP Broker com VMware vCenter

## Visão Geral

Este guia descreve o procedimento completo para configurar o módulo **IdP Broker** do
MFA Gruppen RADIUS Agent como fonte de autenticação SAML 2.0 para o VMware vCenter
Server 7.x/8.x. Com esta integração, todos os logins no vCenter passam a exigir
autenticação MFA (senha do AD + código TOTP).

### Fluxo de Autenticação

```
Usuário acessa vCenter /ui
        │
        ▼
vCenter detecta IdP externo configurado
        │
        ▼
Redireciona para o Agent (/saml/sso) com SAMLRequest
        │
        ▼
Agent exibe tela de login (username + senha AD + TOTP)
        │
        ▼
Agent valida senha contra AD/LDAP (bind)
        │
        ▼
Agent valida TOTP contra API do MFA Gruppen
        │
        ▼
Agent gera SAML Assertion assinada (UPN, grupos)
        │
        ▼
Redireciona de volta ao vCenter com SAMLResponse
        │
        ▼
vCenter aceita a assertion e cria sessão
```

---

## Pré-requisitos

| Item | Descrição |
|------|-----------|
| **Servidor Linux** | CentOS/RHEL 8+, Ubuntu 20.04+ ou similar com acesso à rede do vCenter |
| **Go 1.21+** | Para compilação do agent (ou usar binário pré-compilado) |
| **AD/LDAP** | Acesso ao Active Directory com conta de serviço para bind |
| **API Key** | Chave de API do tenant no MFA Gruppen (formato `mfa_xxxxx`) |
| **DNS/IP** | O vCenter precisa resolver o hostname do agent (ou usar IP) |
| **Porta 8443** | Liberada no firewall entre o vCenter e o servidor do agent |
| **vCenter 7.0+** | Com permissão de administrador para configurar Identity Provider |

---

## Passo 1: Compilar o Agent

```bash
# Clonar o repositório
git clone https://github.com/GruppenIT/mfa-win-agent.git
cd mfa-win-agent/radius-agent

# Compilar com versão embutida
go build -ldflags "-X main.version=1.0.0" -o mfa-gruppen-agent ./cmd/radius-agent/

# Mover o binário para local adequado
sudo cp mfa-gruppen-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/mfa-gruppen-agent
```

---

## Passo 2: Criar Estrutura de Diretórios

```bash
# Diretório de configuração
sudo mkdir -p /etc/mfa-gruppen/certs
sudo mkdir -p /etc/mfa-gruppen/templates  # opcional, para template customizado

# Diretório de logs
sudo mkdir -p /var/log/mfa-gruppen
```

---

## Passo 3: Criar o Arquivo de Configuração

Crie o arquivo `/etc/mfa-gruppen/radius-agent.yaml`:

```yaml
server:
  agent_id: ""  # será preenchido após registro no backend

# Conexão com o backend MFA Gruppen
api:
  base_url: "https://mfa.gruppen.com.br"
  key: "mfa_SUA_API_KEY_AQUI"
  timeout: 30

logging:
  level: "info"    # use "debug" durante a configuração inicial
  format: "json"

# RADIUS pode ser desabilitado se não for necessário
radius:
  enabled: false

# Configuração do IdP Broker
idp:
  enabled: true
  port: 8443

  tls:
    cert: /etc/mfa-gruppen/certs/idp.crt
    key: /etc/mfa-gruppen/certs/idp.key
    auto_generate: true  # gera certificado self-signed automaticamente

  # EntityID — DEVE ser acessível pelo vCenter
  # Use o FQDN ou IP do servidor onde o agent roda
  entity_id: "https://mfa-agent.empresa.local:8443/saml"

  session_timeout: 3600  # 1 hora

  # Service Providers confiáveis
  trusted_sps:
    - name: "vCenter"
      entity_id: "https://vcenter.empresa.local/websso"
      acs_url: "https://vcenter.empresa.local/websso/SAML2/SSO/vsphere.local"
      attributes:
        # UPN — usado pelo vCenter para identificar o usuário
        - name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
          source: "upn"
        # Grupos — usado pelo vCenter para mapeamento de permissões
        - name: "http://schemas.xmlsoap.org/claims/Group"
          source: "memberOf"

  # Configuração LDAP para autenticação primária (senha AD)
  ldap:
    use_radius_config: false
    server: "ldap://dc01.empresa.local:389"
    base_dn: "DC=empresa,DC=local"
    bind_dn: "CN=svc-mfa,OU=Service Accounts,DC=empresa,DC=local"
    bind_password: "SENHA_DA_CONTA_DE_SERVICO"
    user_filter: "(sAMAccountName=%s)"
    starttls: true
```

Proteja o arquivo de configuração:

```bash
sudo chmod 600 /etc/mfa-gruppen/radius-agent.yaml
sudo chown root:root /etc/mfa-gruppen/radius-agent.yaml
```

### Notas sobre a configuração

**`entity_id`**: Este valor é o identificador único do IdP. O vCenter usará este valor
para referenciá-lo. Deve corresponder ao hostname/IP acessível pelo vCenter.

**`trusted_sps[].entity_id`**: O EntityID do vCenter. No vCenter 7.x/8.x o padrão é
`https://<vcenter-fqdn>/websso`. Verifique na configuração do vCenter se necessário.

**`trusted_sps[].acs_url`**: URL do Assertion Consumer Service do vCenter. O padrão é
`https://<vcenter-fqdn>/websso/SAML2/SSO/vsphere.local`.

**`attributes`**: O vCenter espera pelo menos o UPN para identificar o usuário. Os
grupos são necessários para o mapeamento automático de permissões.

---

## Passo 4: Iniciar o Agent (teste manual)

```bash
# Iniciar em modo debug para verificar se tudo funciona
sudo /usr/local/bin/mfa-gruppen-agent \
  -config /etc/mfa-gruppen/radius-agent.yaml
```

Saída esperada:

```json
{"time":"2026-02-20T10:00:00Z","level":"INFO","msg":"starting mfa-gruppen-radius-agent","version":"1.0.0"}
{"time":"2026-02-20T10:00:00Z","level":"INFO","msg":"IdP module enabled","port":8443,"entity_id":"https://mfa-agent.empresa.local:8443/saml"}
{"time":"2026-02-20T10:00:00Z","level":"INFO","msg":"IdP server starting","port":8443}
```

### Verificar endpoints

```bash
# Verificar saúde do serviço
curl -k https://localhost:8443/health
# Resposta: {"status":"ok","module":"idp","sessions":0}

# Baixar metadata XML do IdP
curl -k https://mfa-agent.empresa.local:8443/saml/metadata -o idp-metadata.xml

# Verificar conteúdo do metadata
cat idp-metadata.xml
```

O metadata XML deve conter:
- O `entityID` configurado
- O certificado X.509 de assinatura (em Base64)
- Os endpoints SSO (HTTP-Redirect e HTTP-POST)
- Os formatos de NameID suportados

---

## Passo 5: Configurar o vCenter como Service Provider

### 5.1 — Obter o metadata do IdP

No servidor do agent, exporte o metadata XML:

```bash
curl -k https://mfa-agent.empresa.local:8443/saml/metadata > /tmp/mfa-idp-metadata.xml
```

Transfira o arquivo `mfa-idp-metadata.xml` para uma máquina com acesso ao vSphere Client.

### 5.2 — Configurar Identity Provider no vCenter

1. Acesse o **vSphere Client** como administrador:
   `https://vcenter.empresa.local/ui`

2. Navegue para:
   **Administration** → **Single Sign-On** → **Configuration** → **Identity Provider**

3. Clique em **Change Identity Provider** (ou **Add Identity Provider**)

4. Selecione **SAML 2.0**

5. Preencha os campos:

   | Campo | Valor |
   |-------|-------|
   | **Identity Provider Name** | MFA Gruppen |
   | **Entity ID** | `https://mfa-agent.empresa.local:8443/saml` |
   | **SSO Service URL** | `https://mfa-agent.empresa.local:8443/saml/sso` |
   | **SLO Service URL** | `https://mfa-agent.empresa.local:8443/saml/slo` |
   | **Metadata** | Importar o arquivo `mfa-idp-metadata.xml` |

   > Se o vCenter permitir apenas importação de metadata XML, basta importar o arquivo.
   > Todos os campos acima serão preenchidos automaticamente a partir do metadata.

6. Clique em **Save**

### 5.3 — Obter o EntityID e ACS URL do vCenter

Após salvar, o vCenter exibirá suas informações de SP. Anote:

- **SP Entity ID** — geralmente `https://vcenter.empresa.local/websso`
- **ACS URL** — geralmente `https://vcenter.empresa.local/websso/SAML2/SSO/vsphere.local`

Compare com os valores em `trusted_sps` no arquivo de configuração do agent. Se forem
diferentes, atualize o `radius-agent.yaml` e reinicie o agent.

### 5.4 — Certificado TLS

Se o agent estiver usando certificado self-signed (padrão com `auto_generate: true`),
o vCenter pode rejeitar a conexão. Duas opções:

**Opção A — Adicionar o certificado do agent ao trust store do vCenter:**

```bash
# No servidor do agent, copie o certificado
cat /etc/mfa-gruppen/certs/idp.crt
```

No vCenter, adicione o certificado em:
**Administration** → **Certificate Management** → **Trusted Root Certificates** → **Add**

**Opção B — Usar um certificado assinado por CA confiável:**

```yaml
# No radius-agent.yaml, aponte para certificados válidos
idp:
  tls:
    cert: /etc/mfa-gruppen/certs/idp-signed.crt
    key: /etc/mfa-gruppen/certs/idp-signed.key
    auto_generate: false
```

---

## Passo 6: Mapear Usuários e Grupos no vCenter

Para que os usuários autenticados via IdP tenham permissões no vCenter, é necessário
mapear os grupos do AD.

1. No vSphere Client, vá para:
   **Administration** → **Access Control** → **Global Permissions**

2. Clique em **Add**

3. Selecione o domínio do IdP (será listado após a configuração)

4. Busque o grupo do AD (ex: `vCenter-Admins`)

5. Atribua o role desejado (ex: `Administrator`)

6. Marque **Propagate to children** se necessário

> Os grupos são recebidos pelo vCenter através do atributo SAML
> `http://schemas.xmlsoap.org/claims/Group` configurado no `trusted_sps`.

---

## Passo 7: Criar Serviço Systemd (Produção)

Crie o arquivo `/etc/systemd/system/mfa-gruppen-agent.service`:

```ini
[Unit]
Description=MFA Gruppen RADIUS/IdP Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mfa-gruppen-agent -config /etc/mfa-gruppen/radius-agent.yaml
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536

# Segurança
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/mfa-gruppen/certs /var/log/mfa-gruppen

[Install]
WantedBy=multi-user.target
```

Ative e inicie o serviço:

```bash
sudo systemctl daemon-reload
sudo systemctl enable mfa-gruppen-agent
sudo systemctl start mfa-gruppen-agent

# Verificar status
sudo systemctl status mfa-gruppen-agent

# Acompanhar logs
sudo journalctl -u mfa-gruppen-agent -f
```

---

## Passo 8: Testar o Fluxo Completo

### 8.1 — Teste via navegador

1. Abra uma janela anônima/privada no navegador
2. Acesse `https://vcenter.empresa.local/ui`
3. O vCenter deve redirecionar para a tela de login do MFA Gruppen
4. Preencha:
   - **Username**: seu usuário do AD (ex: `joao.silva`)
   - **Password**: sua senha do AD
   - **TOTP Code**: código de 6 dígitos do app autenticador
5. Clique em **Sign In**
6. Após autenticação bem-sucedida, o navegador será redirecionado de volta ao vCenter
7. Você estará logado no vCenter com as permissões mapeadas para seus grupos

### 8.2 — Verificar eventos na plataforma MFA Gruppen

Na GUI centralizada do MFA Gruppen, verifique se os seguintes eventos foram registrados:

| Evento | Descrição |
|--------|-----------|
| `idp.auth.success` | Login bem-sucedido com usuário, SP destino e IP |
| `idp.session.created` | Sessão SAML criada para o usuário |
| `idp.metadata.requested` | Quando o vCenter solicitou o metadata (configuração) |

Em caso de falha, verifique:

| Evento | Causa Provável |
|--------|----------------|
| `idp.auth.failure` (reason: `ldap_auth_failed`) | Senha do AD incorreta ou usuário não encontrado |
| `idp.auth.totp_failure` (reason: `totp_invalid`) | Código TOTP incorreto ou expirado |

### 8.3 — Verificar health e sessões ativas

```bash
curl -k https://mfa-agent.empresa.local:8443/health
# {"status":"ok","module":"idp","sessions":1}
```

---

## Solução de Problemas

### O vCenter não redireciona para o IdP

- Verifique se o Identity Provider está configurado e ativo no vCenter
- Confirme que o `entity_id` no agent corresponde ao configurado no vCenter
- Verifique conectividade: `curl -k https://mfa-agent.empresa.local:8443/health`

### Erro "Untrusted Service Provider" na tela de login

O `entity_id` do vCenter na requisição SAML não corresponde a nenhum SP em `trusted_sps`.

```bash
# Verificar logs do agent com nível debug
# Procure pela mensagem "untrusted SP" com o entity_id recebido
```

Atualize o campo `entity_id` em `trusted_sps` para corresponder ao valor real do vCenter.

### Erro "Invalid username or password"

- Verifique as credenciais LDAP no arquivo de configuração
- Teste o bind da conta de serviço:
  ```bash
  ldapsearch -H ldap://dc01.empresa.local \
    -D "CN=svc-mfa,OU=Service Accounts,DC=empresa,DC=local" \
    -W -b "DC=empresa,DC=local" "(sAMAccountName=joao.silva)"
  ```
- Verifique se `user_filter` está correto (padrão: `(sAMAccountName=%s)`)
- Verifique se `starttls: true` é necessário para seu ambiente

### Erro "Invalid TOTP code"

- Verifique se o relógio do servidor está sincronizado (NTP)
- Confirme que o usuário tem TOTP configurado na plataforma MFA Gruppen
- Verifique se a API Key tem permissão para validar no tenant correto

### vCenter rejeita a SAML Assertion

- Verifique se o certificado do IdP está no trust store do vCenter
- Confirme que o `entity_id` no agent é idêntico ao configurado no vCenter
- Verifique se o relógio está sincronizado (assertions têm validade de 5 minutos)
- Habilite `logging.level: "debug"` para inspecionar a assertion gerada

### Certificado expirado

O certificado self-signed gerado automaticamente tem validade de **5 anos**. Para
verificar a data de expiração:

```bash
openssl x509 -in /etc/mfa-gruppen/certs/idp.crt -noout -dates
```

Para renovar, delete os arquivos e reinicie o agent:

```bash
sudo rm /etc/mfa-gruppen/certs/idp.crt /etc/mfa-gruppen/certs/idp.key
sudo systemctl restart mfa-gruppen-agent
```

> Após renovar o certificado, será necessário atualizar o metadata no vCenter
> (reimportar o metadata XML).

---

## Referência Rápida

### Linha de comando

```bash
# Iniciar com configuração padrão
mfa-gruppen-agent

# Iniciar com configuração customizada
mfa-gruppen-agent -config /caminho/para/config.yaml

# Verificar versão
mfa-gruppen-agent -version
```

### Endpoints do IdP

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/saml/metadata` | GET | Metadata XML do IdP (importar no vCenter) |
| `/saml/sso` | GET, POST | Single Sign-On (HTTP-Redirect e HTTP-POST) |
| `/saml/slo` | GET, POST | Single Logout (fase 2) |
| `/health` | GET | Health check com contagem de sessões |

### Portas

| Porta | Protocolo | Módulo | Descrição |
|-------|-----------|--------|-----------|
| 8443 | HTTPS | IdP | SAML 2.0 Identity Provider |
| 1812 | UDP | RADIUS | Autenticação RADIUS (se habilitado) |

### Atributos SAML disponíveis

| Source | Descrição | Campo LDAP |
|--------|-----------|------------|
| `username` | Nome de login (sAMAccountName) | `sAMAccountName` |
| `upn` | User Principal Name | `userPrincipalName` |
| `email` | Endereço de e-mail | `mail` |
| `displayName` | Nome completo | `displayName` |
| `memberOf` | Grupos do AD (multi-valor) | `memberOf` |
