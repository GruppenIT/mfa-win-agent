# Guia de Configuração: IdP Broker com VMware vCenter

## Visão Geral

Este guia descreve o procedimento completo para configurar o módulo **IdP Broker** do
GruppenMFA RADIUS Agent como fonte de autenticação SAML 2.0 para o VMware vCenter
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
| **Servidor Windows ou Linux** | Windows Server 2016+ / Windows 10+ ou Linux (CentOS 8+, Ubuntu 20.04+) |
| **AD/LDAP** | Acesso ao Active Directory com conta de serviço para bind |
| **API Key** | Chave de API do tenant no MFA Gruppen (formato `mfa_xxxxx`) |
| **DNS/IP** | O vCenter precisa resolver o hostname do servidor do agent |
| **Porta 8443** | Liberada no firewall entre o vCenter e o servidor do agent |
| **vCenter 7.0+** | Com permissão de administrador para configurar Identity Provider |

---

## Instalação

### Opção A — Instalação via MSI (Windows — Recomendado)

O instalador MSI é o método recomendado para ambientes Windows. Ele instala o agent como
serviço Windows, cria as estruturas de diretório e configura o Registry automaticamente.

#### A.1 — Executar o instalador

Faça download do arquivo `GruppenMFA-RadiusAgent-x64.msi` na página de releases do projeto
ou obtenha junto ao suporte Gruppen IT.

Execute o instalador como **Administrador** (duplo-clique ou via linha de comando):

```powershell
msiexec /i GruppenMFA-RadiusAgent-x64.msi
```

O wizard de instalação solicitará:

| Campo | Descrição | Exemplo |
|-------|-----------|---------|
| **Server URL** | URL do backend MFA Gruppen | `https://mfa.gruppen.com.br` |
| **API Key** | Chave de API do seu tenant | `mfa_a1b2c3d4e5f6...` |

> O instalador grava esses valores no Registry em
> `HKLM\SOFTWARE\Gruppen IT\GruppenMFA-RadiusAgent\`.

#### A.2 — Estrutura instalada

Após a instalação, os seguintes caminhos são criados:

| Caminho | Conteúdo |
|---------|----------|
| `C:\Program Files\Gruppen IT\GruppenMFA RadiusAgent\` | Binário do agent (`GruppenMFA.RadiusAgent.exe`) |
| `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\` | Configuração (`radius-agent.yaml`) |
| `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\certs\` | Certificados SAML (auto-gerados) |
| `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\Logs\` | Logs do serviço |

O instalador também registra o serviço Windows:

| Propriedade | Valor |
|-------------|-------|
| **Nome do serviço** | `GruppenMFARadiusAgent` |
| **Nome de exibição** | GruppenMFA RADIUS/IdP Agent |
| **Tipo de início** | Automático |
| **Conta** | LocalSystem |

#### A.3 — Instalação silenciosa (GPO / SCCM)

Para deploy em massa sem interação do usuário:

```powershell
msiexec /i GruppenMFA-RadiusAgent-x64.msi /qn ^
  SERVER_URL="https://mfa.gruppen.com.br" ^
  API_KEY="mfa_a1b2c3d4e5f6..."
```

Parâmetros adicionais opcionais:

| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `SERVER_URL` | URL do backend MFA Gruppen | `https://mfa.gruppen.com.br` |
| `API_KEY` | API Key do tenant | *(obrigatório)* |
| `IDP_PORT` | Porta HTTPS do IdP | `8443` |
| `RADIUS_ENABLED` | Habilitar módulo RADIUS (`1`/`0`) | `0` |
| `RADIUS_PORT` | Porta UDP do RADIUS | `1812` |
| `RADIUS_SECRET` | Shared secret RADIUS | *(obrigatório se RADIUS habilitado)* |

Exemplo com RADIUS habilitado:

```powershell
msiexec /i GruppenMFA-RadiusAgent-x64.msi /qn ^
  SERVER_URL="https://mfa.gruppen.com.br" ^
  API_KEY="mfa_a1b2c3d4e5f6..." ^
  RADIUS_ENABLED="1" ^
  RADIUS_SECRET="meu_secret_radius"
```

#### A.4 — Atualização via MSI

O instalador suporta atualização in-place (mesma versão ou superior):

```powershell
msiexec /i GruppenMFA-RadiusAgent-x64-nova-versao.msi /qn
```

- A configuração existente (`radius-agent.yaml`) é preservada
- Os valores de API Key e Server URL são lidos do Registry
- Certificados existentes não são sobrescritos
- O serviço é reiniciado automaticamente após a atualização

#### A.5 — Desinstalação

Via Painel de Controle:
**Configurações** → **Aplicativos** → **GruppenMFA RADIUS/IdP Agent** → **Desinstalar**

Via linha de comando:

```powershell
msiexec /x GruppenMFA-RadiusAgent-x64.msi /qn
```

> A desinstalação remove o binário e o serviço, mas **preserva** a pasta
> `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\` com configuração, certs e logs.

---

### Opção B — Instalação manual (Linux)

Para ambientes Linux, compile e instale manualmente.

#### B.1 — Compilar o agent

```bash
# Clonar o repositório
git clone https://github.com/GruppenIT/mfa-win-agent.git
cd mfa-win-agent/radius-agent

# Compilar (requer Go 1.21+)
go build -ldflags "-X main.version=1.0.0" -o mfa-gruppen-agent ./cmd/radius-agent/

# Instalar o binário
sudo cp mfa-gruppen-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/mfa-gruppen-agent
```

#### B.2 — Criar estrutura de diretórios

```bash
sudo mkdir -p /etc/mfa-gruppen/certs
sudo mkdir -p /var/log/mfa-gruppen
```

#### B.3 — Criar serviço systemd

Crie o arquivo `/etc/systemd/system/mfa-gruppen-agent.service`:

```ini
[Unit]
Description=GruppenMFA RADIUS/IdP Agent
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

```bash
sudo systemctl daemon-reload
sudo systemctl enable mfa-gruppen-agent
```

---

## Configuração do Agent

Independente do método de instalação, o agent é configurado via arquivo YAML.

| Plataforma | Caminho do arquivo |
|------------|-------------------|
| **Windows** | `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\radius-agent.yaml` |
| **Linux** | `/etc/mfa-gruppen/radius-agent.yaml` |

### Arquivo de configuração completo

Edite o arquivo com as configurações do seu ambiente:

```yaml
server:
  agent_id: ""  # preenchido automaticamente pelo backend

# Conexão com o backend MFA Gruppen
api:
  base_url: "https://mfa.gruppen.com.br"
  key: "mfa_SUA_API_KEY_AQUI"
  timeout: 30

logging:
  level: "info"    # use "debug" durante a configuração inicial
  format: "json"

# RADIUS — desabilite se não for necessário
radius:
  enabled: false

# Configuração do IdP Broker
idp:
  enabled: true
  port: 8443

  tls:
    # Windows: C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\certs\idp.crt
    # Linux:   /etc/mfa-gruppen/certs/idp.crt
    cert: ""   # deixe vazio para usar o caminho padrão da plataforma
    key: ""    # deixe vazio para usar o caminho padrão da plataforma
    auto_generate: true  # gera certificado self-signed se não existir

  # EntityID — DEVE ser acessível pelo vCenter via rede
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

  # Autenticação primária contra AD/LDAP
  ldap:
    use_radius_config: false
    server: "ldap://dc01.empresa.local:389"
    base_dn: "DC=empresa,DC=local"
    bind_dn: "CN=svc-mfa,OU=Service Accounts,DC=empresa,DC=local"
    bind_password: "SENHA_DA_CONTA_DE_SERVICO"
    user_filter: "(sAMAccountName=%s)"
    starttls: true
```

### Notas sobre campos importantes

**`entity_id`**: Identificador único do IdP. O vCenter usará este valor para
referenciá-lo. Deve conter o hostname/IP acessível pelo vCenter na rede.

**`trusted_sps[].entity_id`**: O EntityID do vCenter. No vCenter 7.x/8.x o padrão é
`https://<vcenter-fqdn>/websso`. Verifique na configuração do vCenter se necessário.

**`trusted_sps[].acs_url`**: URL do Assertion Consumer Service do vCenter. O padrão é
`https://<vcenter-fqdn>/websso/SAML2/SSO/vsphere.local`.

**`attributes`**: O vCenter espera pelo menos o UPN para identificar o usuário. Os
grupos são necessários para o mapeamento automático de permissões.

**`ldap.bind_password`**: Proteja o arquivo de configuração para que apenas o usuário
do serviço possa lê-lo (ver seção de permissões abaixo).

### Proteger o arquivo de configuração

**Windows** (PowerShell como Administrador):

```powershell
$path = "C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\radius-agent.yaml"
$acl = Get-Acl $path
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "Allow")
$acl.AddAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $path $acl
```

**Linux**:

```bash
sudo chmod 600 /etc/mfa-gruppen/radius-agent.yaml
sudo chown root:root /etc/mfa-gruppen/radius-agent.yaml
```

---

## Iniciar o Serviço e Validar

### Windows

```powershell
# Iniciar o serviço
Start-Service GruppenMFARadiusAgent

# Verificar status
Get-Service GruppenMFARadiusAgent

# Acompanhar logs (PowerShell)
Get-Content "C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\Logs\agent-service-*.log" -Tail 50 -Wait
```

Ou via `services.msc`: localize **GruppenMFA RADIUS/IdP Agent** e clique em **Iniciar**.

### Linux

```bash
sudo systemctl start mfa-gruppen-agent
sudo systemctl status mfa-gruppen-agent

# Acompanhar logs
sudo journalctl -u mfa-gruppen-agent -f
```

### Verificar endpoints

Após iniciar o serviço, valide que o IdP está respondendo:

```powershell
# Health check (Windows PowerShell — ignore erros de certificado self-signed)
Invoke-WebRequest -Uri "https://localhost:8443/health" -SkipCertificateCheck | Select-Object -ExpandProperty Content
# Resposta esperada: {"status":"ok","module":"idp","sessions":0}

# Baixar metadata XML
Invoke-WebRequest -Uri "https://mfa-agent.empresa.local:8443/saml/metadata" -SkipCertificateCheck -OutFile idp-metadata.xml
```

```bash
# Health check (Linux)
curl -k https://localhost:8443/health
# Resposta esperada: {"status":"ok","module":"idp","sessions":0}

# Baixar metadata XML
curl -k https://mfa-agent.empresa.local:8443/saml/metadata -o idp-metadata.xml
```

O metadata XML deve conter:
- O `entityID` configurado
- O certificado X.509 de assinatura (em Base64)
- Os endpoints SSO (HTTP-Redirect e HTTP-POST)
- Os formatos de NameID suportados

---

## Configurar o vCenter como Service Provider

### 1 — Obter o metadata do IdP

Baixe o metadata XML do agent conforme a seção anterior. Transfira o arquivo
`idp-metadata.xml` para uma máquina com acesso ao vSphere Client.

### 2 — Configurar Identity Provider no vCenter

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
   | **Metadata** | Importar o arquivo `idp-metadata.xml` |

   > Se o vCenter permitir importação de metadata XML, basta importar o arquivo.
   > Todos os campos acima serão preenchidos automaticamente a partir do metadata.

6. Clique em **Save**

### 3 — Verificar EntityID e ACS URL do vCenter

Após salvar, o vCenter exibirá suas informações de SP. Anote:

- **SP Entity ID** — geralmente `https://vcenter.empresa.local/websso`
- **ACS URL** — geralmente `https://vcenter.empresa.local/websso/SAML2/SSO/vsphere.local`

Compare com os valores em `trusted_sps` no arquivo de configuração do agent. Se forem
diferentes, atualize o `radius-agent.yaml` e reinicie o serviço.

### 4 — Certificado TLS

Se o agent estiver usando certificado self-signed (padrão com `auto_generate: true`),
o vCenter pode rejeitar a conexão TLS. Duas opções:

**Opção A — Adicionar o certificado do agent ao trust store do vCenter:**

No servidor do agent, exporte o certificado:

```powershell
# Windows
Get-Content "C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\certs\idp.crt"
```

```bash
# Linux
cat /etc/mfa-gruppen/certs/idp.crt
```

No vCenter, adicione o certificado em:
**Administration** → **Certificate Management** → **Trusted Root Certificates** → **Add**

**Opção B — Usar um certificado assinado por CA corporativa:**

Coloque os arquivos do certificado no diretório de certs e edite o `radius-agent.yaml`:

```yaml
idp:
  tls:
    cert: "C:\\ProgramData\\Gruppen IT\\GruppenMFA RadiusAgent\\certs\\idp-signed.crt"
    key: "C:\\ProgramData\\Gruppen IT\\GruppenMFA RadiusAgent\\certs\\idp-signed.key"
    auto_generate: false
```

Reinicie o serviço após a alteração.

---

## Mapear Usuários e Grupos no vCenter

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

## Testar o Fluxo Completo

### Teste via navegador

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

### Verificar eventos na plataforma MFA Gruppen

Na GUI centralizada do MFA Gruppen, verifique se os seguintes eventos foram registrados:

| Evento | Descrição |
|--------|-----------|
| `idp.auth.success` | Login bem-sucedido com usuário, SP destino e IP |
| `idp.session.created` | Sessão SAML criada para o usuário |
| `idp.metadata.requested` | vCenter solicitou o metadata (configuração) |

Em caso de falha, verifique:

| Evento | Causa Provável |
|--------|----------------|
| `idp.auth.failure` (reason: `ldap_auth_failed`) | Senha do AD incorreta ou usuário não encontrado |
| `idp.auth.totp_failure` (reason: `totp_invalid`) | Código TOTP incorreto ou expirado |

### Verificar health e sessões ativas

```powershell
# Windows
Invoke-WebRequest -Uri "https://localhost:8443/health" -SkipCertificateCheck
```

```bash
# Linux
curl -k https://localhost:8443/health
# {"status":"ok","module":"idp","sessions":1}
```

---

## Gerenciamento do Serviço

### Windows

| Ação | Comando (PowerShell) | Alternativa (services.msc) |
|------|---------------------|---------------------------|
| Iniciar | `Start-Service GruppenMFARadiusAgent` | Botão direito → Iniciar |
| Parar | `Stop-Service GruppenMFARadiusAgent` | Botão direito → Parar |
| Reiniciar | `Restart-Service GruppenMFARadiusAgent` | Botão direito → Reiniciar |
| Status | `Get-Service GruppenMFARadiusAgent` | Coluna "Status" |
| Logs | `Get-Content "...\Logs\agent-service-*.log" -Tail 100` | Event Viewer |

Registry do serviço (para referência ou diagnóstico):

```
HKLM\SOFTWARE\Gruppen IT\GruppenMFA-RadiusAgent\
├── api_key          (REG_SZ)  — API Key do tenant
├── server_url       (REG_SZ)  — URL do backend
├── config_hash      (REG_SZ)  — Hash da config sincronizada
└── agent_id         (REG_SZ)  — ID do agent no backend
```

### Linux

| Ação | Comando |
|------|---------|
| Iniciar | `sudo systemctl start mfa-gruppen-agent` |
| Parar | `sudo systemctl stop mfa-gruppen-agent` |
| Reiniciar | `sudo systemctl restart mfa-gruppen-agent` |
| Status | `sudo systemctl status mfa-gruppen-agent` |
| Logs | `sudo journalctl -u mfa-gruppen-agent -f` |
| Habilitar no boot | `sudo systemctl enable mfa-gruppen-agent` |

---

## Solução de Problemas

### O vCenter não redireciona para o IdP

- Verifique se o Identity Provider está configurado e ativo no vCenter
- Confirme que o `entity_id` no agent corresponde ao configurado no vCenter
- Teste conectividade a partir do vCenter (ou de outra máquina na mesma rede):
  ```
  curl -k https://mfa-agent.empresa.local:8443/health
  ```
- No Windows, verifique se o Firewall permite conexões na porta 8443:
  ```powershell
  New-NetFirewallRule -DisplayName "GruppenMFA IdP" -Direction Inbound -Port 8443 -Protocol TCP -Action Allow
  ```

### Erro "Untrusted Service Provider" na tela de login

O `entity_id` do vCenter na requisição SAML não corresponde a nenhum SP em `trusted_sps`.

Habilite `logging.level: "debug"` no YAML, reinicie o serviço e procure nos logs pela
mensagem `"untrusted SP"` com o `entity_id` recebido. Atualize o campo `entity_id` em
`trusted_sps` para corresponder ao valor real do vCenter.

### Erro "Invalid username or password"

- Verifique as credenciais LDAP no arquivo de configuração
- Teste o bind da conta de serviço manualmente:
  ```bash
  ldapsearch -H ldap://dc01.empresa.local \
    -D "CN=svc-mfa,OU=Service Accounts,DC=empresa,DC=local" \
    -W -b "DC=empresa,DC=local" "(sAMAccountName=joao.silva)"
  ```
- Verifique se `user_filter` está correto (padrão: `(sAMAccountName=%s)`)
- Verifique se `starttls: true` é necessário para seu ambiente

### Erro "Invalid TOTP code"

- Verifique se o relógio do servidor está sincronizado via NTP:
  ```powershell
  # Windows
  w32tm /query /status
  ```
  ```bash
  # Linux
  timedatectl status
  ```
- Confirme que o usuário tem TOTP configurado na plataforma MFA Gruppen
- Verifique se a API Key tem permissão para validar no tenant correto

### vCenter rejeita a SAML Assertion

- Verifique se o certificado do IdP está no trust store do vCenter
- Confirme que o `entity_id` no agent é idêntico ao configurado no vCenter
- Verifique se os relógios estão sincronizados (assertions têm validade de 5 minutos)
- Habilite `logging.level: "debug"` para inspecionar a assertion gerada

### Serviço não inicia (Windows)

Verifique o Event Viewer:
**Event Viewer** → **Windows Logs** → **Application** → filtrar por fonte `GruppenMFARadiusAgent`

Causas comuns:
- Arquivo `radius-agent.yaml` não encontrado ou com erro de sintaxe
- Porta 8443 já em uso por outro processo
- Sem permissão para ler os certificados

Teste manualmente no prompt de comando:

```powershell
& "C:\Program Files\Gruppen IT\GruppenMFA RadiusAgent\GruppenMFA.RadiusAgent.exe" -config "C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\radius-agent.yaml"
```

### Renovar certificado expirado

O certificado self-signed tem validade de **5 anos**. Para verificar a expiração:

```powershell
# Windows
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\certs\idp.crt")
$cert.NotAfter
```

```bash
# Linux
openssl x509 -in /etc/mfa-gruppen/certs/idp.crt -noout -dates
```

Para renovar, remova os arquivos e reinicie o serviço:

```powershell
# Windows
Remove-Item "C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\certs\idp.crt"
Remove-Item "C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\certs\idp.key"
Restart-Service GruppenMFARadiusAgent
```

```bash
# Linux
sudo rm /etc/mfa-gruppen/certs/idp.crt /etc/mfa-gruppen/certs/idp.key
sudo systemctl restart mfa-gruppen-agent
```

> Após renovar o certificado, reimporte o metadata XML no vCenter
> (o certificado de assinatura mudou).

---

## Referência Rápida

### Caminhos de instalação (Windows)

| Recurso | Caminho |
|---------|---------|
| Binário | `C:\Program Files\Gruppen IT\GruppenMFA RadiusAgent\` |
| Configuração | `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\radius-agent.yaml` |
| Certificados | `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\certs\` |
| Logs | `C:\ProgramData\Gruppen IT\GruppenMFA RadiusAgent\Logs\` |
| Registry | `HKLM\SOFTWARE\Gruppen IT\GruppenMFA-RadiusAgent\` |

### Caminhos de instalação (Linux)

| Recurso | Caminho |
|---------|---------|
| Binário | `/usr/local/bin/mfa-gruppen-agent` |
| Configuração | `/etc/mfa-gruppen/radius-agent.yaml` |
| Certificados | `/etc/mfa-gruppen/certs/` |
| Logs | `journalctl -u mfa-gruppen-agent` |
| Serviço | `/etc/systemd/system/mfa-gruppen-agent.service` |

### Linha de comando

```powershell
# Iniciar com configuração padrão (Windows)
GruppenMFA.RadiusAgent.exe

# Iniciar com configuração customizada
GruppenMFA.RadiusAgent.exe -config "C:\caminho\para\config.yaml"

# Verificar versão
GruppenMFA.RadiusAgent.exe -version
```

```bash
# Linux
mfa-gruppen-agent -config /etc/mfa-gruppen/radius-agent.yaml
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
