# CatBridge

Conecte o CatSuite às ferramentas do seu computador usando capacidades autorizadas, comunicação assinada e resultados rastreáveis.

[English](README.en.md)

## Baixar e executar

[Windows ZIP](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-windows-amd64.zip) · [Linux TAR.GZ](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-linux-amd64.tar.gz) · [SHA-256](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/SHA256SUMS.txt)

Baixe o pacote para seu sistema, extraia todos os arquivos e abra um terminal na pasta extraída. No Windows, o executável se chama `catbridge.exe`; no Linux, `catbridge`. A distribuição pronta não exige Go. Siga as instruções de pareamento abaixo.

## Compilar

Requer Go 1.26 ou superior.

```powershell
go build -buildvcs=false -trimpath -ldflags="-s -w" -o catbridge.exe .
```

```sh
go build -buildvcs=false -trimpath -ldflags="-s -w" -o catbridge .
```

## Conectar o celular

Escolha o endereço local do seu computador, acessível pelo celular. Os dois devem estar na mesma rede ou numa rede privada configurada por você.

```powershell
.\catbridge.exe serve -state .\private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743
```

O terminal mostra o endereço e um código de 24 números em seis grupos. No CatSuite, ative o módulo em Configurações → Extensões e abra Extensões → Conexões → Parear CatBridge. Informe o endereço e cole ou digite o código. Não é necessário QR, conta ou serviço de terceiros.

O código vale por dois minutos e autoriza um aparelho. O aplicativo verifica a identidade do Bridge antes de enviar o código no canal HTTPS autenticado. O código não fica salvo na conexão. Uma tentativa com código errado não instala a conexão.

Para gerar outro código, mantendo o servidor em execução, use outro terminal e a mesma pasta e endereço:

```powershell
.\catbridge.exe pair -state .\private-state -public https://192.168.1.20:8743
```

Para o emulador Android padrão no computador:

```powershell
.\catbridge.exe serve -state .\private-emulator -listen 127.0.0.1:8743 -public https://10.0.2.2:8743
```

Mantenha `-public` consistente com o endereço usado pelo aparelho. A identidade contém esse endereço. Se precisar mudar o hostname, use uma nova pasta de identidade e faça novo pareamento. Configure o acesso à porta na sua rede; o Bridge não modifica seu firewall.

## Ferramentas

O Bridge pode iniciar sem ferramentas. Nesse estado, o pareamento e a consulta de capacidades funcionam; executores ausentes permanecem indisponíveis.

- `nuclei.scan`: Nuclei local, templates HTTP revisados e escopo explícito.
- `http.probe`, `web.crawl`, `api.schema.test`: httpx, Katana e Schemathesis em containers Linux com intermediário de rede.
- O catálogo também inclui os adaptadores do ecossistema do SDK 1.4. A execução depende de imagens instaladas, hashes e autorização correspondentes.

```powershell
.\catbridge.exe serve -state .\private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743 -scope https://api.example.test -nuclei C:\Ferramentas\nuclei.exe -templates .\examples\templates.json
```

O manifesto de exemplo deve receber o caminho e SHA-256 do seu template revisado. O exemplo Aurora destina-se a um laboratório fictício.

Para preparar os executores prioritários, requer Docker com engine Linux, Python 3.12+ e `cryptography`:

```sh
python runtime/prepare.py --output runtime/prepared --go go --docker docker
```

Use o fingerprint de `runtime/prepared/author.sha256` ao iniciar com o manifesto assinado:

```powershell
.\catbridge.exe serve -state .\private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743 -scope https://api.example.test -tool-lock .\runtime\prepared\tools.lock.json -tool-key IMPRESSAO_DIGITAL
```

Preparação e atualização são operações administrativas do host. Extensões não selecionam executáveis, comandos de shell ou imagens arbitrárias. As ferramentas recebem somente os dados aprovados.

## Revogar

```powershell
.\catbridge.exe revoke -state .\private-state -public https://192.168.1.20:8743 -device IDENTIFICADOR_DO_APARELHO
```

Remover a conexão no aplicativo também revoga o certificado quando o Bridge está alcançável e apaga a chave local. Use o comando no host para revogar um aparelho desconectado.

## Compatibilidade

CatSuite 1.3.7+100 com o novo pareamento numérico, SDK 1.4 e CatBridge Protocol 2. Conexões existentes do Protocol 2 continuam funcionando. O canal legado de dados assinados de pareamento permanece compatível; o Bridge gera somente códigos numéricos novos. Protocol 1 não é aceito.

Mantenha a pasta de estado, chaves, certificados, códigos e logs em local privado. Restrinja o acesso ao servidor à rede necessária. Avisos e licenças das dependências estão em `THIRD_PARTY_LICENSES.txt`.

## Downloads

[Windows 64 bits](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-windows-amd64.zip) · [Linux 64 bits](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-linux-amd64.tar.gz) · [SHA-256](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/SHA256SUMS.txt)

[SDK](../catsuite-vscode/sdk/catsuite.d.ts)
