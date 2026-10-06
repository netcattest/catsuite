# CatSuite Extension SDK

**SDK 1.4.0 · API v1 · JavaScript · pt-BR / English**

[English](README.en.md) · [Baixar SDK](https://github.com/netcattest/catsuite/releases/download/sdk-1.4.0/catsuite-sdk-1.4.0.zip) · [SHA-256](https://github.com/netcattest/catsuite/releases/download/sdk-1.4.0/SHA256SUMS.txt) · [CatSuite Studio](https://marketplace.visualstudio.com/items?itemName=NetCatTest.catsuite-studio)

SDK para criar extensões do CatSuite: eventos HTTP, alteração de tráfego, comandos, menus, abas nativas, armazenamento, achados, parsers, etapas de fluxo e capacidades do CatBridge.

## Começar

1. Instale o CatSuite Studio no VS Code e extraia o SDK.
2. Abra uma pasta de `exemplos` como projeto, por exemplo `exemplos/painel`.
3. Edite o arquivo indicado por `entry` em `manifest.json`. Digite `cat.` para explorar a API.
4. Use **CatSuite: Validar projeto** e a prévia local do Studio.
5. Gere o `.catplug` assinado no Studio e importe-o em uma versão do CatSuite com extensões compatíveis. Revise as permissões antes de ativar.

Os exemplos são projetos editáveis, sem assinatura de distribuição. O Studio recalcula os hashes e cria uma revisão assinada com a identidade escolhida pelo usuário.

## Conteúdo

| Arquivo ou pasta | Uso |
| --- | --- |
| `catsuite.d.ts` | Contrato completo da API e tipos para o editor. |
| `sdk.js` | Runtime de referência carregado pelo host QuickJS do CatSuite. |
| `sdk.json` | Versão e estrutura do SDK. |
| `esquemas` | Esquemas de manifesto, projeto, fluxos e dados. |
| `capability-contracts.json` | Contratos tipados das capacidades do CatBridge. |
| `exemplos` | Quinze projetos editáveis, com manifestos e fixtures. |
| `fluxos` | Seis modelos de fluxos e entradas fictícias. |

Não inclua `sdk.js` no script da extensão: o aplicativo já fornece o objeto global `cat`. Não há Node.js, DOM, `fetch`, shell ou acesso geral aos arquivos do aparelho.

## Exemplos

- **Essenciais:** painel e comandos, análise de tráfego, headers, etapa de fluxo e parser JSON.
- **Aurora:** captura, alteração, envio, análise, menu, aba, persistência, API simulada e achados.
- **Identidade:** JWT, candidatos a segredos, hipóteses de autorização e relatório.
- **APIs:** análise estática de JavaScript, endpoints e comparação OpenAPI.
- **CatBridge:** probe HTTP e proveniência dos resultados. Execução real exige conexão, ferramenta disponível e aprovação; a prévia do Studio usa simulação.

Os fluxos requerem os módulos indicados nos blocos. Importar um modelo não amplia o escopo nem autoriza envios. As fixtures usam dados fictícios. A análise de JWT não verifica assinaturas; indícios de autorização não demonstram IDOR/BOLA.

Handlers de alteração são síncronos, limitados a 100 ms. Envios e outras operações dependem das permissões e destinos aprovados pelo host. Credenciais usam referências controladas pelo aplicativo.

[Aplicativo](https://netcattest.com/catsuite) · [Código do Studio](https://github.com/netcattest/catsuite/tree/main/catsuite-vscode/) · [CatBridge](https://github.com/netcattest/catsuite/tree/main/catbridge/)
