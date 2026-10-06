# CatSuite Extension SDK

**SDK 1.4.0 · API v1 · JavaScript · pt-BR / English**

[Português brasileiro](README.md) · [Download SDK](https://github.com/netcattest/catsuite/releases/download/sdk-1.4.0/catsuite-sdk-1.4.0.zip) · [SHA-256](https://github.com/netcattest/catsuite/releases/download/sdk-1.4.0/SHA256SUMS.txt) · [CatSuite Studio](https://marketplace.visualstudio.com/items?itemName=NetCatTest.catsuite-studio)

SDK for CatSuite extensions: HTTP events, traffic modification, commands, menus, native tabs, storage, findings, parsers, workflow steps and CatBridge capabilities.

## Get started

1. Install CatSuite Studio in VS Code and extract the SDK.
2. Open an `exemplos` folder as a project, such as `exemplos/painel`.
3. Edit the file specified by `entry` in `manifest.json`. Type `cat.` to explore the API.
4. Use **CatSuite: Validate project** and the Studio local preview.
5. Build the signed `.catplug` in Studio and import it into a CatSuite version with compatible extension support. Review permissions before enabling it.

Examples are editable projects without distribution signatures. Studio recalculates hashes and creates a signed revision with the user's chosen identity.

## Contents

| File or folder | Purpose |
| --- | --- |
| `catsuite.d.ts` | Complete API contract and editor types. |
| `sdk.js` | Reference runtime loaded by the CatSuite QuickJS host. |
| `sdk.json` | SDK version and structure. |
| `esquemas` | Manifest, project, workflow and data schemas. |
| `capability-contracts.json` | Typed CatBridge capability contracts. |
| `exemplos` | Fifteen editable projects with manifests and fixtures. |
| `fluxos` | Six workflow models and fictional inputs. |

Do not include `sdk.js` in a plugin script: the app already provides the global `cat` object. Node.js, DOM, `fetch`, shell and general device file access are unavailable.

## Examples

- **Essentials:** panels and commands, traffic analysis, headers, workflow steps and a JSON parser.
- **Aurora:** capture, modification, sending, analysis, menus, tabs, persistence, a simulated API and findings.
- **Identity:** JWT, secret candidates, authorization hypotheses and reports.
- **APIs:** static JavaScript analysis, endpoints and OpenAPI comparison.
- **CatBridge:** HTTP probing and result provenance. Real execution requires a connection, an available tool and approval; Studio preview uses simulation.

Workflows require the modules specified in their nodes. Importing a model does not expand scope or authorize requests. Fixtures use fictional data. JWT analysis does not verify signatures; authorization indicators do not demonstrate IDOR/BOLA.

Traffic modification handlers are synchronous and limited to 100 ms. Requests and other operations depend on host-approved permissions and destinations. Credentials use references controlled by the app.

[App](https://netcattest.com/catsuite) · [Studio source](https://github.com/netcattest/catsuite/tree/main/catsuite-vscode/) · [CatBridge](https://github.com/netcattest/catsuite/tree/main/catbridge/)
