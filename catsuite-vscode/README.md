# CatSuite Studio

Build your next CatSuite plugin without leaving Visual Studio Code.

CatSuite Studio is a development workspace for JavaScript plugins, custom commands and workflows for the **CatSuite Android app**. Write scripts with SDK suggestions, validate your project, preview its behavior with local fixtures and build signed plugin packages from one place.

**Explore the app:** [netcattest.com/catsuite](https://netcattest.com/catsuite)

## Install

[Install from the VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=NetCatTest.catsuite-studio) · [Download VSIX 1.2.0](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catsuite-studio-1.2.0.vsix) · [SHA-256](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/SHA256SUMS.txt)

In VS Code, open **Extensions → ⋯ → Install from VSIX** and select the downloaded file. To install directly from the Marketplace:

```sh
code --install-extension NetCatTest.catsuite-studio
```

**Português brasileiro:** no VS Code, abra **Extensões → ⋯ → Instalar do VSIX** e selecione o arquivo baixado. O link do Marketplace também permite instalar a extensão.

## What is CatSuite?

CatSuite is an Android application for web security, API testing and QA. It brings HTTP/HTTPS traffic capture, request inspection, testing and evidence organization into a mobile workspace. CatSuite Studio helps developers extend that workspace with their own tools.

## Your plugin workbench

- **Write with the CatSuite SDK.** Type `cat.` for API suggestions and contextual help. Suggestions are available across editor languages and can be limited to CatSuite projects in settings.
- **Start from a working template.** Type `catplug` to insert a script template, or use the creation wizard for panels and commands, traffic analysis, header changes, workflow steps or parsers.
- **Keep the code in the editor.** Textual `.catplug` and `.catjs` files support JavaScript editing, syntax highlighting, snippets and diagnostics. Compiled packages have a separate inspector.
- **Validate before packaging.** Check manifests, permissions, SDK usage, file hashes and workflow connections while developing.
- **Preview with local fixtures.** Run scripts in an isolated QuickJS preview and inspect registered tabs, findings, request changes and emitted artifacts.
- **Build signed plugins.** Create `.catplug` packages with a signing identity and inspect package integrity and author fingerprints.
- **Protect portable files.** Inspect password-protected packages and manage encrypted signing-identity backups.
- **Create editable drafts.** Turn an existing plugin package into a project copy while preserving the original package and its origin information.
- **Make VS Code feel like CatSuite.** Choose the black-and-yellow CatSuite Cyber theme, the CatSuite Comfort theme or the dedicated file icons. Restore your previous style from the extension commands.
- **Work in English or Brazilian Portuguese.** Choose the panel language in CatSuite Studio settings, or follow the editor language.

## Get started

1. Open a folder in Visual Studio Code.
2. Open the command palette and run **CatSuite: Create extension**.
3. Select a template and open its JavaScript entry script.
4. Type `cat.` to explore the SDK, then run **CatSuite: Validate project**.
5. Run **CatSuite: Test with a local fixture** to inspect the preview.
6. When the project is ready, run **CatSuite: Build signed .catplug** and import the resulting package into a CatSuite app version that supports extensions.

For a quick script, run **CatSuite: New CatPlug script**, or create an empty `.catjs` or textual `.catplug` file and type `catplug`.

## Files and workflows

| File | Purpose |
| --- | --- |
| `.catjs` or textual `.catplug` | JavaScript source for development |
| `manifest.json` | Plugin identity, entry script, permissions, destinations and hashes |
| `catsuite.projeto.json` | CatSuite Studio project configuration |
| Compiled `.catplug` | Plugin package for inspection and import into a compatible app |
| `.catflow` | Workflow definition with validation and inspection |
| `.catdata` | Exported CatSuite data for inspection |

A source script is packaged through the project build command before distribution to the app. The installed CatSuite app must support the package format and SDK version requested by your plugin.

## Local preview and trust

The preview uses local fixtures and simulated host APIs. It does not send live HTTP requests or run external tools. Validate live behavior separately in your authorized CatSuite environment.

Project creation, preview, signing and export require a trusted VS Code workspace. Package inspection distinguishes a valid signature from a recognized author: verify the author's fingerprint before trusting an unfamiliar package.

## Requirements

- Visual Studio Code **1.100.0 or newer**.
- A compatible CatSuite app for installing and running exported plugins.

## About

Created by **NetCatTest** for developers building tools around CatSuite.

[Discover CatSuite](https://netcattest.com/catsuite)
