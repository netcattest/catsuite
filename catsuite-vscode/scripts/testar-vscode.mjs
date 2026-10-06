import { runTests } from '@vscode/test-electron';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import caminho from 'node:path';
import os from 'node:os';
const executavel = process.env.CATSUITE_VSCODE_EXECUTAVEL || (process.platform === 'win32' && process.env.LOCALAPPDATA ? caminho.join(process.env.LOCALAPPDATA,'Programs','Microsoft VS Code','Code.exe') : undefined);
const raiz = await mkdtemp(caminho.join(os.tmpdir(),'catsuite-vscode-teste-'));
const entrega = caminho.resolve('artefatos'); await mkdir(entrega,{recursive:true});
try {
  const workspace = caminho.join(raiz,'projeto'); await mkdir(workspace);
  await runTests({vscodeExecutablePath:executavel,extensionDevelopmentPath:process.env.CATSUITE_EXTENSAO_TESTE || process.cwd(),extensionTestsPath:caminho.resolve('dist/testes-vscode.js'),extensionTestsEnv:{CATSUITE_TESTE_WORKSPACE:workspace,CATSUITE_TESTE_RELATORIO:caminho.join(entrega,'teste-vscode.json')},launchArgs:[workspace,'--disable-gpu','--disable-extensions','--skip-welcome','--skip-release-notes','--disable-workspace-trust','--user-data-dir',caminho.join(raiz,'perfil'),'--extensions-dir',caminho.join(raiz,'extensoes')]});
} finally { if(!caminho.basename(raiz).startsWith('catsuite-vscode-teste-')) throw Error('pasta'); await rm(raiz,{recursive:true,force:true,maxRetries:10,retryDelay:200}); }
