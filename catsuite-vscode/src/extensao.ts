import * as vscode from 'vscode';
import { Projetos, RecursosSdk } from './projetos';
import { Linguagem } from './linguagem';
import { Atelier, Inspetor } from './interface';
import { Operacoes } from './operacoes';
import { lerArquivoSeguro } from './nucleo/pacotes';
import { classificarCatPlug } from './nucleo/edicao';
import { traduzir } from './idiomas';
export async function activate(contexto: vscode.ExtensionContext): Promise<{ projetos: Projetos; linguagem: Linguagem; operacoes: Operacoes }> {
  const projetos = new Projetos(vscode.Uri.joinPath(contexto.extensionUri,'midia/icone.png')); const recursos = new RecursosSdk(); const linguagem = new Linguagem(projetos); let operacoes: Operacoes;
  const atelier = new Atelier(contexto, nome => operacoes.executar(nome)); operacoes = new Operacoes(contexto, projetos, linguagem, atelier);
  const inspetor = new Inspetor(contexto, impressao => operacoes.reconhecer(impressao), erro => operacoes.falhar(erro), (nome,uri) => operacoes.executar(nome,uri));
  contexto.subscriptions.push(projetos, recursos, linguagem, atelier, inspetor, vscode.window.registerTreeDataProvider('catsuite.projetos', projetos), vscode.window.registerTreeDataProvider('catsuite.recursos', recursos), vscode.window.registerCustomEditorProvider('catsuite.pacote', inspetor, { supportsMultipleEditorsPerDocument: false }));
  contexto.subscriptions.push(vscode.window.registerCustomEditorProvider('catsuite.documento', inspetor, { supportsMultipleEditorsPerDocument: false }));
  const comandos = ['painel', 'criarProjeto', 'validarProjeto', 'simularProjeto', 'empacotarProjeto', 'aplicarEstilo', 'restaurarEstilo', 'inspecionarPacote', 'atualizarHashes', 'inserirRecurso', 'criarFluxo', 'verIdentidade', 'exportarIdentidade', 'importarIdentidade', 'escolherIdioma', 'abrirConfiguracoes', 'removerAutor', 'atualizar','novoScript','abrirScript','editarPacote','aplicarIcones'];
  for (const nome of comandos) contexto.subscriptions.push(vscode.commands.registerCommand('catsuite.' + nome, (parametro?: unknown) => operacoes.executar(nome, parametro instanceof vscode.Uri ? parametro : undefined, typeof parametro === 'string' ? parametro : undefined)));
  contexto.subscriptions.push(vscode.commands.registerCommand('catsuite.adicionarPermissao', (uri, permissao) => { if (uri instanceof vscode.Uri && typeof permissao === 'string') return operacoes.adicionarPermissao(uri, permissao).catch(e => operacoes.falhar(e)); return undefined; }));
  contexto.subscriptions.push(vscode.commands.registerCommand('catsuite.confiarAutor', () => operacoes.inspecionar()));
  linguagem.registrar(contexto);
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90); status.command = 'catsuite.painel'; contexto.subscriptions.push(status);
  const atualizarAtivo = () => { const projeto = projetos.localizar(); void vscode.commands.executeCommand('setContext', 'catsuite.projetoAtivo', Boolean(projeto)); if (projeto) { status.text = '$(shield) CatSuite'; status.tooltip = traduzir('painel'); status.show(); linguagem.atualizar(); } else status.hide(); };
  contexto.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(atualizarAtivo), vscode.workspace.onDidChangeTextDocument(e => linguagem.atualizar(e.document)), vscode.workspace.onDidCloseTextDocument(d => linguagem.diagnosticos.delete(d.uri)), vscode.workspace.onDidChangeWorkspaceFolders(() => { void projetos.atualizar().then(atualizarAtivo); }), vscode.workspace.onDidGrantWorkspaceTrust(() => { atelier.atualizar(); inspetor.atualizar(); }));
  const observador = vscode.workspace.createFileSystemWatcher('**/{catsuite.projeto.json,manifest.json}'); contexto.subscriptions.push(observador); for (const evento of [observador.onDidCreate, observador.onDidChange, observador.onDidDelete]) contexto.subscriptions.push(evento(() => { void projetos.atualizar().then(atualizarAtivo); }));
  contexto.subscriptions.push(vscode.workspace.onDidChangeConfiguration(e => { if (e.affectsConfiguration('catsuite')) { recursos.atualizar(); void projetos.atualizar().then(atualizarAtivo); atelier.atualizar(); inspetor.atualizar(); linguagem.atualizar(); } }));
  const aberturas=new Set<string>(); const abrirPacotes=()=>{for(const grupo of vscode.window.tabGroups.all)for(const aba of grupo.tabs){const entrada=aba.input;if(!(entrada instanceof vscode.TabInputText)||entrada.uri.scheme!=='file'||!entrada.uri.path.endsWith('.catplug')||aberturas.has(entrada.uri.toString()))continue;const chave=entrada.uri.toString();aberturas.add(chave);void lerArquivoSeguro(entrada.uri.fsPath,64*1024*1024+64).then(bytes=>{if(classificarCatPlug(bytes)==='pacote')return vscode.commands.executeCommand('vscode.openWith',entrada.uri,'catsuite.pacote',{preview:false});return undefined;}).catch(()=>{}).finally(()=>aberturas.delete(chave));}}; contexto.subscriptions.push(vscode.window.tabGroups.onDidChangeTabs(abrirPacotes));
  await projetos.atualizar(); atualizarAtivo(); return { projetos, linguagem, operacoes };
}
export function deactivate(): void {}
