import * as vscode from 'vscode';
import caminho from 'node:path';
import { api, Objeto } from './nucleo/contratos';
import { interpretarJson } from './nucleo/validacao';
import { lerDentro } from './nucleo/pacotes';
import { traduzir, idiomaAtual } from './idiomas';
export type ReferenciaProjeto = { pasta: string; uri: vscode.Uri; nome: string; id: string };
export class Projetos implements vscode.TreeDataProvider<vscode.TreeItem>, vscode.Disposable {
  constructor(private icone?:vscode.Uri) {}
  private evento = new vscode.EventEmitter<void>(); readonly onDidChangeTreeData = this.evento.event;
  lista: ReferenciaProjeto[] = []; private revisao = 0;
  async atualizar(): Promise<void> {
    const revisao = ++this.revisao; const encontrados = await vscode.workspace.findFiles('**/catsuite.projeto.json', '**/{node_modules,.git,dist,build,.vscode-test}/**', 50); const lista: ReferenciaProjeto[] = [];
    for (const uri of encontrados) { if (uri.scheme !== 'file') continue; const pasta = caminho.dirname(uri.fsPath); try { const m = interpretarJson((await lerDentro(pasta, 'manifest.json', 64 * 1024)).toString('utf8')); lista.push({ pasta, uri, nome: String(m.name?.[idiomaAtual()] ?? m.name?.['pt-BR'] ?? m.name?.en ?? m.id), id: String(m.id) }); } catch { lista.push({ pasta, uri, nome: caminho.basename(pasta), id: '' }); } }
    if (revisao !== this.revisao) return; this.lista = lista; this.evento.fire(); await vscode.commands.executeCommand('setContext', 'catsuite.semProjetos', lista.length === 0);
  }
  localizar(uri?: vscode.Uri): ReferenciaProjeto | undefined {
    const atual = uri ?? vscode.window.activeTextEditor?.document.uri;
    if (!atual || atual.scheme !== 'file') return undefined;
    return this.lista.filter(p => { const relativo = caminho.relative(p.pasta, atual.fsPath); return relativo === '' || !relativo.startsWith('..') && !caminho.isAbsolute(relativo); }).sort((a, b) => b.pasta.length - a.pasta.length)[0];
  }
  async escolher(uri?: vscode.Uri): Promise<ReferenciaProjeto | undefined> {
    await this.atualizar(); const projeto = this.localizar(uri); if (projeto) return projeto;
    if (this.lista.length === 1) return this.lista[0];
    if (!this.lista.length) { void vscode.window.showInformationMessage(traduzir('workspaceNecessario')); return undefined; }
    const selecionado = await vscode.window.showQuickPick(this.lista.map(p => ({ label: p.nome, description: p.id, projeto: p })), { placeHolder: traduzir('escolherProjeto'), matchOnDescription: true }); return selecionado?.projeto;
  }
  getTreeItem(item: vscode.TreeItem): vscode.TreeItem { return item; }
  getChildren(elemento?: vscode.TreeItem): vscode.TreeItem[] {
    if (!elemento) return this.lista.map(p => { const item = new vscode.TreeItem(p.nome, vscode.TreeItemCollapsibleState.Expanded); item.id = p.pasta; item.description = p.id; item.tooltip = p.nome; item.iconPath = this.icone ?? new vscode.ThemeIcon('package'); item.contextValue = 'catsuite.projeto'; return item; });
    const projeto = this.lista.find(p => p.pasta === elemento.id); if (!projeto) return [];
    return [['manifest.json', 'json'], ['src/principal.js', 'symbol-method'], ['catsuite.projeto.json', 'settings'], ['fixtures/resposta.json', 'beaker']].map(([nome, icone]) => { const uri = vscode.Uri.file(caminho.join(projeto.pasta, nome!)); const item = new vscode.TreeItem(nome!); item.resourceUri = uri; item.iconPath = new vscode.ThemeIcon(icone!); item.command = { command: 'vscode.open', title: traduzir('abrirCodigo'), arguments: [uri] }; return item; });
  }
  dispose(): void { this.revisao++; this.evento.dispose(); }
}
export class RecursosSdk implements vscode.TreeDataProvider<vscode.TreeItem>, vscode.Disposable {
  private evento = new vscode.EventEmitter<void>(); readonly onDidChangeTreeData = this.evento.event;
  atualizar(): void { this.evento.fire(); }
  dispose(): void { this.evento.dispose(); }
  getTreeItem(item: vscode.TreeItem): vscode.TreeItem { return item; }
  getChildren(): vscode.TreeItem[] { return Object.entries(api).map(([nome, recurso]) => { const item = new vscode.TreeItem('cat.' + nome); item.description = recurso.permissao; item.tooltip = idiomaAtual() === 'pt-BR' ? recurso.pt : recurso.en; item.iconPath = new vscode.ThemeIcon(recurso.permissao ? 'lock' : 'symbol-method'); item.command = { command: 'catsuite.inserirRecurso', title: traduzir('inserirRecurso'), arguments: [nome] }; return item; }); }
}
export async function manifestoAtual(projeto: ReferenciaProjeto): Promise<Objeto> { const uri = vscode.Uri.file(caminho.join(projeto.pasta, 'manifest.json')); const aberto = vscode.workspace.textDocuments.find(d => d.uri.toString() === uri.toString()); return interpretarJson(aberto?.getText() ?? (await lerDentro(projeto.pasta, 'manifest.json', 64 * 1024)).toString('utf8')); }
