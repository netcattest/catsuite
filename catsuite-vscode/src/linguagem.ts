import * as vscode from 'vscode';
import caminho from 'node:path';
import { api, Problema, Falha, permissoes } from './nucleo/contratos';
import { interpretarJson, validarManifesto, validarFluxo, analisarCodigo } from './nucleo/validacao';
import { modelos, criarModelo } from './nucleo/modelos';
import { trechoSdk, prefixoCat } from './nucleo/trechos';
import { Projetos, manifestoAtual } from './projetos';
import { traduzir, idiomaAtual } from './idiomas';
export class Linguagem implements vscode.Disposable {
  readonly diagnosticos = vscode.languages.createDiagnosticCollection('CatSuite'); private timer?: ReturnType<typeof setTimeout>; private revisoes = new Map<string, number>(); private sugestao?:ReturnType<typeof setTimeout>;
  constructor(private projetos: Projetos) {}
  atualizar(documento?: vscode.TextDocument): void { clearTimeout(this.timer); this.timer = setTimeout(() => { void this.validar(documento ?? vscode.window.activeTextEditor?.document); }, 250); }
  async validar(documento?: vscode.TextDocument): Promise<void> {
    if (!documento || documento.uri.scheme !== 'file' || documento.getText().length > 4 * 1024 * 1024) return;
    if (!vscode.workspace.getConfiguration('catsuite').get('validacaoContinua', true)) { this.diagnosticos.clear(); return; }
    const versao = documento.version; const chave = documento.uri.toString(); const revisao = (this.revisoes.get(chave) ?? 0) + 1; this.revisoes.set(chave, revisao); const texto = documento.getText(); let problemas: Problema[] = [];
    try {
      if (documento.uri.path.endsWith('.catflow')) problemas = validarFluxo(interpretarJson(texto));
      else { const projeto = this.projetos.localizar(documento.uri); if (!projeto) { if (documento.languageId !== 'catsuite-plugin') return; problemas = analisarCodigo(texto,{entry:caminho.basename(documento.uri.fsPath),permissions:permissoes}); }
        else
        if (caminho.basename(documento.uri.fsPath) === 'manifest.json') problemas = validarManifesto(interpretarJson(texto));
        else if (['javascript','catsuite-plugin'].includes(documento.languageId)) problemas = analisarCodigo(texto, await manifestoAtual(projeto));
        else return;
      }
    } catch (erro) { problemas = [{ codigo: erro instanceof Falha ? erro.codigo : 'falhaGenerica', argumentos: erro instanceof Falha ? erro.argumentos : {}, caminho: '', gravidade: 'erro' }]; }
    if (documento.isClosed || documento.version !== versao || revisao !== this.revisoes.get(chave)) return;
    this.diagnosticos.set(documento.uri, problemas.map(p => this.diagnostico(documento, p)));
  }
  diagnostico(documento: vscode.TextDocument, problema: Problema): vscode.Diagnostic {
    const linha = Math.max(0, Math.min(documento.lineCount - 1, (problema.linha ?? 1) - 1)); const coluna = Math.min(documento.lineAt(linha).text.length, problema.coluna ?? 0);
    let faixa = new vscode.Range(linha, coluna, linha, Math.min(documento.lineAt(linha).text.length, coluna + 1));
    if (!problema.linha && problema.caminho) { const campo = problema.caminho.split('.')[0]; const posicao = documento.getText().indexOf('"' + campo + '"'); if (posicao >= 0) faixa = new vscode.Range(documento.positionAt(posicao), documento.positionAt(posicao + campo!.length + 2)); }
    const d = new vscode.Diagnostic(faixa, traduzir(problema.codigo, problema.argumentos), problema.gravidade === 'erro' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning);
    d.source = 'CatSuite'; d.code = problema.codigo + (problema.argumentos?.permissao ? ':' + problema.argumentos.permissao : ''); return d;
  }
  registrar(contexto: vscode.ExtensionContext): void {
    contexto.subscriptions.push(vscode.workspace.onDidChangeTextDocument(e=>{if(e.reason||!e.contentChanges.some(c=>c.text)||!vscode.workspace.getConfiguration('catsuite').get('sugestoesGlobais',true))return;clearTimeout(this.sugestao);this.sugestao=setTimeout(()=>{const editor=vscode.window.activeTextEditor;if(!editor||editor.document.uri.toString()!==e.document.uri.toString()||editor.selection.isEmpty===false)return;const prefixo=prefixoCat(editor.document.lineAt(editor.selection.active.line).text.slice(0,editor.selection.active.character));if(prefixo && (prefixo.startsWith('cat.')||prefixo.startsWith('catplug')))void vscode.commands.executeCommand('editor.action.triggerSuggest');},100);}));
    const seletor: vscode.DocumentSelector = [{scheme:'file'}, {scheme:'untitled'}, {scheme:'vscode-remote'}];
    contexto.subscriptions.push(vscode.languages.registerCompletionItemProvider(seletor, { provideCompletionItems: (documento, posicao) => {
      if (!vscode.workspace.getConfiguration('catsuite').get('sugestoesGlobais',true) && !this.projetos.localizar(documento.uri) && documento.languageId !== 'catsuite-plugin') return undefined;
      const prefixo = prefixoCat(documento.lineAt(posicao.line).text.slice(0,posicao.character)); if (!prefixo) return undefined;
      const faixa = new vscode.Range(posicao.translate(0,-prefixo.length),posicao);
      if (prefixo === 'cat' || prefixo.startsWith('catplug')) return modelos.map((modelo,indice)=>{const item = new vscode.CompletionItem(indice === 0 ? 'catplug' : 'catplug.'+modelo,vscode.CompletionItemKind.Snippet); item.detail = traduzir('scriptModelo'); item.documentation = new vscode.MarkdownString(traduzir('modeloAjuda.'+modelo)+'\n\n'+traduzir('scriptFormato')); item.filterText = 'catplug.'+modelo; item.sortText = String(indice); item.range = faixa; item.insertText = new vscode.SnippetString(criarModelo(modelo,'Minha extensão','Autor','local.extensao').codigo+'\n${0}'); return item; });
      const prefixoCaminho = prefixo.slice(4); return Object.entries(api).filter(([nome])=>nome.startsWith(prefixoCaminho)).map(([nome,definicao])=>{ const item = new vscode.CompletionItem(nome.slice(prefixoCaminho.lastIndexOf('.')+1),vscode.CompletionItemKind.Method); item.detail = 'CatSuite SDK · '+definicao.assinatura; item.filterText = 'cat.'+nome; item.documentation = new vscode.MarkdownString((idiomaAtual()==='pt-BR'?definicao.pt:definicao.en)+'\n\n'+traduzir(definicao.permissao?'recursoPermissao':'recursoSemPermissao',{permissao:definicao.permissao ?? ''})); item.range = faixa; item.insertText = new vscode.SnippetString(trechoSdk(nome)); return item; });
    } }, '.'));
    contexto.subscriptions.push(vscode.languages.registerHoverProvider(seletor, { provideHover: (documento, posicao) => {
      if (!vscode.workspace.getConfiguration('catsuite').get('sugestoesGlobais',true) && !this.projetos.localizar(documento.uri) && documento.languageId !== 'catsuite-plugin') return undefined; const faixa = documento.getWordRangeAtPosition(posicao, /cat(?:\.[A-Za-z_][A-Za-z\d_]*)+/); if (!faixa) return undefined; const nome = documento.getText(faixa).slice(4); const d = api[nome]; if (!d) return undefined;
      const md = new vscode.MarkdownString(); md.appendCodeblock(d.assinatura, 'javascript'); md.appendText(idiomaAtual() === 'pt-BR' ? d.pt : d.en); md.appendText('\n\n' + traduzir(d.permissao ? 'recursoPermissao' : 'recursoSemPermissao', { permissao: d.permissao ?? '' })); return new vscode.Hover(md, faixa);
    } }));
    contexto.subscriptions.push(vscode.languages.registerCodeLensProvider([{ language: 'javascript', scheme: 'file' }, { language: 'json', scheme: 'file' }, {language:'catsuite-plugin',scheme:'file'}], { provideCodeLenses: documento => this.projetos.localizar(documento.uri) && (['javascript','catsuite-plugin'].includes(documento.languageId) || caminho.basename(documento.uri.fsPath) === 'manifest.json') ? ['validarProjeto', 'simularProjeto', 'empacotarProjeto'].map(c => new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), { title: traduzir(c), command: 'catsuite.' + c, arguments: [documento.uri] })) : [] }));
    contexto.subscriptions.push(vscode.languages.registerCodeActionsProvider(seletor, { provideCodeActions: (documento, _faixa, contextoAcao) => {
      if (!this.projetos.localizar(documento.uri) || !vscode.workspace.isTrusted) return [];
      return contextoAcao.diagnostics.filter(d => String(d.code).startsWith('permissaoAusente:')).map(d => { const permissao = String(d.code).split(':')[1]!; const acao = new vscode.CodeAction(traduzir('adicionarPermissao', { permissao }), vscode.CodeActionKind.QuickFix); acao.diagnostics = [d]; acao.command = { command: 'catsuite.adicionarPermissao', title: acao.title, arguments: [documento.uri, permissao] }; acao.isPreferred = true; return acao; });
    } }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
  }
  dispose(): void { clearTimeout(this.timer);clearTimeout(this.sugestao); this.revisoes.clear(); this.diagnosticos.dispose(); }
}
