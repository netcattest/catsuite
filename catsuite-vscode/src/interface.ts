import * as vscode from 'vscode';
import caminho from 'node:path';
import { randomBytes as bytesAleatorios } from 'node:crypto';
import { Objeto, Falha } from './nucleo/contratos';
import { ocultarSegredos, selado } from './nucleo/seguranca';
import { inspecionar, lerArquivoSeguro } from './nucleo/pacotes';
import { idiomaAtual, rotulos, traduzir } from './idiomas';
import { classificarCatPlug } from './nucleo/edicao';
import { trabalhar } from './trabalhador';
export type EstadoPainel = { modo: 'inicio' | 'projeto' | 'previa' | 'arquivo'; dados: Objeto };
function escapar(texto: string): string { return texto.replace(/[&<>"']/g, caractere => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[caractere]!)); }
export function htmlPainel(webview: vscode.Webview, contexto: vscode.ExtensionContext): string {
  const nonce = bytesAleatorios(24).toString('base64'); const css = webview.asWebviewUri(vscode.Uri.joinPath(contexto.extensionUri, 'midia/atelier.css')); const js = webview.asWebviewUri(vscode.Uri.joinPath(contexto.extensionUri, 'midia/atelier.js')); const icone = webview.asWebviewUri(vscode.Uri.joinPath(contexto.extensionUri, 'midia/icone.png'));
  return `<!DOCTYPE html><html lang="${idiomaAtual()}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource}; style-src ${webview.cspSource}; script-src 'nonce-${nonce}'; connect-src 'none'; base-uri 'none'; form-action 'none'"><title>${escapar(traduzir('painel'))}</title><link rel="stylesheet" href="${css}"></head><body><main id="app" aria-busy="true"><header class="marca"><img src="${icone}" width="36" height="36" alt=""><span>CatSuite <strong>Studio</strong></span><span class="selo">SDK 1.4</span></header><section class="inicio"><p class="sobretitulo">CATSUITE STUDIO</p><h1>${escapar(traduzir('painel'))}</h1></section></main><script nonce="${nonce}" src="${js}"></script></body></html>`;
}
export class Atelier implements vscode.Disposable {
  private painel?: vscode.WebviewPanel; private estado: EstadoPainel = { modo: 'inicio', dados: {} };
  constructor(private contexto: vscode.ExtensionContext, private acao: (nome: string) => Promise<unknown>) {}
  abrir(estado?: EstadoPainel): void {
    if (estado) this.estado = estado;
    if (!this.painel) {
      this.painel = vscode.window.createWebviewPanel('catsuite.atelier', traduzir('painel'), vscode.ViewColumn.One, { enableScripts: true, retainContextWhenHidden: false, localResourceRoots: [vscode.Uri.joinPath(this.contexto.extensionUri, 'midia')] });
      this.painel.webview.html = htmlPainel(this.painel.webview, this.contexto);
      this.painel.webview.onDidReceiveMessage(m => { if (m?.tipo === 'pronto') this.atualizar(); else if (m?.tipo === 'acao' && typeof m.acao === 'string' && ['criarProjeto', 'validarProjeto', 'simularProjeto', 'empacotarProjeto', 'aplicarEstilo', 'restaurarEstilo', 'escolherIdioma', 'abrirConfiguracoes', 'inspecionarPacote', 'verIdentidade', 'criarFluxo', 'abrirManifesto', 'abrirScript', 'novoScript', 'aplicarIcones'].includes(m.acao)) void this.acao(m.acao); }, undefined, this.contexto.subscriptions);
      this.painel.onDidDispose(() => { this.painel = undefined; this.estado = { modo: 'inicio', dados: {} }; }, undefined, this.contexto.subscriptions);
      this.painel.onDidChangeViewState(e => { if (e.webviewPanel.visible) this.atualizar(); }, undefined, this.contexto.subscriptions);
    } else this.painel.reveal(vscode.ViewColumn.One);
    this.atualizar();
  }
  atualizar(): void { if (!this.painel) return; this.painel.title = traduzir('painel'); void this.painel.webview.postMessage({ tipo: 'estado', recursos:{logo:this.painel.webview.asWebviewUri(vscode.Uri.joinPath(this.contexto.extensionUri,'midia/icone.png')).toString()}, estado: ocultarSegredos(this.estado), rotulos: rotulos(), idioma: idiomaAtual(), confiavel: vscode.workspace.isTrusted, estilo: vscode.workspace.getConfiguration('catsuite').get('estiloPainel', 'catsuite') }); }
  dispose(): void { this.painel?.dispose(); }
}
export class Inspetor implements vscode.CustomReadonlyEditorProvider, vscode.Disposable {
  private paineis = new Set<{ painel: vscode.WebviewPanel; atualizar: () => void }>();
  constructor(private contexto: vscode.ExtensionContext, private reconhecer: (impressao: string) => Promise<void>, private falhar: (erro: unknown) => void, private acao: (nome: string, uri?:vscode.Uri) => Promise<unknown>) {}
  async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> { if (!['file', 'vscode-remote'].includes(uri.scheme)) throw new Falha('virtualNaoSuportado'); await lerArquivoSeguro(uri.fsPath, 64 * 1024 * 1024 + 64); return { uri, dispose() {} }; }
  async resolveCustomEditor(documento: vscode.CustomDocument, painel: vscode.WebviewPanel): Promise<void> {
    let estado: Objeto = {}; let terminou = false; let revisao = 0; const bytes = await lerArquivoSeguro(documento.uri.fsPath, 64 * 1024 * 1024 + 64); const protegido = selado(bytes);
    if(caminho.extname(documento.uri.fsPath)==='.catplug' && classificarCatPlug(bytes)==='script'){ await vscode.commands.executeCommand('vscode.openWith',documento.uri,'default',{viewColumn:painel.viewColumn,preview:false});painel.dispose();return; }
    const carregar = async (conteudo: Buffer = bytes) => { const corrente = ++revisao; const resultado = await inspecionar(conteudo, caminho.extname(documento.uri.fsPath)); if (!terminou && corrente === revisao) estado = resultado; };
    painel.webview.options = { enableScripts: true, localResourceRoots: [vscode.Uri.joinPath(this.contexto.extensionUri, 'midia')] };
    painel.webview.html = htmlPainel(painel.webview, this.contexto);
    const atualizar = () => { if (!terminou) void painel.webview.postMessage({ tipo: 'estado', recursos:{logo:painel.webview.asWebviewUri(vscode.Uri.joinPath(this.contexto.extensionUri,'midia/icone.png')).toString()}, estado: { modo: 'arquivo', dados: ocultarSegredos({ ...estado, autorReconhecido: this.contexto.globalState.get<string[]>('autoresReconhecidos', []).includes(estado.assinatura?.impressao) }) }, rotulos: rotulos(), idioma: idiomaAtual(), confiavel: vscode.workspace.isTrusted, estilo: vscode.workspace.getConfiguration('catsuite').get('estiloPainel', 'catsuite') }); };
    const referencia = { painel, atualizar }; this.paineis.add(referencia);
    painel.webview.onDidReceiveMessage(async m => {
      try {
        if (m?.tipo === 'pronto') atualizar();
        if (m?.tipo !== 'acao') return;
        if(m.acao==='editarPacote' && estado.tipo==='catplug'){ await this.acao('editarPacote',documento.uri);return; }
        if (['aplicarEstilo','escolherIdioma','aplicarIcones'].includes(m.acao)) { await this.acao(m.acao); return; }
        if (m.acao === 'abrirProtegido' && protegido && !terminou) {
          const senha = await vscode.window.showInputBox({ prompt: traduzir('abrirProtegido'), password: true, ignoreFocusOut: true }); if (!senha || terminou || !painel.visible) return; const tentativa = revisao;
          await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: traduzir('preparando'), cancellable: true }, async (_p, token) => { const aberto = Buffer.from(await trabalhar<Uint8Array>(this.contexto.asAbsolutePath('dist/executor.js'), 'abrir', { bytes, senha }, token)); try { if (!terminou && painel.visible && tentativa === revisao) await carregar(aberto); } finally { aberto.fill(0); } });
          atualizar();
        } else if (m.acao === 'copiarImpressao' && typeof estado.assinatura?.impressao === 'string') await vscode.env.clipboard.writeText(estado.assinatura.impressao);
        else if (m.acao === 'confiarAutor' && estado.assinatura?.estado === 'valida' && /^[a-f0-9]{64}$/.test(estado.assinatura.impressao ?? '')) { await this.reconhecer(estado.assinatura.impressao); atualizar(); }
        else if (m.acao === 'copiarResultado' && !estado.bloqueado) await vscode.env.clipboard.writeText(JSON.stringify(ocultarSegredos(estado), null, 2));
        else if (m.acao === 'abrirCodigo' && !protegido && caminho.extname(documento.uri.fsPath) !== '.catplug') await vscode.commands.executeCommand('vscode.openWith', documento.uri, 'default');
      } catch (erro) { this.falhar(erro); }
    }, undefined, this.contexto.subscriptions);
    painel.onDidChangeViewState(e => { if (protegido && !e.webviewPanel.visible) { revisao++; estado = { tipo: 'protegido', tamanho: bytes.length, bloqueado: true }; } if (e.webviewPanel.visible) atualizar(); }, undefined, this.contexto.subscriptions);
    painel.onDidDispose(() => { terminou = true; revisao++; bytes.fill(0); estado = {}; this.paineis.delete(referencia); }, undefined, this.contexto.subscriptions);
    try { await carregar(); atualizar(); } catch (erro) { estado = { problemas: [{ codigo: erro instanceof Falha ? erro.codigo : 'pacoteInvalido', gravidade: 'erro' }] }; atualizar(); }
  }
  atualizar(): void { for (const p of this.paineis) p.atualizar(); }
  dispose(): void { for (const p of this.paineis) p.painel.dispose(); this.paineis.clear(); }
}
