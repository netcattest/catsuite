import * as vscode from 'vscode';
import { promises as arquivos } from 'node:fs';
import caminho from 'node:path';
import { randomUUID as identidadeAleatoria } from 'node:crypto';
import { Projeto, Objeto, Falha, ResultadoPrevia, permissoes, api, limites } from './nucleo/contratos';
import { criarIdentidade, hash, verificarAssinatura, ocultarSegredos, canonico, selado, exigirConfianca } from './nucleo/seguranca';
import { lerProjeto, lerDentro, criarPacote, gravarAtomico, lerArquivoSeguro } from './nucleo/pacotes';
import { interpretarJson, analisarCodigo, validarManifesto, validarFluxo } from './nucleo/validacao';
import { criarModelo, modelos, Modelo, modeloFluxo } from './nucleo/modelos';
import { Projetos, ReferenciaProjeto, manifestoAtual } from './projetos';
import { Linguagem } from './linguagem';
import { Atelier } from './interface';
import { classificarCatPlug, prepararCopiaEditavel } from './nucleo/edicao';
import { trechoSdk } from './nucleo/trechos';
import { traduzir, idiomaAtual } from './idiomas';
import { trabalhar } from './trabalhador';
export class Operacoes {
  private criacaoIdentidade?: Promise<string | undefined>;
  constructor(private contexto: vscode.ExtensionContext, private projetos: Projetos, private linguagem: Linguagem, readonly atelier: Atelier) {}
  falhar(erro: unknown): void { if (erro instanceof Falha && erro.codigo === 'cancelado') return; const codigo = erro instanceof Falha ? erro.codigo : 'falhaGenerica'; void vscode.window.showErrorMessage(traduzir(codigo, erro instanceof Falha ? erro.argumentos : {})); }
  confiarWorkspace(): void { exigirConfianca(vscode.workspace.isTrusted); }
  async salvar(projeto: ReferenciaProjeto): Promise<boolean> {
    const edicoes = vscode.workspace.textDocuments.filter(d => d.isDirty && this.projetos.localizar(d.uri)?.pasta === projeto.pasta);
    if (!edicoes.length) return true;
    const escolha = await vscode.window.showWarningMessage(traduzir('salvarEdicoes'), { modal: true }, traduzir('salvar')); if (!escolha) return false;
    this.confiarWorkspace(); for (const doc of edicoes) if (!await doc.save()) return false; return true;
  }
  async obterProjeto(uri?: vscode.Uri, salvar = false): Promise<Projeto | undefined> {
    const referencia = await this.projetos.escolher(uri); if (!referencia || salvar && !await this.salvar(referencia)) return undefined;
    const projeto = await lerProjeto(referencia.pasta);
    if (!salvar) {
      projeto.manifesto = await manifestoAtual(referencia);
      if (typeof projeto.manifesto.entry !== 'string') throw new Falha('entradaInvalida');
      const aberto = vscode.workspace.textDocuments.find(d => d.uri.fsPath === caminho.join(projeto.pasta, ...projeto.manifesto.entry.split('/')));
      if (aberto) projeto.codigo = aberto.getText();
      projeto.problemas = [...validarManifesto(projeto.manifesto), ...analisarCodigo(projeto.codigo, projeto.manifesto)];
    }
    return projeto;
  }
  mostrarProjeto(projeto: Projeto): void { this.atelier.abrir({ modo: 'projeto', dados: { manifesto: projeto.manifesto, problemas: projeto.problemas, assinatura: verificarAssinatura(projeto.manifesto), arquivos: Object.entries(projeto.arquivos).map(([nome, b]) => ({ nome, tamanho: b.length, sha256: hash(b) })) } }); }
  async criar(): Promise<void> {
    this.confiarWorkspace();
    const escolhido = await vscode.window.showQuickPick(modelos.map(modelo => ({ label: traduzir('modelo.' + modelo), detail: traduzir('modeloAjuda.' + modelo), modelo })), { title: 'CatSuite · 1/5', placeHolder: traduzir('escolherModelo'), ignoreFocusOut: true }); if (!escolhido) return;
    const nome = await vscode.window.showInputBox({ title: 'CatSuite · 2/5', prompt: traduzir('nomeProjeto'), ignoreFocusOut: true, validateInput: v => v.trim().length < 1 || v.length > 120 || /[\x00-\x1f]/.test(v) ? traduzir('nomeInvalido') : undefined }); if (!nome) return;
    const secundario = await vscode.window.showInputBox({ title: 'CatSuite · 2/5', prompt: traduzir('nomeSecundario'), ignoreFocusOut: true, validateInput: v => v.length > 120 || /[\x00-\x1f]/.test(v) ? traduzir('nomeInvalido') : undefined }); if (secundario === undefined) return;
    const autor = await vscode.window.showInputBox({ title: 'CatSuite · 3/5', prompt: traduzir('autorProjeto'), value: vscode.workspace.getConfiguration('catsuite').get('autor', '') || 'NetCatTest', ignoreFocusOut: true, validateInput: v => !v.trim() || v.length > 120 || /[\x00-\x1f]/.test(v) ? traduzir('nomeInvalido') : undefined }); if (!autor) return;
    const id = await vscode.window.showInputBox({ title: 'CatSuite · 4/5', prompt: traduzir('idProjeto'), value: 'minha.extensao', ignoreFocusOut: true, validateInput: v => /^[a-z][a-z0-9.-]{2,63}$/.test(v) ? undefined : traduzir('idInvalido') }); if (!id) return;
    const destino = await vscode.window.showOpenDialog({ title: traduzir('pastaProjeto'), canSelectFiles: false, canSelectFolders: true, canSelectMany: false }); if (!destino?.[0]) return;
    if (!['file', 'vscode-remote'].includes(destino[0].scheme)) throw new Falha('virtualNaoSuportado');
    const base = await arquivos.realpath(destino[0].fsPath); const alvo = caminho.join(base, 'catsuite-' + id.replaceAll('.', '-')); try { await arquivos.lstat(alvo); throw new Falha('pastaExiste'); } catch (erro: any) { if (erro?.code !== 'ENOENT') throw erro; }
    const modelo = criarModelo(escolhido.modelo as Modelo, nome.trim(), autor.trim(), id);
    const locale = idiomaAtual(); modelo.manifesto.name[locale] = nome.trim(); modelo.manifesto.name[locale === 'pt-BR' ? 'en' : 'pt-BR'] = secundario.trim() || nome.trim();
    const resumo = traduzir('modeloAjuda.' + escolhido.modelo) + '\n\n' + traduzir('permissoes') + ': ' + modelo.manifesto.permissions.join(', ') + '\n' + traduzir('destinos') + ': ' + (modelo.manifesto.targets.join(', ') || traduzir('semDestino'));
    const confirmar = await vscode.window.showInformationMessage(resumo, { modal: true }, traduzir('criarProjeto')); if (!confirmar) return;
    const temporario = caminho.join(base, '.' + caminho.basename(alvo) + '.' + identidadeAleatoria() + '.tmp');
    try {
      await arquivos.mkdir(temporario, { mode: 0o700 }); for (const dir of ['src', 'sdk', 'fixtures']) await arquivos.mkdir(caminho.join(temporario, dir));
      for (const [nomeArquivo, dados] of [['manifest.json', modelo.manifesto], ['catsuite.projeto.json', modelo.projeto], ['fixtures/resposta.json', modelo.fixture], ['jsconfig.json', { compilerOptions: { target: 'ES2022', module: 'none', checkJs: true, noEmit: true, lib: ['ES2022'] }, include: ['sdk/catsuite.d.ts', 'src/**/*.js'], exclude: ['entregas'] }]] as const) await arquivos.writeFile(caminho.join(temporario, ...nomeArquivo.split('/')), JSON.stringify(dados, null, 2) + '\n', { flag: 'wx' });
      await arquivos.writeFile(caminho.join(temporario, 'src/principal.js'), modelo.codigo, { flag: 'wx' });
      await arquivos.writeFile(caminho.join(temporario, '.gitignore'), 'entregas/\n*.catplug\n*.catkey\n.env*\n*.pem\n*.key\n', { flag: 'wx' });
      await arquivos.copyFile(this.contexto.asAbsolutePath('sdk/catsuite.d.ts'), caminho.join(temporario, 'sdk/catsuite.d.ts'));
      await arquivos.rename(temporario, alvo);
    } finally { await arquivos.rm(temporario, { recursive: true, force: true }); }
    const abrir = await vscode.window.showInformationMessage(traduzir('projetoCriado'), traduzir('abrirPasta')); if (abrir) await vscode.commands.executeCommand('vscode.openFolder', vscode.Uri.file(alvo), true); else await this.projetos.atualizar();
  }
  async validar(uri?: vscode.Uri): Promise<void> {
    if (uri?.path.endsWith('.catflow') || !uri && vscode.window.activeTextEditor?.document.uri.path.endsWith('.catflow')) { const doc = await vscode.workspace.openTextDocument(uri ?? vscode.window.activeTextEditor!.document.uri); const problemas = validarFluxo(interpretarJson(doc.getText())); this.atelier.abrir({ modo: 'arquivo', dados: { tipo: 'catflow', documento: interpretarJson(doc.getText()), problemas } }); return; }
    const projeto = await this.obterProjeto(uri); if (!projeto) return; this.mostrarProjeto(projeto);
    const erros = projeto.problemas.filter(p => p.gravidade === 'erro').length; void vscode.window.showInformationMessage(traduzir('validacaoPronta', { erros, avisos: projeto.problemas.length - erros })); this.linguagem.atualizar();
  }
  async simular(uri?: vscode.Uri): Promise<void> {
    this.confiarWorkspace(); const projeto = await this.obterProjeto(uri, true); if (!projeto) return;
    if (projeto.problemas.some(p => p.gravidade === 'erro')) { this.mostrarProjeto(projeto); throw new Falha('validacaoFalhou'); }
    const config = interpretarJson((await lerDentro(projeto.pasta, 'catsuite.projeto.json', limites.manifesto)).toString('utf8'));
    const fixture = interpretarJson((await lerDentro(projeto.pasta, config.fixture, limites.manifesto)).toString('utf8'));
    if (typeof fixture.url !== 'string' || !/^https?:\/\//.test(fixture.url) || !Array.isArray(fixture.headers) || !fixture.body || !Array.isArray(fixture.body.bytes) || fixture.body.bytes.length > 32768 || fixture.body.bytes.some((v: unknown) => !Number.isInteger(v) || Number(v) < 0 || Number(v) > 255)) throw new Falha('fixtureInvalida');
    const resultado = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: traduzir('simulando'), cancellable: true }, async (_p, token) => trabalhar<ResultadoPrevia>(this.contexto.asAbsolutePath('dist/executor.js'), 'previa', { codigo: projeto.codigo, manifesto: projeto.manifesto, fixture, idioma: idiomaAtual(), arquivos: Object.fromEntries(Object.entries(projeto.arquivos).map(([nome, b]) => [nome, b.toString('utf8')])) }, token));
    this.atelier.abrir({ modo: 'previa', dados: { manifesto: projeto.manifesto, resultado } });
  }
  async identidade(criar = false): Promise<string | undefined> {
    if (this.criacaoIdentidade) { const resultado = await this.criacaoIdentidade; if (resultado || !criar) return resultado; }
    const operacao = (async () => { let privada = await this.contexto.secrets.get('catsuite.identidade.ed25519'); if (!privada && criar) { this.confiarWorkspace(); privada = criarIdentidade().privada; await this.contexto.secrets.store('catsuite.identidade.ed25519', privada); } return privada; })();
    this.criacaoIdentidade = operacao;
    try { return await operacao; } finally { if (this.criacaoIdentidade === operacao) this.criacaoIdentidade = undefined; }
  }
  async senha(): Promise<string | undefined> {
    const senha = await vscode.window.showInputBox({ prompt: traduzir('senhaArquivo'), password: true, ignoreFocusOut: true, validateInput: v => Buffer.byteLength(v) < 12 || Buffer.byteLength(v) > 1024 ? traduzir('senhaLimite') : undefined }); if (!senha) return undefined;
    const confirmacao = await vscode.window.showInputBox({ prompt: traduzir('confirmarSenha'), password: true, ignoreFocusOut: true }); if (confirmacao !== senha) { if (confirmacao !== undefined) throw new Falha('senhasDiferentes'); return undefined; } return senha;
  }
  async empacotar(uri?: vscode.Uri): Promise<void> {
    this.confiarWorkspace(); const projeto = await this.obterProjeto(uri, true); if (!projeto) return; if (projeto.problemas.some(p => p.gravidade === 'erro')) { this.mostrarProjeto(projeto); throw new Falha('validacaoFalhou'); }
    const escolha = await vscode.window.showQuickPick([{ label: traduzir('pacoteAssinado'), protegida: false }, { label: traduzir('pacoteProtegido'), protegida: true }], { placeHolder: traduzir('exportacaoFormato') }); if (!escolha) return;
    const senha = escolha.protegida ? await this.senha() : undefined; if (escolha.protegida && !senha) return;
    const alvo = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.file(caminho.join(projeto.pasta, projeto.manifesto.id + '-' + projeto.manifesto.version + '.catplug')), filters: { CatSuite: ['catplug'] } }); if (!alvo) return;
    if (!alvo.fsPath.endsWith('.catplug')) throw new Falha('entradaInvalida');
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: traduzir('empacotando'), cancellable: true }, async (_p, token) => {
      const privada = (await this.identidade(true))!; const bytes = await criarPacote(projeto, privada);
      const conteudo = senha ? Buffer.from(await trabalhar<Uint8Array>(this.contexto.asAbsolutePath('dist/executor.js'), 'proteger', { bytes, senha }, token)) : bytes;
      if (token.isCancellationRequested) throw new Falha('cancelado'); await gravarAtomico(alvo.fsPath, conteudo); bytes.fill(0);
    });
    void vscode.window.showInformationMessage(traduzir('pacotePronto', { arquivo: caminho.basename(alvo.fsPath) })); await vscode.commands.executeCommand('vscode.openWith', alvo, 'catsuite.pacote');
  }
  async hashes(uri?: vscode.Uri): Promise<void> {
    this.confiarWorkspace(); const projeto = await this.obterProjeto(uri, true); if (!projeto) return;
    const novo: Objeto = { ...projeto.manifesto, hashes: Object.fromEntries(Object.entries(projeto.arquivos).map(([nome, b]) => [nome, hash(b)])) }; delete novo.signature;
    if (canonico(novo.hashes) !== canonico(projeto.manifesto.hashes)) { novo.parentRevision = novo.revisionId; novo.revisionId = identidadeAleatoria(); }
    await this.gravarManifesto(projeto.pasta, novo); this.linguagem.atualizar();
  }
  async gravarManifesto(pasta: string, novo: Objeto): Promise<void> { const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(caminho.join(pasta, 'manifest.json'))); const edicao = new vscode.WorkspaceEdit(); edicao.replace(doc.uri, new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length)), JSON.stringify(novo, null, 2) + '\n'); if (!await vscode.workspace.applyEdit(edicao)) throw new Falha('execucaoFalhou'); await vscode.window.showTextDocument(doc); }
  async adicionarPermissao(uri: vscode.Uri, permissao: string): Promise<void> {
    this.confiarWorkspace(); if (!permissoes.includes(permissao as any)) throw new Falha('permissaoInvalida'); const projeto = this.projetos.localizar(uri); if (!projeto) return;
    const m = await manifestoAtual(projeto); if (m.permissions.includes(permissao)) return; m.permissions = [...m.permissions, permissao]; delete m.signature; m.parentRevision = m.revisionId; m.revisionId = identidadeAleatoria(); await this.gravarManifesto(projeto.pasta, m);
  }
  async inspecionar(uri?: vscode.Uri): Promise<void> { const selecionado = uri ?? (await vscode.window.showOpenDialog({ canSelectMany: false, filters: { CatSuite: ['catplug', 'catflow', 'catdata'] } }))?.[0]; if (!selecionado) return; await vscode.commands.executeCommand('vscode.openWith', selecionado, selecionado.path.endsWith('.catplug') ? 'catsuite.pacote' : 'catsuite.documento'); }
  async reconhecer(impressao: string): Promise<void> {
    if (!/^[a-f0-9]{64}$/.test(impressao)) throw new Falha('assinaturaInvalida');
    const confirmado = await vscode.window.showInformationMessage(traduzir('confiarAviso', { impressao }), { modal: true }, traduzir('confirmar')); if (!confirmado) return;
    const autores = this.contexto.globalState.get<string[]>('autoresReconhecidos', []); await this.contexto.globalState.update('autoresReconhecidos', [...new Set([...autores, impressao])].slice(-100));
  }
  async removerAutor(): Promise<void> { const lista = this.contexto.globalState.get<string[]>('autoresReconhecidos', []); const selecionado = await vscode.window.showQuickPick(lista, { placeHolder: traduzir('removerAutor') }); if (selecionado) await this.contexto.globalState.update('autoresReconhecidos', lista.filter(v => v !== selecionado)); }
  async verIdentidade(): Promise<void> { const privada = await this.identidade(); if (!privada) { void vscode.window.showInformationMessage(traduzir('identidadeAusente')); return; } const { createPrivateKey, createPublicKey } = await import('node:crypto'); const publica = createPublicKey(createPrivateKey({ key: Buffer.from(privada, 'base64'), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(-32); const impressao = hash(publica); const copiar = await vscode.window.showInformationMessage(traduzir('identidadeCriada') + '\n' + impressao, traduzir('copiarImpressao')); if (copiar) await vscode.env.clipboard.writeText(impressao); }
  async exportarIdentidade(): Promise<void> {
    this.confiarWorkspace(); const privada = await this.identidade(); if (!privada) throw new Falha('identidadeAusente'); const confirmado = await vscode.window.showWarningMessage(traduzir('backupAviso'), { modal: true }, traduzir('confirmar')); if (!confirmado) return;
    const senha = await this.senha(); if (!senha) return; const destino = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.file(caminho.join(process.env.USERPROFILE || process.env.HOME || '', 'catsuite-identidade.catkey')), filters: { CatSuite: ['catkey'] } }); if (!destino) return;
    if (vscode.workspace.getWorkspaceFolder(destino)) throw new Falha('backupLocal');
    const bytes = Buffer.from(JSON.stringify({ format: 'catsuite-identity', formatVersion: 1, privateKey: privada }));
    try { const resultado = Buffer.from(await trabalhar<Uint8Array>(this.contexto.asAbsolutePath('dist/executor.js'), 'proteger', { bytes, senha })); await gravarAtomico(destino.fsPath, resultado); } finally { bytes.fill(0); } void vscode.window.showInformationMessage(traduzir('backupPronto'));
  }
  async importarIdentidade(): Promise<void> {
    this.confiarWorkspace(); const origem = (await vscode.window.showOpenDialog({ canSelectMany: false, filters: { CatSuite: ['catkey'] } }))?.[0]; if (!origem) return; const bytes = await lerArquivoSeguro(origem.fsPath, 64 * 1024); if (!selado(bytes)) throw new Falha('arquivoProtegido'); const senha = await vscode.window.showInputBox({ prompt: traduzir('abrirProtegido'), password: true, ignoreFocusOut: true }); if (!senha) return;
    const plain = Buffer.from(await trabalhar<Uint8Array>(this.contexto.asAbsolutePath('dist/executor.js'), 'abrir', { bytes, senha }));
    try { const documento = interpretarJson(plain.toString('utf8')); if (documento.format !== 'catsuite-identity' || documento.formatVersion !== 1 || typeof documento.privateKey !== 'string') throw new Falha('assinaturaInvalida'); const { createPrivateKey } = await import('node:crypto'); const chave = createPrivateKey({ key: Buffer.from(documento.privateKey, 'base64'), format: 'der', type: 'pkcs8' }); if (chave.asymmetricKeyType !== 'ed25519') throw new Falha('assinaturaInvalida'); const confirmado = await vscode.window.showWarningMessage(traduzir('restaurarAviso'), { modal: true }, traduzir('confirmar')); if (confirmado) { await this.contexto.secrets.store('catsuite.identidade.ed25519', documento.privateKey); void vscode.window.showInformationMessage(traduzir('identidadeRestaurada')); } } finally { plain.fill(0); bytes.fill(0); }
  }
  async estilo(): Promise<void> {
    const tema = await vscode.window.showQuickPick([{ label: traduzir('temaCyber'), tema: 'CatSuite Cyber' }, { label: traduzir('temaConforto'), tema: 'CatSuite Comfort' }], { placeHolder: traduzir('estiloEscolher'), title: traduzir('temaExplicacao') }); if (!tema) return;
    const escolha = vscode.workspace.workspaceFolders?.length ? await vscode.window.showQuickPick([{ label: traduzir('somenteWorkspace'), alvo: vscode.ConfigurationTarget.Workspace }, { label: traduzir('todoEditor'), alvo: vscode.ConfigurationTarget.Global }], { placeHolder: traduzir('aplicarEstilo') }) : { alvo: vscode.ConfigurationTarget.Global }; if (!escolha) return;
    const config = vscode.workspace.getConfiguration('workbench'); const estado = escolha.alvo === vscode.ConfigurationTarget.Workspace ? this.contexto.workspaceState : this.contexto.globalState;
    if (!estado.get('catsuite.estiloAnterior')) await estado.update('catsuite.estiloAnterior', { alvo: escolha.alvo, tema: (escolha.alvo === vscode.ConfigurationTarget.Workspace ? config.inspect('colorTheme')?.workspaceValue : config.inspect('colorTheme')?.globalValue) ?? null, icones: (escolha.alvo === vscode.ConfigurationTarget.Workspace ? config.inspect('iconTheme')?.workspaceValue : config.inspect('iconTheme')?.globalValue) ?? null });
    await config.update('colorTheme', tema.tema, escolha.alvo); await config.update('iconTheme', 'catsuite-arquivos', escolha.alvo); void vscode.window.showInformationMessage(traduzir('temaAtualizado'));
  }
  async restaurarEstilo(): Promise<void> { const estado = this.contexto.workspaceState.get('catsuite.estiloAnterior') ? this.contexto.workspaceState : this.contexto.globalState; const anterior = estado.get<{ alvo: vscode.ConfigurationTarget; tema: string | null; icones: string | null }>('catsuite.estiloAnterior'); if (!anterior) { void vscode.window.showInformationMessage(traduzir('temaNaoSalvo')); return; } const config = vscode.workspace.getConfiguration('workbench'); await config.update('colorTheme', anterior.tema ?? undefined, anterior.alvo); await config.update('iconTheme', anterior.icones ?? undefined, anterior.alvo); await estado.update('catsuite.estiloAnterior', undefined); void vscode.window.showInformationMessage(traduzir('temaRestaurado')); }
  async idioma(): Promise<void> { const escolhido = await vscode.window.showQuickPick([{ label: traduzir('idiomaSistema'), valor: 'sistema' }, { label: traduzir('idiomaPt'), valor: 'pt-BR' }, { label: traduzir('idiomaEn'), valor: 'en' }], { placeHolder: traduzir('escolherIdioma') }); if (escolhido) { await vscode.workspace.getConfiguration('catsuite').update('idioma', escolhido.valor, vscode.ConfigurationTarget.Global); void vscode.window.showInformationMessage(traduzir('idiomaAtualizado')); } }
  async recurso(nome?: string): Promise<void> {
    const editor = vscode.window.activeTextEditor; if (!editor) { void vscode.window.showInformationMessage(traduzir('workspaceNecessario')); return; }
    const escolhido = nome && api[nome] ? { nome } : await vscode.window.showQuickPick(Object.entries(api).map(([nome, valor]) => ({ label: 'cat.' + nome, description: valor.permissao, detail: idiomaAtual() === 'pt-BR' ? valor.pt : valor.en, nome })), { placeHolder: traduzir('inserirRecurso'), matchOnDescription: true }); if (!escolhido) return;
    const texto = this.trecho(escolhido.nome); await editor.insertSnippet(new vscode.SnippetString(texto));
  }
  trecho(nome: string): string { return trechoSdk(nome); }
  async novoScript(): Promise<void> { const documento=await vscode.workspace.openTextDocument({language:'catsuite-plugin',content:''}); await vscode.window.showTextDocument(documento,{preview:false}); }
  async abrirScript(uri?: vscode.Uri): Promise<void> {
    if(uri && uri.path.endsWith('.catplug') && classificarCatPlug(await lerArquivoSeguro(uri.fsPath,64*1024*1024+64))==='script'){await vscode.commands.executeCommand('vscode.openWith',uri,'default',{preview:false});return;}
    const referencia=this.projetos.localizar(uri); if(referencia){ const projeto=await lerProjeto(referencia.pasta); const alvo=vscode.Uri.file(caminho.join(projeto.pasta,...projeto.manifesto.entry.split('/'))); await vscode.commands.executeCommand('vscode.openWith',alvo,'default',{preview:false}); return; }
    const alvo=uri ?? vscode.window.activeTextEditor?.document.uri;
    if(!alvo){ await this.novoScript(); return; }
    if(alvo.scheme==='untitled'){ await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(alvo),{preview:false}); return; }
    if(caminho.extname(alvo.fsPath)==='.catplug') { const bytes=await lerArquivoSeguro(alvo.fsPath,64*1024*1024+64); if(classificarCatPlug(bytes)==='pacote'){await this.editarPacote(alvo);return;} }
    await vscode.commands.executeCommand('vscode.openWith',alvo,'default',{preview:false});
  }
  async editarPacote(uri?: vscode.Uri): Promise<void> {
    this.confiarWorkspace(); const origem=uri ?? (await vscode.window.showOpenDialog({canSelectMany:false,filters:{CatSuite:['catplug']}}))?.[0]; if(!origem)return;
    const bytes=await lerArquivoSeguro(origem.fsPath,64*1024*1024+64); let aberto=bytes;
    try {
      if(selado(bytes)){ const senha=await vscode.window.showInputBox({prompt:traduzir('abrirProtegido'),password:true,ignoreFocusOut:true}); if(!senha)return; aberto=Buffer.from(await trabalhar<Uint8Array>(this.contexto.asAbsolutePath('dist/executor.js'),'abrir',{bytes,senha})); }
      if(classificarCatPlug(aberto)==='script'){ await vscode.commands.executeCommand('vscode.openWith',origem,'default',{preview:false});return; }
      const copia=await prepararCopiaEditavel(aberto);
      const confirmado=await vscode.window.showInformationMessage(traduzir('editarPacoteAviso'),{modal:true},traduzir('confirmar')); if(!confirmado)return;
      const destino=(await vscode.window.showOpenDialog({title:traduzir('pastaProjeto'),canSelectFiles:false,canSelectFolders:true,canSelectMany:false}))?.[0]; if(!destino)return;
      if(!['file','vscode-remote'].includes(destino.scheme))throw new Falha('virtualNaoSuportado');
      const base=await arquivos.realpath(destino.fsPath); const alvo=caminho.join(base,'catsuite-'+copia.manifesto.id.replaceAll('.','-')+'-editavel'); try{await arquivos.lstat(alvo);throw new Falha('pastaExiste');}catch(e:any){if(e?.code!=='ENOENT')throw e;}
      const temporario=caminho.join(base,'.'+caminho.basename(alvo)+'.'+identidadeAleatoria()+'.tmp'); if(caminho.dirname(temporario)!==base)throw new Falha('caminhoInvalido');
      try{
        await arquivos.mkdir(temporario); for(const [nome,conteudo] of Object.entries(copia.arquivos)){const arquivo=caminho.join(temporario,...nome.split('/'));await arquivos.mkdir(caminho.dirname(arquivo),{recursive:true});await arquivos.writeFile(arquivo,conteudo,{flag:'wx'});}
        const modelo=criarModelo('painel','Laboratório','CatSuite','local.lab'); await arquivos.mkdir(caminho.join(temporario,'sdk'),{recursive:true}); await arquivos.mkdir(caminho.join(temporario,'fixtures'),{recursive:true});
        await arquivos.writeFile(caminho.join(temporario,'manifest.json'),JSON.stringify(copia.manifesto,null,2)+'\n',{flag:'wx'});
        await arquivos.writeFile(caminho.join(temporario,'catsuite.projeto.json'),JSON.stringify({format:'catsuite-project',version:1,files:Object.keys(copia.arquivos),fixture:'fixtures/resposta-studio.json'},null,2)+'\n',{flag:'wx'});
        await arquivos.writeFile(caminho.join(temporario,'fixtures/resposta-studio.json'),JSON.stringify(modelo.fixture,null,2)+'\n',{flag:'wx'});
        if(!copia.arquivos['sdk/catsuite.d.ts'])await arquivos.copyFile(this.contexto.asAbsolutePath('sdk/catsuite.d.ts'),caminho.join(temporario,'sdk/catsuite.d.ts'));
        await arquivos.writeFile(caminho.join(temporario,'jsconfig.json'),JSON.stringify({compilerOptions:{target:'ES2022',module:'none',checkJs:true,noEmit:true,lib:['ES2022']},include:['sdk/catsuite.d.ts',copia.manifesto.entry]},null,2)+'\n',{flag:'wx'});
        await arquivos.rename(temporario,alvo);
      }finally{if(caminho.dirname(temporario)!==base||!caminho.basename(temporario).startsWith('.catsuite-'))throw new Falha('caminhoInvalido');await arquivos.rm(temporario,{recursive:true,force:true});}

      await this.projetos.atualizar(); await vscode.commands.executeCommand('vscode.openWith',vscode.Uri.file(caminho.join(alvo,...copia.manifesto.entry.split('/'))),'default',{preview:false}); void vscode.window.showInformationMessage(traduzir('scriptCopiado'));
    }finally{if(aberto!==bytes)aberto.fill(0);bytes.fill(0);}
  }
  async aplicarIcones(): Promise<void> {
    const escolha=vscode.workspace.workspaceFolders?.length ? await vscode.window.showQuickPick([{label:traduzir('somenteWorkspace'),alvo:vscode.ConfigurationTarget.Workspace},{label:traduzir('todoEditor'),alvo:vscode.ConfigurationTarget.Global}],{placeHolder:traduzir('aplicarIcones')}) : {alvo:vscode.ConfigurationTarget.Global}; if(!escolha)return;
    const config=vscode.workspace.getConfiguration('workbench');const estado=escolha.alvo===vscode.ConfigurationTarget.Workspace?this.contexto.workspaceState:this.contexto.globalState;
    if(!estado.get('catsuite.estiloAnterior'))await estado.update('catsuite.estiloAnterior',{alvo:escolha.alvo,tema:(escolha.alvo===vscode.ConfigurationTarget.Workspace?config.inspect('colorTheme')?.workspaceValue:config.inspect('colorTheme')?.globalValue)??null,icones:(escolha.alvo===vscode.ConfigurationTarget.Workspace?config.inspect('iconTheme')?.workspaceValue:config.inspect('iconTheme')?.globalValue)??null});
    await config.update('iconTheme','catsuite-arquivos',escolha.alvo);void vscode.window.showInformationMessage(traduzir('iconeAtualizado'));
  }

  async criarFluxo(): Promise<void> { this.confiarWorkspace(); const destino = await vscode.window.showSaveDialog({ filters: { CatSuite: ['catflow'] } }); if (!destino) return; await gravarAtomico(destino.fsPath, Buffer.from(JSON.stringify(modeloFluxo(), null, 2) + '\n')); await vscode.commands.executeCommand('vscode.open', destino); }
  async abrirManifesto(): Promise<void> { const projeto = await this.projetos.escolher(); if (projeto) await vscode.window.showTextDocument(vscode.Uri.file(caminho.join(projeto.pasta, 'manifest.json'))); }
  async executar(nome: string, uri?: vscode.Uri, parametro?: string): Promise<unknown> {
    try {
      switch (nome) {
        case 'painel': { const referencia = this.projetos.localizar(); if (referencia) this.mostrarProjeto(await lerProjeto(referencia.pasta)); else this.atelier.abrir({ modo: 'inicio', dados: {} }); break; }
        case 'novoScript': await this.novoScript(); break; case 'abrirScript': await this.abrirScript(uri); break; case 'editarPacote': await this.editarPacote(uri); break; case 'aplicarIcones': await this.aplicarIcones(); break;
        case 'criarProjeto': await this.criar(); break; case 'validarProjeto': await this.validar(uri); break; case 'simularProjeto': await this.simular(uri); break; case 'empacotarProjeto': await this.empacotar(uri); break;
        case 'atualizarHashes': await this.hashes(uri); break; case 'inspecionarPacote': await this.inspecionar(uri); break; case 'inserirRecurso': await this.recurso(parametro); break; case 'criarFluxo': await this.criarFluxo(); break; case 'verIdentidade': await this.verIdentidade(); break;
        case 'exportarIdentidade': await this.exportarIdentidade(); break; case 'importarIdentidade': await this.importarIdentidade(); break; case 'removerAutor': await this.removerAutor(); break; case 'aplicarEstilo': await this.estilo(); break; case 'restaurarEstilo': await this.restaurarEstilo(); break;
        case 'escolherIdioma': await this.idioma(); break; case 'abrirConfiguracoes': await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:netcattest.catsuite-studio'); break; case 'abrirManifesto': await this.abrirManifesto(); break; case 'atualizar': await this.projetos.atualizar(); break;
        default: throw new Falha('operacaoInvalida');
      }
    } catch (erro) { this.falhar(erro); }
    return undefined;
  }
}
