import * as vscode from 'vscode';
import assert from 'node:assert/strict';
import caminho from 'node:path';
import { promises as arquivos } from 'node:fs';
import { criarModelo } from './nucleo/modelos';
import { executarPrevia } from './nucleo/simulacao';
import { lerProjeto, criarPacote } from './nucleo/pacotes';
import { criarIdentidade } from './nucleo/seguranca';
import { trabalhar } from './trabalhador';
export async function run(): Promise<void> {
  const extensao = vscode.extensions.getExtension('netcattest.catsuite-studio'); assert.ok(extensao); const servicos = await extensao.activate(); const pasta = process.env.CATSUITE_TESTE_WORKSPACE!;
  const m = criarModelo('painel','Painel do teste','Autor','local.teste'); await arquivos.mkdir(caminho.join(pasta,'src'),{recursive:true}); await arquivos.mkdir(caminho.join(pasta,'fixtures'),{recursive:true}); await arquivos.writeFile(caminho.join(pasta,'src/principal.js'),m.codigo); await arquivos.writeFile(caminho.join(pasta,'manifest.json'),JSON.stringify(m.manifesto)); await arquivos.writeFile(caminho.join(pasta,'catsuite.projeto.json'),JSON.stringify(m.projeto)); await arquivos.writeFile(caminho.join(pasta,'fixtures/resposta.json'),JSON.stringify(m.fixture));
  for(let i=0;i<15 && servicos.projetos.lista.length!==1;i++){ await new Promise(r=>setTimeout(r,150)); await servicos.projetos.atualizar(); } assert.equal(servicos.projetos.lista.length,1,'descoberta de projeto'); assert.equal(servicos.projetos.getChildren().length,1);

  const comandos = await vscode.commands.getCommands(); for(const nome of ['painel','criarProjeto','validarProjeto','simularProjeto','empacotarProjeto','aplicarEstilo','inspecionarPacote','escolherIdioma']) assert.ok(comandos.includes('catsuite.'+nome));
  const documento = await vscode.workspace.openTextDocument(vscode.Uri.file(caminho.join(pasta,'src/principal.js'))); const editor = await vscode.window.showTextDocument(documento);
  await servicos.linguagem.validar(documento); assert.equal(servicos.linguagem.diagnosticos.get(documento.uri)?.length,0);
  const posicao = documento.positionAt(documento.getText().indexOf('cat.commands.register')+8);
  for(const idioma of ['pt-BR','en']) { await vscode.workspace.getConfiguration('catsuite').update('idioma',idioma,vscode.ConfigurationTarget.Workspace); const h = await vscode.commands.executeCommand<vscode.Hover[]>('vscode.executeHoverProvider',documento.uri,posicao); assert.ok(h.some(x=>x.contents.some(c=>String(typeof c==='string'?c:c.value).replaceAll('&nbsp;',' ').includes(idioma==='en'?'Registers a custom bilingual command':'Registra um comando próprio'))), 'hover '+idioma+' '+JSON.stringify(h.map(x=>x.contents.map(c=>({tipo:typeof c,valor:typeof c==='string'?c:c.value,campos:typeof c==='object'?Object.getOwnPropertyNames(c):[]}))))); }
  const antes = documento.getText(); await editor.edit(e=>e.replace(new vscode.Range(documento.positionAt(0),documento.positionAt(antes.length)),'cat.http.'));
  const sugestoes = await vscode.commands.executeCommand<vscode.CompletionList>('vscode.executeCompletionItemProvider',documento.uri,new vscode.Position(0,9)); assert.ok(sugestoes.items.some(x=>String(x.label)==='send'));
  await editor.edit(e=>e.replace(new vscode.Range(documento.positionAt(0),documento.positionAt(documento.getText().length)),'cat.http.send({url:"https://api.aurora.test"});'));
  await servicos.linguagem.validar(documento); assert.ok(servicos.linguagem.diagnosticos.get(documento.uri)?.some((d:vscode.Diagnostic)=>String(d.code).startsWith('permissaoAusente:')));
  await editor.edit(e=>e.replace(new vscode.Range(documento.positionAt(0),documento.positionAt(documento.getText().length)),antes)); await documento.save();
  for(const idioma of ['pt-BR','en']) {
    await vscode.workspace.getConfiguration('catsuite').update('idioma',idioma,vscode.ConfigurationTarget.Workspace);
    for(const formato of ['plaintext','markdown','json','css']) {
      const solto=await vscode.workspace.openTextDocument({language:formato,content:'cat.'}); await vscode.window.showTextDocument(solto,{preview:false});
      const opcoes=await vscode.commands.executeCommand<vscode.CompletionList>('vscode.executeCompletionItemProvider',solto.uri,new vscode.Position(0,4)); assert.ok(opcoes.items.filter(i=>i.detail?.startsWith('CatSuite SDK')).length>=29,'SDK global '+formato);
      const plugin=await vscode.workspace.openTextDocument({language:formato,content:'catplug'}); await vscode.window.showTextDocument(plugin,{preview:false}); const modelos=await vscode.commands.executeCommand<vscode.CompletionList>('vscode.executeCompletionItemProvider',plugin.uri,new vscode.Position(0,7)); const modelo=modelos.items.find(i=>i.label==='catplug'); assert.ok(modelo && modelo.insertText instanceof vscode.SnippetString && !modelo.command,'modelo insere codigo'); assert.ok(modelo.detail?.includes(idioma==='en'?'Editable':'editável'));
    }
  }
  const uriScript=vscode.Uri.file(caminho.join(caminho.dirname(pasta),'ca.catplug')); await arquivos.writeFile(uriScript.fsPath,''); await vscode.commands.executeCommand('vscode.open',uriScript);
  await new Promise(r=>setTimeout(r,200)); assert.equal(vscode.window.activeTextEditor?.document.uri.toString(),uriScript.toString(),'catplug vazio no editor'); assert.equal(vscode.window.activeTextEditor?.document.languageId,'catsuite-plugin');
  const edicao=vscode.window.activeTextEditor!; await edicao.edit(e=>e.insert(new vscode.Position(0,0),'cat.')); const preenchimento=await vscode.commands.executeCommand<vscode.CompletionList>('vscode.executeCompletionItemProvider',uriScript,new vscode.Position(0,4)); assert.ok(preenchimento.items.some(i=>i.label==='events.on')); await edicao.document.save();
  await vscode.commands.executeCommand('vscode.openWith',uriScript,'catsuite.pacote'); await new Promise(r=>setTimeout(r,400)); assert.equal(vscode.window.activeTextEditor?.document.uri.toString(),uriScript.toString(),'associacao antiga reabre codigo');
  await vscode.commands.executeCommand('catsuite.novoScript'); assert.equal(vscode.window.activeTextEditor?.document.languageId,'catsuite-plugin');
  await vscode.commands.executeCommand('catsuite.abrirScript',documento.uri); assert.equal(vscode.window.activeTextEditor?.document.uri.toString(),documento.uri.toString(),'abrir script do projeto');
  const cancelamento=new vscode.CancellationTokenSource(); cancelamento.cancel(); await assert.rejects(trabalhar(caminho.join(extensao.extensionPath,'dist/executor.js'),'previa',{codigo:'while(true){}'},cancelamento.token),{codigo:'cancelado'}); cancelamento.dispose();
  const resultado = await trabalhar<any>(caminho.join(extensao.extensionPath,'dist/executor.js'),'previa',{codigo:m.codigo,manifesto:m.manifesto,fixture:m.fixture,idioma:'en'}); assert.equal(resultado.abas.length,1);
  const identidades=await Promise.all([servicos.operacoes.identidade(true),servicos.operacoes.identidade(true)]); assert.ok(Boolean(identidades[0]) && identidades[0]===identidades[1],'identidade unica no SecretStorage');
  const p = await lerProjeto(pasta); const pacote = await criarPacote(p,criarIdentidade().privada); const arquivo = caminho.join(pasta,'teste.catplug'); await arquivos.writeFile(arquivo,pacote); await vscode.commands.executeCommand('vscode.open',vscode.Uri.file(arquivo)); for(let i=0;i<25;i++){ if(vscode.window.tabGroups.all.flatMap(g=>g.tabs).some(t=>t.input instanceof vscode.TabInputCustom && t.input.viewType==='catsuite.pacote'))break; await new Promise(r=>setTimeout(r,100)); } assert.ok(vscode.window.tabGroups.all.flatMap(g=>g.tabs).some(t=>t.input instanceof vscode.TabInputCustom && t.input.viewType==='catsuite.pacote'),'pacote binario reconhecido automaticamente');
  await vscode.commands.executeCommand('catsuite.painel');
  for(let i=0;i<15;i++){ const abertos=vscode.window.tabGroups.all.flatMap(g=>g.tabs).map(t=>t.input); if(abertos.some(t=>t instanceof vscode.TabInputWebview)) break; await new Promise(r=>setTimeout(r,100)); } const tipos = vscode.window.tabGroups.all.flatMap(g=>g.tabs).map(t=>t.input); assert.ok(tipos.some(t=>t instanceof vscode.TabInputCustom && t.viewType==='catsuite.pacote'),'editor catplug'); assert.ok(tipos.some(t=>t instanceof vscode.TabInputWebview),'painel');
  for(const tipo of ['headers','analise','fluxo','parser'] as const) { const modelo=criarModelo(tipo,'Teste','Autor','local.teste'); assert.ok((await executarPrevia({codigo:modelo.codigo,manifesto:modelo.manifesto,fixture:modelo.fixture,idioma:'pt-BR'})).memoria>0); }
  await arquivos.writeFile(process.env.CATSUITE_TESTE_RELATORIO!,JSON.stringify({sucesso:true,verificacoes:['ativacao','projetos','comandos','diagnosticos','autocomplete','hover pt-BR/en','worker QuickJS','editor catplug','painel','cinco modelos','SDK em plaintext/markdown/json/css pt-BR/en','modelos catplug inserem codigo','catplug vazio editavel','associacao antiga corrigida','novo script','abrir script']},null,2));
}
