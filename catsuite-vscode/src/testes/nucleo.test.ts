import teste from 'node:test';
import assert from 'node:assert/strict';
import { promises as arquivos } from 'node:fs';
import caminho from 'node:path';
import os from 'node:os';
import { parse } from 'acorn';
import ts from 'typescript';
import { criarModelo, modelos, modeloFluxo } from '../nucleo/modelos';
import { interpretarJson, normalizarDestino, validarManifesto, analisarCodigo, validarFluxo } from '../nucleo/validacao';
import { criarIdentidade, assinarDocumento, verificarAssinatura, canonico, caminhoSeguro, proteger, abrirProtegido, ocultarSegredos, hash, exigirConfianca } from '../nucleo/seguranca';
import { compactar, verificarPacote, descompactar, criarPacote, lerProjeto, lerDentro } from '../nucleo/pacotes';
import { executarPrevia } from '../nucleo/simulacao';
import { classificarCatPlug,prepararCopiaEditavel } from '../nucleo/edicao';
import { prefixoCat,trechoSdk } from '../nucleo/trechos';
import { textosPt, textosEn } from '../nucleo/textos';
import { Objeto } from '../nucleo/contratos';
const criar = () => criarModelo('painel', 'Meu painel', 'Autor', 'local.painel');
const codigos = (lista: { codigo: string }[]) => lista.map(p => p.codigo);
teste('JSON estrito rejeita duplicatas, comentarios, profundidade e chaves perigosas', () => {
  for (const texto of ['{"a":1,"a":2}', '{"__proto__":{}}', '{"constructor":1}', '{"x":9007199254740992}', '{"x":NaN}', '{"x":1,}', '{/*x*/"a":1}']) assert.throws(() => interpretarJson(texto));
  assert.equal(interpretarJson('{"nome":"Aurora"}').nome, 'Aurora');
  assert.throws(() => interpretarJson('{"x":' + '['.repeat(70) + '0' + ']'.repeat(70) + '}'));
});
teste('caminhos de pacote excluem travessia e identidades reservadas', () => {
  for (const c of ['../a.js','/a.js','C:/a.js','src/../a','src//a','__proto__/x','a\\b','a/constructor']) assert.equal(caminhoSeguro(c), false, c);
  assert.equal(caminhoSeguro('src/principal.js'), true);
});
teste('destinos reconhecem IDNA, protocolos, IPv4 e IPv6 sem ambiguidades', () => {
  assert.equal(normalizarDestino('https://EXAMPLE.com:443/api'), 'https://example.com/api');
  assert.equal(normalizarDestino('ação.example'), 'xn--ao-siap.example');
  assert.equal(normalizarDestino('2001:db8::1'), '[2001:db8::1]');
  assert.equal(normalizarDestino('http://[::1]:8080'), 'http://[::1]:8080');
  for (const c of ['*','http://user:pass@example.com','https://example.com?q=1','https://example.com#x','127.1','0x7f000001','2130706433','http://example.com:65536','fe80::1%eth0','*.127.0.0.1']) assert.throws(() => normalizarDestino(c), c);
});
teste('manifesto e cinco modelos validam permissoes minimas e traducao', () => {
  for (const modelo of modelos) { const m = criarModelo(modelo, 'Meu painel', 'Autor', 'local.painel'); assert.deepEqual(validarManifesto(m.manifesto), []); assert.deepEqual(analisarCodigo(m.codigo,m.manifesto), []); }
  const m = criar().manifesto; delete m.name.en; m.permissions.push('shell'); m.settingsSchema = { campo: null };
  const c = codigos(validarManifesto(m)); assert.ok(c.includes('traducaoAusente')); assert.ok(c.includes('permissaoInvalida')); assert.ok(c.includes('configuracaoInvalida'));
});
teste('analise encontra sintaxe, APIs indisponiveis, permissoes e handlers lentos', () => {
  const m = criar().manifesto;
  assert.ok(codigos(analisarCodigo('cat.http.send({});',m)).includes('permissaoAusente'));
  assert.ok(codigos(analisarCodigo('cat.proxy.onRequest(async x => x);',m)).includes('handlerSincrono'));
  assert.ok(codigos(analisarCodigo('cat.proxy.onRequest(x => { cat.storage.get("x"); return x; });',m)).includes('handlerSincrono'));
  assert.ok(codigos(analisarCodigo('require("fs"); process.exit();',m)).includes('apiIndisponivel'));
  assert.ok(codigos(analisarCodigo('const = 1;',m)).includes('sintaxe'));
  assert.deepEqual(analisarCodigo('const nome = "fetch process require";',m), []);
});
teste('canonico preserva Unicode, ordem e numeros sem expoentes', () => { assert.equal(canonico({z:1e-7,a:'ação',n:-0}), '{"a":"ação","n":0,"z":0.0000001}'); assert.throws(() => canonico(Infinity)); });
teste('assinatura Ed25519 detecta adulteracao e usa identidade independente', () => {
  const identidade = criarIdentidade(); const assinado = assinarDocumento(criar().manifesto, identidade.privada);
  assert.equal(verificarAssinatura(assinado).estado,'valida'); assert.equal(verificarAssinatura(assinado).impressao, identidade.impressao);
  assinado.author = 'Alterado'; assert.equal(verificarAssinatura(assinado).estado,'invalida'); assert.equal(verificarAssinatura({}).estado,'ausente');
});
teste('assinatura gerada pelo host CatSuite e compativel', async () => { const documento = interpretarJson(await arquivos.readFile('testes/assinatura-host.json','utf8')); assert.equal(verificarAssinatura(documento).estado,'valida'); });
teste('cinco pacotes assinados verificam hashes, recursos e revisao', async () => {
  const identidade = criarIdentidade();
  for (const modelo of modelos) { const m = criarModelo(modelo,'Teste','Autor','local.teste'); const pacote = await criarPacote({ pasta:'', manifesto:m.manifesto, codigo:m.codigo, arquivos:{'src/principal.js':Buffer.from(m.codigo)}, problemas:[] }, identidade.privada); const lido = await verificarPacote(pacote); assert.equal(lido.assinatura.estado,'valida'); assert.notEqual(lido.manifesto.revisionId,m.manifesto.revisionId); assert.equal(lido.arquivos['src/principal.js']!.toString(),m.codigo); }
});
teste('pacotes corrompidos, recursos extras e hashes alterados sao recusados', async () => {
  const m = criar(); m.manifesto.hashes = {'src/principal.js':hash(m.codigo)};
  await assert.rejects(verificarPacote(Buffer.from('corrompido')));
  await assert.rejects(verificarPacote(await compactar(m.manifesto,{'src/principal.js':Buffer.from(m.codigo+';')})));
  await assert.rejects(verificarPacote(await compactar(m.manifesto,{'src/principal.js':Buffer.from(m.codigo),'extra.txt':Buffer.from('extra')})));
  await assert.rejects(descompactar(Buffer.alloc(11*1024*1024)));
});
teste('leitura de projeto e explicita e exclui arquivos privados e links', async () => {
  const pasta = await arquivos.mkdtemp(caminho.join(os.tmpdir(),'catsuite-unidade-'));
  try { const m = criar(); await arquivos.mkdir(caminho.join(pasta,'src')); await arquivos.writeFile(caminho.join(pasta,'src/principal.js'),m.codigo); await arquivos.writeFile(caminho.join(pasta,'manifest.json'),JSON.stringify(m.manifesto)); await arquivos.writeFile(caminho.join(pasta,'catsuite.projeto.json'),JSON.stringify(m.projeto)); const p = await lerProjeto(pasta); assert.equal(p.codigo,m.codigo); await assert.rejects(lerDentro(pasta,'../fora',100)); m.projeto.files.push('.env'); await arquivos.writeFile(caminho.join(pasta,'catsuite.projeto.json'),JSON.stringify(m.projeto)); await assert.rejects(lerProjeto(pasta),{codigo:'arquivoPrivado'}); }
  finally { if (!caminho.basename(pasta).startsWith('catsuite-unidade-')) throw Error('pasta'); await arquivos.rm(pasta,{recursive:true,force:true}); }
});
teste('CATSEAL2 oculta metadados e autentica senha, cabecalho e conteudo', async () => {
  const original = Buffer.from('{"autor":"Aurora privado"}'); const selado = await proteger(original,'Senha-de-teste-123');
  assert.equal(selado.subarray(0,8).toString(),'CATSEAL2'); assert.equal(selado.includes(Buffer.from('Aurora')),false); assert.deepEqual(await abrirProtegido(selado,'Senha-de-teste-123'),original);
  await assert.rejects(abrirProtegido(selado,'Senha-incorreta'),{codigo:'senhaIncorreta'});
  const adulterado = Buffer.from(selado); adulterado[48] = adulterado[48]! ^ 1; await assert.rejects(abrirProtegido(adulterado,'Senha-de-teste-123'));
  const cabecalho = Buffer.from(selado); cabecalho.writeInt32BE(999999,16); await assert.rejects(abrirProtegido(cabecalho,'Senha-de-teste-123'),{codigo:'parametrosCripto'});
});
teste('mascara credenciais e cabeçalhos sem ocultar identidade publica', () => { const o = ocultarSegredos({password:'p',headers:[{name:'Authorization',value:'Bearer abc'}],signature:{publicKey:'publica'}}) as Objeto; assert.equal(o.password,'[OCULTO]'); assert.equal(o.headers[0].value,'[OCULTO]'); assert.equal(o.signature.publicKey,'publica'); });
teste('fluxos rejeitam ciclos, tipos invalidos, referencias e dados malformados', () => {
  const fluxo = modeloFluxo(); assert.deepEqual(codigos(validarFluxo(fluxo)),['semAssinatura']);
  fluxo.nodes[0].inputs = ['record']; fluxo.edges.push({from:'relatorio',to:'captura'}); assert.ok(codigos(validarFluxo(fluxo)).includes('ciclo'));
  const outro = modeloFluxo(); outro.nodes[1].inputs = ['jwt']; assert.ok(codigos(validarFluxo(outro)).includes('tipoIncompativel'));
  assert.ok(codigos(validarFluxo({...outro,nodes:[null]})).includes('fluxoInvalido')); assert.doesNotThrow(()=>validarFluxo({...outro,nodes:[{id:'x',inputs:42,outputs:42}]}));
});
for (const modelo of modelos) teste('QuickJS executa modelo '+modelo+' sem rede', async () => { const m = criarModelo(modelo,'Teste','Autor','local.teste'); const resultado = await executarPrevia({codigo:m.codigo,manifesto:m.manifesto,fixture:m.fixture,idioma:'en'}); assert.ok(resultado.memoria>0); if(modelo==='painel') assert.equal(resultado.abas.length,1); if(modelo==='analise') assert.equal(resultado.achados.length,1); if(modelo==='headers') assert.ok(resultado.request.headers.some((h:Objeto)=>h.name==='X-Cat-Lab')); if(modelo==='fluxo') assert.equal(resultado.artefatos.length,2); if(modelo==='parser') assert.equal(resultado.artefatos.length,1); });
teste('QuickJS aplica permissoes, recusa promises pendentes e interrompe loops', async () => {
  const m = criar(); const entrada = {manifesto:m.manifesto,fixture:m.fixture,idioma:'pt-BR'};
  await assert.rejects(executarPrevia({...entrada,codigo:'cat.commands.register("x","x",async()=>await cat.http.send({url:"https://fora.example"}));'}));
  await assert.rejects(executarPrevia({...entrada,codigo:'cat.commands.register("x","x",async()=>await new Promise(()=>{}));'}),{codigo:'promessaPendente'});
  await assert.rejects(executarPrevia({...entrada,codigo:'while(true) {}'}));
  await assert.rejects(executarPrevia({...entrada,codigo:'process.exit();'}));
});
teste('idiomas e contribuicoes tem cobertura integral', async () => {
  assert.deepEqual(Object.keys(textosPt).sort(),Object.keys(textosEn).sort());
  const p = JSON.parse(await arquivos.readFile('package.json','utf8')); const pt = JSON.parse(await arquivos.readFile('package.nls.pt-br.json','utf8')); const en = JSON.parse(await arquivos.readFile('package.nls.json','utf8'));
  for (const placeholder of JSON.stringify(p).matchAll(/%([^%]+)%/g)) { assert.ok(pt[placeholder[1]!]); assert.ok(en[placeholder[1]!]); }
  const descricao = await arquivos.readFile('README.md','utf8');
  assert.ok(descricao.startsWith('# CatSuite Studio\n'));
  assert.ok(descricao.includes('https://netcattest.com/catsuite'));
  assert.ok(descricao.includes('CatSuite Android app'));
});
teste('codigo proprio nao contem comentarios nem notas', async () => {
  for(const pasta of ['src','scripts','midia']) for(const arquivo of await arquivos.readdir(pasta,{recursive:true})) {
    const nome = caminho.join(pasta,arquivo); if(!/\.(ts|js|mjs)$/.test(nome)) continue; const texto = await arquivos.readFile(nome,'utf8');
    const fonte = nome.endsWith('.ts') ? ts.transpileModule(texto,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022,removeComments:false}}).outputText : texto; const comentarios:any[]=[]; parse(fonte,{ecmaVersion:'latest',sourceType:'module',onComment:comentarios}); assert.equal(comentarios.length,0,nome);
  }
});

teste('CATSEAL2 aceita vetor de Argon2id e AES-GCM gerado por biblioteca independente',async()=> { const bytes=await arquivos.readFile('testes/catseal2-vetor.bin'); const resultado=await abrirProtegido(bytes,'Senha-fixture-publica-123'); assert.equal(JSON.parse(resultado.toString()).format,'catsuite-fixture'); });
teste('modelos JavaScript passam pelo verificador de tipos do SDK real',async()=> {
 const pasta=await arquivos.mkdtemp(caminho.join(os.tmpdir(),'catsuite-tipos-')); try { await arquivos.writeFile(caminho.join(pasta,'catsuite.d.ts'),await arquivos.readFile('sdk/catsuite.d.ts')); const nomes=[]; for(const modelo of modelos) { const nome=caminho.join(pasta,modelo+'.js'); await arquivos.writeFile(nome,criarModelo(modelo,'Teste','Autor','local.teste').codigo); nomes.push(nome); } const programa=ts.createProgram([...nomes,caminho.join(pasta,'catsuite.d.ts')],{allowJs:true,checkJs:true,noEmit:true,strict:true,types:[],target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}); const erros=ts.getPreEmitDiagnostics(programa); assert.deepEqual(erros.map(e=>ts.flattenDiagnosticMessageText(e.messageText,' ')),[]); } finally { if(!caminho.basename(pasta).startsWith('catsuite-tipos-')) throw Error('pasta'); await arquivos.rm(pasta,{recursive:true,force:true}); }
});
teste('temas mantem contraste de texto, selecao e controles',async()=> {
 const luminancia=(hex:string)=> { const rgb=[1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)/255).map(c=>c<=.04045?c/12.92:((c+.055)/1.055)**2.4); return rgb[0]!* .2126 + rgb[1]!*.7152 + rgb[2]!*.0722; };
 for(const nome of ['cyber','conforto']){const cores=JSON.parse(await arquivos.readFile('temas/'+nome+'-color-theme.json','utf8')).colors; for(const [a,b] of [['editor.foreground','editor.background'],['sideBar.foreground','sideBar.background'],['button.foreground','button.background'],['input.foreground','input.background'],['list.activeSelectionForeground','list.activeSelectionBackground'],['descriptionForeground','editor.background']]){ const valores=[luminancia(cores[a!]),luminancia(cores[b!])].sort((x,y)=>y-x); assert.ok((valores[0]!+.05)/(valores[1]!+.05)>=4.5,nome+' '+a); }}
});

teste('politica de workspace restringe operacoes de criacao e execucao',()=> { assert.throws(()=>exigirConfianca(false),{codigo:'confiancaNecessaria'}); assert.doesNotThrow(()=>exigirConfianca(true)); });

teste('ZIP recusa nomes duplicados, travessia e entradas enormes',async()=> {
 const {ZipFile}=await import('yazl'); const montar=async(duplicar:boolean)=> {const zip=new ZipFile(); const partes:Buffer[]=[]; const resultado=new Promise<Buffer>((r,e)=>{zip.outputStream.on('data',b=>partes.push(b));zip.outputStream.on('end',()=>r(Buffer.concat(partes)));zip.outputStream.on('error',e);});zip.addBuffer(Buffer.from('x'),'src/a.js');if(duplicar)zip.addBuffer(Buffer.from('y'),'src/a.js');zip.end();return resultado;};
 await assert.rejects(descompactar(await montar(true)),{codigo:'caminhoInvalido'});
 const travessia=await montar(false); const alvo=Buffer.from('../a.txt'); const nome=Buffer.from('src/a.js'); for(let pos=travessia.indexOf(nome);pos>=0;pos=travessia.indexOf(nome,pos+1)) alvo.copy(travessia,pos); await assert.rejects(descompactar(travessia));
 const enorme=await montar(false);const central=enorme.indexOf(Buffer.from('504b0102','hex'));enorme.writeUInt32LE(5*1024*1024,central+24);await assert.rejects(descompactar(enorme));
});
teste('QuickJS interrompe handler de alteracao e limita memoria',async()=> {
 const m=criarModelo('headers','Teste','Autor','local.teste'); const entrada={manifesto:m.manifesto,fixture:m.fixture,idioma:'en'};
 const inicio=Date.now(); await assert.rejects(executarPrevia({...entrada,codigo:'cat.proxy.onRequest(m=>{while(true){};return m;});'})); assert.ok(Date.now()-inicio<2000);
 await assert.rejects(executarPrevia({...entrada,codigo:'const a=[];for(let i=0;i<10000000;i++)a.push({texto:"x".repeat(1000)});'}));
});

teste('CatPlug diferencia scripts vazios, UTF-8, pacotes e binarios',async()=> {
 assert.equal(classificarCatPlug(Buffer.alloc(0)),'script'); assert.equal(classificarCatPlug(Buffer.from('cat.log("olá");')),'script'); assert.equal(classificarCatPlug(Buffer.from('CATSEAL2abc')),'pacote'); assert.equal(classificarCatPlug(Buffer.from([0,255])),'invalido'); const m=criar(); const b=await criarPacote({pasta:'',manifesto:m.manifesto,codigo:m.codigo,arquivos:{'src/principal.js':Buffer.from(m.codigo)},problemas:[]},criarIdentidade().privada); assert.equal(classificarCatPlug(b),'pacote'); const copia=await prepararCopiaEditavel(b); assert.notEqual(copia.manifesto.revisionId,m.manifesto.revisionId); assert.equal(copia.manifesto.signature,undefined); assert.equal(copia.arquivos['src/principal.js']!.toString(),m.codigo); assert.deepEqual(copia.manifesto.hashes,{});
});
teste('copia editavel rejeita tarefas automaticas do editor e integridade adulterada',async()=> {
 const m=criar(); const privado={...m.manifesto,hashes:{'src/principal.js':hash(m.codigo),'.vscode/tasks.json':hash('{}')}}; const b=await compactar(privado,{'src/principal.js':Buffer.from(m.codigo),'.vscode/tasks.json':Buffer.from('{}')}); await assert.rejects(prepararCopiaEditavel(b),{codigo:'arquivoPrivado'});
});
teste('prefixos e trechos funcionam sem projeto e nao acionam palavras parecidas',()=> {
 for(const [texto,resultado] of [['cat.','cat.'],['await cat.http.','cat.http.'],['catplug','catplug'],['bobcat.',undefined],['category',undefined],['x.catplug','catplug']]) assert.equal(prefixoCat(texto!),resultado);
 assert.ok(trechoSdk('ui.tab.register').includes('Título')); assert.ok(!trechoSdk('findings.add').includes('Ã')); assert.equal(trechoSdk('inexistente'),'');
});
teste('linguagem CatPlug e icones declaram recursos locais proprios',async()=> {const p=JSON.parse(await arquivos.readFile('package.json','utf8')); const l=p.contributes.languages.find((l:Objeto)=>l.id==='catsuite-plugin');assert.ok(l.extensions.includes('.catplug')); assert.equal(l.icon.dark,'./midia/icone.png'); assert.equal(p.contributes.customEditors.find((e:Objeto)=>e.viewType==='catsuite.pacote').priority,'option'); const icones=JSON.parse(await arquivos.readFile('temas/catsuite-icon-theme.json','utf8'));assert.equal(icones.languageIds['catsuite-plugin'],'plugin');assert.equal(icones.iconDefinitions.plugin.iconPath,'../midia/icone.png');});
