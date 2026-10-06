import { chromium } from '@playwright/test';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import caminho from 'node:path';
import assert from 'node:assert/strict';
const entrega = caminho.resolve('artefatos'); await mkdir(caminho.join(entrega,'visuais'),{recursive:true});
const origem = await readFile('src/nucleo/textos.ts','utf8');
const pt = JSON.parse(origem.match(/textosPt[^=]*=\s*(\{[\s\S]*?\n\});/)[1]); const en = JSON.parse(origem.match(/textosEn[^=]*=\s*(\{[\s\S]*?\n\});/)[1]);
const browser = await chromium.launch({channel:process.env.CATSUITE_NAVEGADOR || (process.platform === 'win32' ? 'msedge' : undefined),headless:true}); const verificacoes=[]; const falhas=[];
try {
  const page = await browser.newPage(); page.on('pageerror',e=>falhas.push(e.message));
  await page.setContent('<!doctype html><html><head><meta charset="utf-8"></head><body><main id="app"></main></body></html>');
  await page.addStyleTag({path:caminho.resolve('midia/atelier.css')}); await page.addScriptTag({path:caminho.resolve('midia/atelier.js')});
  const logo='data:image/png;base64,'+(await readFile('midia/icone.png')).toString('base64'); await page.evaluate(logo=>{const renderizar=window.__renderizarCatSuite;window.__renderizarCatSuite=m=>renderizar({...m,recursos:{logo}});},logo);
  const manifesto = {id:'local.auditoria',name:{'pt-BR':'Auditoria de identidade e contratos de API com um nome muito longo','en':'Identity and API contract audit with a very long project name'},description:{'pt-BR':'Crie, valide, teste e assine extensões com dados locais.','en':'Create, validate, test and sign extensions with local data.'},permissions:['traffic.read','findings'],targets:['https://api.aurora.test/api/perfil']};
  const modos = [{modo:'inicio',dados:{}},{modo:'projeto',dados:{manifesto,problemas:[]}},{modo:'previa',dados:{manifesto,resultado:{abas:[{title:{'pt-BR':'Resumo da análise','en':'Analysis summary'},components:[{type:'text',text:{'pt-BR':'Nenhum segredo será enviado.','en':'No secrets will be sent.'}},{type:'button',label:{'pt-BR':'Analisar a resposta','en':'Analyze response'},command:'analisar'}]}],achados:[{title:'Cache',evidence:'HTTP'}],artefatos:[],duracao:28,eventos:[]}}},{modo:'arquivo',dados:{tipo:'protegido',bloqueado:true}},{modo:'arquivo',dados:{tipo:'catflow',documento:{...manifesto,nodes:[{id:'captura',kind:'capture'},{id:'jwt',kind:'extension'},{id:'relatorio',kind:'report'}],edges:[{from:'captura',to:'jwt'},{from:'jwt',to:'relatorio'}]},assinatura:{estado:'valida',impressao:'a'.repeat(64)},problemas:[]}}];
  for(const [idioma,rotulos] of [['pt-BR',pt],['en',en]]) for(const [largura,altura] of [[320,568],[360,640],[640,360],[1024,768]]) for(const escala of [1,2]) {
    await page.setViewportSize({width:largura,height:altura});
    await page.evaluate(e=>document.documentElement.style.setProperty('--vscode-font-size',13*e+'px'),escala);
    for(const estado of modos) {
      await page.evaluate(m=>window.__renderizarCatSuite(m),{tipo:'estado',estado,rotulos,idioma,confiavel:true,estilo:'catsuite'});
      const medicao = await page.evaluate(()=>({largura:innerWidth,documento:document.documentElement.scrollWidth,botoes:[...document.querySelectorAll('button')].map(b=>({altura:b.getBoundingClientRect().height,largura:b.getBoundingClientRect().width,texto:b.textContent})),lang:document.documentElement.lang}));
      assert.ok(medicao.documento<=medicao.largura+1,JSON.stringify({idioma,largura,escala,modo:estado.modo,medicao})); assert.equal(medicao.lang,idioma); assert.ok(medicao.botoes.every(b=>b.altura>=48));
      verificacoes.push({idioma,largura,altura,escala,modo:estado.modo});
    }
  }
  for(const [idioma,rotulos] of [['pt-BR',pt],['en',en]]) { await page.setViewportSize({width:1280,height:900}); await page.evaluate(()=>document.documentElement.style.setProperty('--vscode-font-size','13px')); await page.evaluate(m=>window.__renderizarCatSuite(m),{tipo:'estado',estado:modos[0],rotulos,idioma,confiavel:true,estilo:'catsuite'}); await page.screenshot({path:caminho.join(entrega,'visuais','painel-'+idioma+'.png'),fullPage:true}); }
  await page.setViewportSize({width:360,height:640}); await page.evaluate(m=>window.__renderizarCatSuite(m),{tipo:'estado',estado:modos[2],rotulos:en,idioma:'en',confiavel:true,estilo:'catsuite'}); await page.screenshot({path:caminho.join(entrega,'visuais','previa-estreita-en.png'),fullPage:true});
  await page.setViewportSize({width:1024,height:768}); await page.evaluate(m=>window.__renderizarCatSuite(m),{tipo:'estado',estado:modos[1],rotulos:en,idioma:'en',confiavel:true,estilo:'editor'}); await page.addStyleTag({content:':root{--vscode-editor-background:#ffffff;--vscode-foreground:#252526;--vscode-descriptionForeground:#54565a;--vscode-input-background:#f2f3f4;--vscode-panel-border:#767676;--vscode-testing-iconPassed:#18794e;--vscode-button-background:#005fb8;--vscode-button-foreground:#ffffff}'}); await page.screenshot({path:caminho.join(entrega,'visuais','tema-editor-claro.png'),fullPage:true});
  await page.evaluate(m=>window.__renderizarCatSuite(m),{tipo:'estado',estado:{modo:'projeto',dados:{manifesto:{name:{en:'<img src=x onerror=alert(1)>'}},problemas:[]}},rotulos:en,idioma:'en',estilo:'catsuite'}); assert.equal(await page.locator('img').count(),2); assert.equal(await page.locator('img[onerror]').count(),0); assert.equal(await page.locator('img').first().getAttribute('src'),logo); await page.keyboard.press('Tab'); assert.equal(await page.evaluate(()=>document.activeElement.tagName),'BUTTON');
  assert.deepEqual(falhas,[]); await writeFile(caminho.join(entrega,'teste-visual.json'),JSON.stringify({sucesso:true,casos:verificacoes.length,verificacoes,errosJavaScript:falhas},null,2)); console.log(JSON.stringify({sucesso:true,casos:verificacoes.length}));
} finally { await browser.close(); }
