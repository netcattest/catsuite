import { fromBuffer } from 'yauzl';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import caminho from 'node:path';
import os from 'node:os';
const executar=promisify(execFile); const pasta=await mkdtemp(caminho.join(os.tmpdir(),'catsuite-vsix-')); const vsix=caminho.resolve('downloads','catsuite-studio-1.2.0.vsix');
try {
 const bytes=await readFile(vsix); const nomes=[];
 await new Promise((resolver,rejeitar)=>fromBuffer(bytes,{lazyEntries:true,validateEntrySizes:true,strictFileNames:true},(erro,zip)=> {if(erro||!zip){rejeitar(erro);return;} zip.on('error',rejeitar);zip.on('end',resolver);zip.on('entry',e=>{
 const relativo=caminho.normalize(e.fileName); if(caminho.isAbsolute(relativo)||relativo.split(caminho.sep).includes('..')||e.uncompressedSize>16*1024*1024||nomesInvalidos(e.fileName)) {zip.close();rejeitar(Error('VSIX invalido'));return;} nomes.push(e.fileName);
 zip.openReadStream(e,(erro,fluxo)=>{if(erro||!fluxo){rejeitar(erro);return;}const partes=[];fluxo.on('error',rejeitar);fluxo.on('data',b=>partes.push(b));fluxo.on('end',async()=> {try{const alvo=caminho.join(pasta,relativo);await mkdir(caminho.dirname(alvo),{recursive:true});await writeFile(alvo,Buffer.concat(partes));zip.readEntry();}catch(e){rejeitar(e);}});});});zip.readEntry();}));
 const resultado=await executar(process.execPath,['scripts/testar-vscode.mjs'],{env:{...process.env,CATSUITE_EXTENSAO_TESTE:caminho.join(pasta,'extension')},maxBuffer:4*1024*1024});
 await writeFile(caminho.resolve('artefatos','teste-vsix.json'),JSON.stringify({sucesso:true,arquivos:nomes.length,verificacoes:['ativacao do pacote de distribuicao','comandos','SDK bilingue','worker com dependencias embarcadas','editor catplug','painel']},null,2)); console.log(JSON.stringify({sucesso:true,arquivos:nomes.length}));
} finally { if(!caminho.basename(pasta).startsWith('catsuite-vsix-')) throw Error('pasta');await rm(pasta,{recursive:true,force:true,maxRetries:10,retryDelay:200}); }
function nomesInvalidos(nome){return /(?:^|\/)(?:src|testes|scripts|\.git)(?:\/|$)/.test(nome.replace(/^extension\//,''))&&!nome.startsWith('extension/node_modules/') || /\.(?:catkey|pem|map|log)$/.test(nome);}
