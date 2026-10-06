import { build } from 'esbuild';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
await mkdir('dist/testes', { recursive: true });
const opcoes = { bundle: true, platform: 'node', target: 'node20', mainFields: ['module', 'main'], format: 'cjs', sourcemap: false, minify: true, legalComments: 'external', external: ['vscode', 'quickjs-emscripten', 'typescript'] };
await build({ ...opcoes, entryPoints: ['src/extensao.ts', 'src/executor.ts', 'src/testes-vscode.ts'], outdir: 'dist' });
const arquivos = (await readdir('src/testes')).filter(nome => nome.endsWith('.test.ts'));
if (arquivos.length) await build({ ...opcoes, entryPoints: arquivos.map(nome => 'src/testes/' + nome), outdir: 'dist/testes' });

const bibliotecas = ['acorn','jsonc-parser','yauzl','yazl','pend','buffer-crc32','hash-wasm'];
let licencas = '';
for(const nome of bibliotecas) { const pacote = JSON.parse(await readFile('node_modules/'+nome+'/package.json','utf8')); const nomes = await readdir('node_modules/'+nome); const arquivo = nomes.find(a=>/^licen[sc]e/i.test(a)); if(!arquivo) throw Error('Licença ausente: '+nome); licencas += nome+' '+pacote.version+'\n'+(await readFile('node_modules/'+nome+'/'+arquivo,'utf8'))+'\n\n'; }
await writeFile('THIRD_PARTY_LICENSES.txt',licencas);
