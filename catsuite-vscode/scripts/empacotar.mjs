import { mkdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import caminho from 'node:path';
const pasta = caminho.resolve('downloads');
await mkdir(pasta, { recursive: true });
execFileSync(process.execPath, [caminho.resolve('node_modules/@vscode/vsce/vsce'), 'package', '--allow-missing-repository', '--out', caminho.join(pasta, 'catsuite-studio-1.2.0.vsix')], { stdio: 'inherit' });
