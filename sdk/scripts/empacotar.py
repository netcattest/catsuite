import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


raiz = Path(__file__).resolve().parents[1]
versao = json.loads((raiz / 'sdk.json').read_text(encoding='utf-8'))['version']
argumentos = argparse.ArgumentParser()
argumentos.add_argument('--output', default=str(raiz / 'downloads'))
destino = Path(argumentos.parse_args().output).resolve()
destino.mkdir(parents=True, exist_ok=True)
fontes = ['sdk.js', 'catsuite.d.ts', 'sdk.json', 'capability-contracts.json', 'README.md', 'README.en.md', 'LICENSE']
for pasta in ['esquemas', 'exemplos', 'fluxos', 'scripts']:
    fontes.extend(p.relative_to(raiz).as_posix() for p in (raiz / pasta).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
fontes = sorted(set(fontes))
limite = 10 * 1024 * 1024
total = 0
itens = []
for relativo in fontes:
    arquivo = raiz / relativo
    if arquivo.is_symlink() or not arquivo.resolve().is_relative_to(raiz):
        raise ValueError('E_PATH')
    if arquivo.suffix not in {'.js', '.ts', '.json', '.catflow', '.md', '.py'} and arquivo.name != 'LICENSE':
        raise ValueError('E_FILE')
    dados = arquivo.read_bytes()
    total += len(dados)
    if total > limite:
        raise ValueError('E_SIZE')
    itens.append((relativo, dados))
hashes = '\n'.join(f'{hashlib.sha256(dados).hexdigest()}  {nome}' for nome, dados in itens) + '\n'
itens.append(('SHA256SUMS.txt', hashes.encode('utf-8')))
nome_pacote = f'catsuite-sdk-{versao}.zip'
temporario = destino / (nome_pacote + '.tmp')
with ZipFile(temporario, 'w') as pacote:
    for nome, dados in itens:
        entrada = ZipInfo('catsuite-sdk/' + nome, date_time=(2000, 1, 1, 0, 0, 0))
        entrada.create_system = 3
        entrada.external_attr = 0o100644 << 16
        entrada.compress_type = ZIP_DEFLATED
        pacote.writestr(entrada, dados)
with ZipFile(temporario) as pacote:
    if pacote.testzip() is not None:
        raise ValueError('E_INTEGRITY')
temporario.replace(destino / nome_pacote)
digest = hashlib.sha256((destino / nome_pacote).read_bytes()).hexdigest()
(destino / 'SHA256SUMS.txt').write_text(f'{digest}  {nome_pacote}\n', encoding='utf-8', newline='\n')
print(nome_pacote)
