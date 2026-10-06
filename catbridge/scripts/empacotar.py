import argparse
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


raiz = Path(__file__).resolve().parents[1]
argumentos = argparse.ArgumentParser()
argumentos.add_argument('--output', default=str(raiz / 'downloads'))
destino = Path(argumentos.parse_args().output).resolve()
destino.mkdir(parents=True, exist_ok=True)

instrucoes = '''CatBridge | NetCatTest
https://netcattest.com/catsuite
https://github.com/netcattest/catsuite/tree/main/catbridge

PORTUGUES BRASILEIRO

Este pacote e portatil. Extraia todos os arquivos antes de executar.
Abra um terminal na pasta extraida. Substitua 192.168.1.20 pelo IP local
do computador que o celular pode acessar. Nao e necessario compilar.

Windows:
.\\catbridge.exe serve -state .\\private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743

Linux:
./catbridge serve -state ./private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743

No CatSuite, ative Configuracoes > Extensoes e abra
Extensoes > Conexoes > Parear CatBridge. Informe o endereco e o codigo
temporario mostrado no terminal. Mantenha o terminal aberto.

Ferramentas externas requerem instalacao e autorizacao separadas.
Este pacote nao inclui Docker, Nuclei ou executores de terceiros.
Mantenha a pasta private-state privada e use ambientes autorizados.

ENGLISH

This package is portable. Extract all files before running it.
Open a terminal in the extracted folder. Replace 192.168.1.20 with
your computer's local IP address reachable from the phone.
No compilation is needed.

Windows:
.\\catbridge.exe serve -state .\\private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743 -lang en

Linux:
./catbridge serve -state ./private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743 -lang en

In CatSuite, enable Settings > Extensions, then open
Extensions > Connections > Pair CatBridge. Enter the address and the
temporary code displayed in the terminal. Keep the terminal open.

External tools require separate installation and authorization.
Docker, Nuclei and third-party executors are not included.
Keep private-state private and use authorized environments.
'''

recursos = [
    'THIRD_PARTY_LICENSES.txt',
    'capability-contracts.json',
    'examples/aurora-cache.yaml',
    'examples/templates.json',
    'runtime/build_ecosystem.py',
    'runtime/ecosystem_lab.py',
    'runtime/finish_ecosystem.py',
    'runtime/lab.py',
    'runtime/openapi.json',
    'runtime/prepare.py',
    'runtime/prepare_amass_profile.py',
    'runtime/prepare_ecosystem.py',
    'runtime/releases.json',
]


def conteudo(binario, nome):
    arquivo = raiz / 'downloads' / binario
    itens = [(nome, arquivo.read_bytes(), 0o755)]
    itens.append(('README.txt', instrucoes.encode('utf-8'), 0o644))
    for relativo in recursos:
        itens.append((relativo, (raiz / relativo).read_bytes(), 0o644))
    linhas = [f'{hashlib.sha256(dados).hexdigest()}  {relativo}' for relativo, dados, _ in itens]
    itens.append(('SHA256SUMS.txt', ('\n'.join(linhas) + '\n').encode(), 0o644))
    return itens


with ZipFile(destino / 'catbridge-windows-amd64.zip', 'w') as pacote:
    for nome, dados, modo in conteudo('catbridge-windows-amd64.exe', 'catbridge.exe'):
        entrada = ZipInfo('CatBridge/' + nome, date_time=(2000, 1, 1, 0, 0, 0))
        entrada.create_system = 3
        entrada.external_attr = (0o100000 | modo) << 16
        entrada.compress_type = ZIP_DEFLATED
        pacote.writestr(entrada, dados)

with (destino / 'catbridge-linux-amd64.tar.gz').open('wb') as arquivo:
    with gzip.GzipFile(filename='', mode='wb', fileobj=arquivo, mtime=0) as compressao:
        with tarfile.open(fileobj=compressao, mode='w', format=tarfile.USTAR_FORMAT) as pacote:
            for nome, dados, modo in conteudo('catbridge-linux-amd64', 'catbridge'):
                entrada = tarfile.TarInfo('catbridge/' + nome)
                entrada.size = len(dados)
                entrada.mode = modo
                entrada.mtime = 0
                pacote.addfile(entrada, io.BytesIO(dados))

nomes = ['catbridge-windows-amd64.zip', 'catbridge-linux-amd64.tar.gz']
for nome in ['catbridge-windows-amd64.exe', 'catbridge-linux-amd64']:
    if (destino / nome).is_file():
        nomes.append(nome)
linhas = [f'{hashlib.sha256((destino / nome).read_bytes()).hexdigest()}  {nome}' for nome in sorted(nomes)]
(destino / 'SHA256SUMS.txt').write_text('\n'.join(linhas) + '\n', encoding='utf-8', newline='\n')
print('\n'.join(nomes))
