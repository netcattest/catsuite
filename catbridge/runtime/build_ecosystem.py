import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--docker', default='docker')
a = p.parse_args()
r = Path(__file__).resolve().parent
out = r/'ecosystem'
base = json.loads((r/'prepared/tools.lock.json').read_text())['preparation']['base']
for record in json.loads((out/'os-packages.lock.json').read_text()):
    if hashlib.sha256((out/'debs'/record['file']).read_bytes()).hexdigest() != record['sha256']:
        raise ValueError('E_INTEGRITY')
runtime_dir=out/'runtime-debs';runtime_dir.mkdir(exist_ok=True)
import shutil
for record in json.loads((out/'os-packages.lock.json').read_text()):
    name=record['file'].split('_')[0]
    if name.endswith('-dev') or name.startswith(('gcc','g++','cpp')) or name in ['build-essential','make','binutils','binutils-common','binutils-x86-64-linux-gnu','dpkg-dev','libdpkg-perl','patch','bzip2'] or name.startswith(('libasan','libubsan','libtsan','liblsan','libcc1','libgprofng','libctf','libbinutils','libgcc-')):
        continue
    shutil.copy2(out/'debs'/record['file'],runtime_dir/record['file'])
content = f'''FROM {base} AS compiler
COPY debs /debs
RUN dpkg -i /debs/*.deb && rm -rf /debs
COPY --chmod=0755 nmap-source /src
WORKDIR /src
RUN python -c 'from pathlib import Path; p=Path("nmap.cc"); p.write_text(p.read_text().replace("  close_nse();", "#ifndef NOLUA\\n  close_nse();\\n#endif"))'
RUN find . -name configure -exec touch {{}} + && CXXFLAGS="-O2 -include cstddef" ./configure --without-ncat --without-nping --without-zenmap --without-ndiff --without-liblua --without-libssh2 --without-nmap-update && make -j2 && make install DESTDIR=/output
FROM {base}
COPY runtime-debs /debs
RUN dpkg -i /debs/*.deb && rm -rf /debs /var/lib/apt/lists
COPY wheels /wheels
COPY requirements.lock /requirements.lock
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-index --find-links=/wheels --require-hashes -r /requirements.lock && rm -rf /wheels /root/.cache
COPY --from=compiler /output/usr/local /usr/local
'''
for name in json.loads((out/'sources.lock.json').read_text()):
    content += f'COPY --chmod=0555 {name}/{name} /opt/tools/{name}\n'
    if (out/name/'licenses').exists():
        content += f'COPY {name}/licenses /opt/licenses/{name}\n'
    elif (out/name/'LICENSE').exists():
        content += f'COPY {name}/LICENSE /opt/licenses/{name}/LICENSE\n'
for name in ['sqlmap','arjun','jwt_tool','testssl','nikto']:
    content += f'COPY {name} /opt/tools/{name}\n'
content += 'COPY downloads/nikto-2.6.1.tar.gz /nikto.tar.gz\nRUN python -c \'import tarfile,pathlib; a=tarfile.open("/nikto.tar.gz"); a.extractall("/tmp/nikto-source",filter="data"); import shutil; shutil.copytree(next(pathlib.Path("/tmp/nikto-source").iterdir()),"/opt/tools/nikto",dirs_exist_ok=True); shutil.rmtree("/tmp/nikto-source"); pathlib.Path("/nikto.tar.gz").unlink()\'\n'
content += 'COPY nmap-source/LICENSE /opt/licenses/nmap/LICENSE\n'
content += 'RUN mkdir /ipc && chown 65532:65532 /ipc\nUSER 65532:65532\n'
(out/'Dockerfile.toolbox').write_text(content,encoding='utf-8')
subprocess.run([a.docker,'build','--network=none','-f',str(out/'Dockerfile.toolbox'),'-t','catsuite-ecosystem-toolbox:sdk1.4',str(out)],check=True)
identity = subprocess.check_output([a.docker,'image','inspect','--format','{{.Id}}','catsuite-ecosystem-toolbox:sdk1.4'],text=True).strip()
(out/'toolbox.sha256').write_text(identity+'\n')
print(json.dumps({'toolbox':identity}))
