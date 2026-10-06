import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--go', default='go')
args = parser.parse_args()
r = Path(__file__).resolve().parent / 'ecosystem'
r.mkdir(exist_ok=True)
archive = r / 'downloads/amass-source-v5.1.1.tar.gz'
if not archive.exists():
    archive.parent.mkdir(exist_ok=True)
    request = urllib.request.Request('https://api.github.com/repos/owasp-amass/amass/tarball/v5.1.1', headers={'User-Agent': 'CatSuite-preparation'})
    with urllib.request.urlopen(request, timeout=120) as response:
        archive.write_bytes(response.read())
if hashlib.sha256(archive.read_bytes()).hexdigest() != '1206f907ce7ae11d46007ce7fba3f1808d62b48623afcfb1b4c377a1f80be649':
    raise ValueError('E_SOURCE_INTEGRITY')
source = r / 'amass-source'
if not source.exists():
    source.mkdir()
    with tarfile.open(archive, 'r:gz') as package:
        prefix = package.getmembers()[0].name.split('/')[0]
        for entry in package.getmembers():
            if not entry.isfile():
                continue
            relative = Path(entry.name).relative_to(prefix)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('E_PATH')
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(package.extractfile(entry).read())
registry = source / 'engine/plugins/load.go'
text = registry.read_text(encoding='utf8')
start = text.index('import (')
stop = text.index('func LoadAndStartPlugins', start)
text = text[:start] + 'import (\n "github.com/owasp-amass/amass/v5/engine/plugins/api"\n et "github.com/owasp-amass/amass/v5/engine/types"\n)\n\nvar pluginNewFuncs = []func() et.Plugin{api.NewCrtsh,NewKnownFQDN}\n\n' + text[stop:]
registry.write_text(text, encoding='utf8')
output = r / 'amass/amass'
output.parent.mkdir(exist_ok=True)
env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0', GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org')
subprocess.run([args.go, 'build', '-buildvcs=false', '-trimpath', '-ldflags=-s -w', '-o', str(output), './cmd/amass'], cwd=source, env=env, check=True)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
lock = r / 'sources.lock.json'
doc = json.loads(lock.read_text(encoding='utf8'))
record = doc['amass']
record.setdefault('upstreamBinarySha256', record['binarySha256'])
record.update(binarySha256=sha(output), profile='catsuite-crtsh-only', profileSourceSha256=sha(archive), registrySha256=sha(registry))
lock.write_text(json.dumps(doc, indent=2), encoding='utf8')
print(json.dumps({'amass': '5.1.1', 'profile': 'catsuite-crtsh-only', 'binarySha256': sha(output)}))
