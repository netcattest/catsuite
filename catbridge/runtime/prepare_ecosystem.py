import argparse
import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--docker', default='docker')
parser.add_argument('--go', default='go')
parser.add_argument('--sources', type=Path)
parser.add_argument('--dependencies', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = root / 'runtime/ecosystem'
out.mkdir(parents=True, exist_ok=True)
sources = json.loads((args.sources or Path(__file__).with_name('releases.json')).read_text())

def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'CatSuite-preparation'}), timeout=180) as response:
        return response.read()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def release(item):
    name, source = item
    if name=='waybackurls':
        folder=out/name
        folder.mkdir(exist_ok=True)
        env=dict(os.environ,GOPROXY='https://proxy.golang.org',GOSUMDB='sum.golang.org',GOWORK='off',GOOS='linux',GOARCH='amd64',CGO_ENABLED='0')
        module='github.com/tomnomnom/waybackurls@v0.1.0'
        downloaded=json.loads(subprocess.check_output([args.go,'mod','download','-json',module],env=env,text=True))
        if 'Sum' not in downloaded:
            raise ValueError('E_SOURCE_UNVERIFIED')
        subprocess.run([args.go,'build','-buildvcs=false','-trimpath','-ldflags=-s -w','-o',str(folder/name),'.'],cwd=downloaded['Dir'],env=env,check=True,stdout=subprocess.DEVNULL)
        for license_path in Path(downloaded['Dir']).glob('*LICENSE*'):
            shutil.copy2(license_path,folder/license_path.name)
        return name,{'version':'0.1.0','source':'https://proxy.golang.org/'+module,'moduleSum':downloaded['Sum'],'binarySha256':sha((folder/name).read_bytes())}
    assets = source.get('assets', [])
    candidates = [a for a in assets if ('linux_amd64' in a['name'] or 'linux-amd64' in a['name'] or 'linux_x64' in a['name'] or 'linux-x86_64-musl' in a['name']) and a['name'].endswith(('.zip','.tar.gz','.tgz'))]
    if not candidates:
        return None
    asset = candidates[0]
    archive_path = out / 'downloads' / asset['name']
    archive_path.parent.mkdir(exist_ok=True)
    data = archive_path.read_bytes() if archive_path.exists() else fetch(asset['browser_download_url'])
    digest = sha(data)
    expected = asset.get('digest', '')
    if expected and expected != 'sha256:'+digest:
        raise ValueError('E_SOURCE_INTEGRITY')
    sums = sorted([a for a in assets if ('checksum' in a['name'].lower() or a['name']==asset['name']+'.sha256') and a['name'].endswith(('.txt','.sha256'))],key=lambda item:item['name']!=asset['name']+'.sha256')
    if sums:
        lines = fetch(sums[0]['browser_download_url']).decode().splitlines()
        matches = [line.split()[0] for line in lines if asset['name'] in line or len(lines)==1]
        if not matches or matches[0].lower() != digest:
            raise ValueError('E_SOURCE_INTEGRITY')
    if not expected and not sums:
        raise ValueError('E_SOURCE_UNVERIFIED:'+name)
    archive_path.write_bytes(data)
    folder = out / name
    folder.mkdir(exist_ok=True)
    if asset['name'].endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = [(x.filename, archive.read(x)) for x in archive.infolist() if not x.is_dir()]
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            files = [(x.name, archive.extractfile(x).read()) for x in archive.getmembers() if x.isfile()]
    binary = next((value for path,value in files if Path(path).name == name), None)
    if binary is None:
        raise ValueError('E_SOURCE_BINARY')
    (folder/name).write_bytes(binary)
    licenses = folder/'licenses'
    licenses.mkdir(exist_ok=True)
    for path,value in files:
        if 'license' in path.lower() or Path(path).name.lower() in ['copying','copyright']:
            (licenses/Path(path).name).write_bytes(value)
    return name, {'version':source['tag'].lstrip('v'), 'source':asset['browser_download_url'], 'sha256':digest, 'binarySha256':sha(binary)}

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    resolved = dict(value for value in executor.map(release, sources.items()) if value)
(out/'sources.lock.json').write_text(json.dumps(resolved, indent=2), encoding='utf-8')
print(json.dumps({name:record['version'] for name,record in resolved.items()}))

if args.dependencies:
    for name in ['sqlmap','jwt_tool','testssl','nikto','arjun']:
        source=sources[name]
        folder=out/name
        marker=folder/'source.json'
        if marker.exists():
            continue
        data=fetch('https://api.github.com/repos/'+source['repo']+'/tarball/'+source['tag'])
        folder.mkdir(exist_ok=True)
        archive_path=out/'downloads'/(name+'-'+source['tag']+'.tar.gz')
        archive_path.write_bytes(data)
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            prefix=archive.getmembers()[0].name.split('/')[0]
            for entry in archive.getmembers():
                if not entry.isfile():
                    continue
                relative=Path(entry.name).relative_to(prefix)
                if '..' in relative.parts or relative.is_absolute():
                    raise ValueError('E_SOURCE_PATH')
                target=folder/relative
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(archive.extractfile(entry).read())
        marker.write_text(json.dumps({'version':source['tag'].lstrip('v'),'url':source['url'],'archiveSha256':sha(data)}),encoding='utf-8')
    nmap_archive=out/'downloads/nmap-7.991.tar.bz2'
    if not nmap_archive.exists():
        nmap_archive.write_bytes(fetch('https://nmap.org/dist/nmap-7.991.tar.bz2'))
    if sha(nmap_archive.read_bytes()) != 'a5d507f29437bef3bedd4771ff9aaa8fc1c2a109ddba1f5b1cf12027456929be':
        raise ValueError('E_SOURCE_INTEGRITY')
    nmap_dir=out/'nmap-source'
    if not nmap_dir.exists():
        nmap_dir.mkdir()
        with tarfile.open(nmap_archive,'r:bz2') as archive:
            for entry in archive.getmembers():
                if not entry.isfile():
                    continue
                relative=Path(entry.name).relative_to('nmap-7.991')
                if '..' in relative.parts or relative.is_absolute():
                    raise ValueError('E_SOURCE_PATH')
                target=nmap_dir/relative
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(archive.extractfile(entry).read())
    base=json.loads((root/'runtime/prepared/tools.lock.json').read_text())['preparation']['base']
    script='''import subprocess,pathlib,json,hashlib
directory=pathlib.Path('/build')
(directory/'debs').mkdir(exist_ok=True)
(directory/'wheels').mkdir(exist_ok=True)
subprocess.run(['apt-get','update'],check=True)
subprocess.run(['apt-get','-y','--download-only','-o','Dir::Cache::archives=/build/debs','install','build-essential','libssl-dev','libpcre2-dev','zlib1g-dev','libpcap0.8','openssl','perl','libwww-perl','libio-socket-ssl-perl','libnet-ssleay-perl','bash','bzip2','bsdextrautils','libjson-perl'],check=True)
subprocess.run(['python','-m','pip','wheel','--no-cache-dir','--wheel-dir','/build/wheels','semgrep==1.179.0','termcolor','cprint','pycryptodomex','requests','ratelimit','dicttoxml'],check=True)
records=[]
for file in (directory/'debs').glob('*.deb'):
 records.append({'file':file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
(directory/'os-packages.lock.json').write_text(json.dumps(records,indent=2))
'''
    subprocess.run([args.docker,'run','--rm','--user','0','--mount','type=bind,source='+str(out)+',target=/build','--entrypoint','python',base,'-c',script],check=True)
    requirements=[]
    for wheel in sorted((out/'wheels').glob('*.whl')):
        name,version=wheel.name.split('-')[:2]
        requirements.append(name+'=='+version+' --hash=sha256:'+sha(wheel.read_bytes()))
    (out/'requirements.lock').write_text('\n'.join(requirements)+'\n',encoding='utf-8')
    print(json.dumps({'dependencies':'prepared','nmapSourceSha256':sha(nmap_archive.read_bytes())}))
