import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

p=argparse.ArgumentParser()
p.add_argument('--docker',default='docker')
p.add_argument('--go',default='go')
a=p.parse_args()
r=Path(__file__).resolve().parent
out=r/'ecosystem'
def docker(*args):
    return subprocess.check_output([a.docker,*args],text=True,timeout=120).strip()
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
env=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0')
subprocess.run([a.go,'build','-buildvcs=false','-trimpath','-ldflags=-s -w','-o',str(out/'catbridge'),'.'],cwd=r.parent,env=env,check=True)
toolbox=(out/'toolbox.sha256').read_text().strip()
if docker('image','inspect','--format','{{.Id}}','catsuite-ecosystem-toolbox:sdk1.4')!=toolbox:
    raise ValueError('E_TOOL_CHANGED')
(out/'catsuite.yml').write_text('''rules:
  - id: catsuite.python.eval-input
    languages: [python]
    severity: WARNING
    message: Dynamic evaluation requires manual review.
    pattern: eval($X)
  - id: catsuite.python.shell-execution
    languages: [python]
    severity: WARNING
    message: Shell execution requires manual review.
    pattern: subprocess.run(..., shell=True, ...)
  - id: catsuite.javascript.eval-input
    languages: [javascript, typescript]
    severity: WARNING
    message: Dynamic evaluation requires manual review.
    pattern: eval($X)
''',encoding='utf-8')
(out/'Dockerfile.runner').write_text(f'FROM catsuite-ecosystem-toolbox:sdk1.4\nCOPY --chmod=0555 catbridge /opt/catbridge\nCOPY catsuite.yml /opt/rules/catsuite.yml\nENTRYPOINT ["/opt/catbridge"]\n',encoding='utf-8')
docker('build','--network=none','-f',str(out/'Dockerfile.runner'),'-t','catsuite-ecosystem:sdk1.4',str(out))
image=docker('image','inspect','--format','{{.Id}}','catsuite-ecosystem:sdk1.4')
previous=json.loads((r/'prepared/tools.lock.json').read_text())
tools=list(previous['tools'])
versions={'nmap':'7.991','semgrep':'1.179.0','sqlmap':'1.10','arjun':'2.2.7','jwt_tool':'2.3.0','testssl':'3.2.4','nikto':'2.6.1'}
versions.update({name:record['version'] for name,record in json.loads((out/'sources.lock.json').read_text()).items()})
entries={'nmap':'/usr/local/bin/nmap','semgrep':'/opt/venv/bin/semgrep','sqlmap':'/opt/tools/sqlmap/sqlmap.py','arjun':'/opt/tools/arjun/arjun/__main__.py','jwt_tool':'/opt/tools/jwt_tool/jwt_tool.py','testssl':'/opt/tools/testssl/testssl.sh','nikto':'/opt/tools/nikto/program/nikto.pl'}
for name,version in sorted(versions.items()):
    entry=entries.get(name,'/opt/tools/'+name)
    binary=docker('run','--rm','--network=none','--entrypoint','sha256sum',image,entry).split()[0]
    tools.append({'id':name,'version':version,'image':image,'binarySha256':binary})
lock={'format':'catbridge-tools','version':1,'broker':previous['broker'],'tools':tools,'preparation':{'base':previous['preparation']['base'],'ecosystemImage':image,'sources':json.loads((out/'sources.lock.json').read_text()),'architecture':'linux/amd64','nmapSourceSha256':digest(out/'downloads/nmap-7.991.tar.bz2'),'rulesSha256':digest(out/'catsuite.yml'),'osPackages':json.loads((out/'os-packages.lock.json').read_text()),'pythonRequirementsSha256':digest(out/'requirements.lock'),'sourceProfiles':{name:json.loads((out/name/'source.json').read_text()) for name in ['sqlmap','arjun','jwt_tool','testssl','nikto']}}}
key=Ed25519PrivateKey.generate();public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
lock['signature']={'publicKey':base64.b64encode(public).decode(),'value':base64.b64encode(key.sign(json.dumps(lock,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())).decode()}
(out/'tools.lock.json').write_text(json.dumps(lock,indent=2,ensure_ascii=False),encoding='utf-8');(out/'author.sha256').write_text(hashlib.sha256(public).hexdigest()+'\n')
print(json.dumps({'image':image,'tools':len(tools),'author':hashlib.sha256(public).hexdigest()}))
