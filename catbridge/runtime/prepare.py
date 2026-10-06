import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

p = argparse.ArgumentParser()
p.add_argument("--docker", default="docker")
p.add_argument("--go", default="go")
p.add_argument("--output", default="prepared")
p.add_argument("--reuse", action="store_true")
a = p.parse_args()
r = Path(__file__).resolve().parent
out = Path(a.output).resolve()
out.mkdir(parents=True, exist_ok=True)
def execute(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()
def docker(*args):
    return execute([a.docker, *args])
def digest(data):
    return hashlib.sha256(data).hexdigest()
def fetch(url):
    if not url.startswith("https://"):
        raise ValueError("E_TRANSPORT")
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "CatSuite-host-preparation"}), timeout=120) as response:
        return response.read(128 * 1024 * 1024)
if docker("info", "--format", "{{.OSType}}") != "linux":
    raise ValueError("E_RUNTIME_UNAVAILABLE")
base_tag = "python:3.12-slim-bookworm"
previous = None
if a.reuse:
    previous = json.loads((out / "tools.lock.json").read_text(encoding="utf-8"))
    signature = previous.pop("signature")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    public = base64.b64decode(signature["publicKey"], validate=True)
    if digest(public) != (out / "author.sha256").read_text().strip():
        raise ValueError("E_SIGNATURE")
    Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(signature["value"], validate=True), json.dumps(previous, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    base = previous["preparation"]["base"]
else:
    docker("pull", base_tag)
    base = json.loads(docker("image", "inspect", base_tag))[0]["RepoDigests"][0]
env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
execute([a.go, "build", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", str(out / "catbridge"), "."], cwd=r.parent, env=env)
tool_files = {}
sources = []
for tool, version in [("httpx", "1.12.0"), ("katana", "1.7.0")]:
    if previous:
        tool_files[tool] = digest((out / tool).read_bytes())
        if tool_files[tool] != next(x["binarySha256"] for x in previous["tools"] if x["id"] == tool):
            raise ValueError("E_INTEGRITY")
        sources.append(next(x for x in previous["preparation"]["sources"] if x["tool"] == tool))
        continue
    api = json.loads(fetch(f"https://api.github.com/repos/projectdiscovery/{tool}/releases/tags/v{version}"))
    archive = next(x for x in api["assets"] if x["name"] == f"{tool}_{version}_linux_amd64.zip")
    checksums = next(x for x in api["assets"] if "checksums" in x["name"])
    hashes = fetch(checksums["browser_download_url"]).decode().splitlines()
    expected = next(line.split()[0] for line in hashes if line.split()[-1].lstrip("*") == archive["name"])
    data = fetch(archive["browser_download_url"])
    if digest(data) != expected:
        raise ValueError("E_INTEGRITY")
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        target = out / tool
        target.write_bytes(z.read(tool))
        licenses = out / "licenses" / tool
        licenses.mkdir(parents=True, exist_ok=True)
        for name in z.namelist():
            if "license" in name.lower():
                (licenses / Path(name).name).write_bytes(z.read(name))
    tool_files[tool] = digest(target.read_bytes())
    sources.append({"tool": tool, "version": version, "url": archive["browser_download_url"], "sha256": expected})
wheels = out / "wheels"
wheels.mkdir(exist_ok=True)
if not previous:
    docker("run", "--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,size=128m", "--mount", f"type=bind,source={out},target=/build", base, "python", "-m", "pip", "download", "--no-cache-dir", "--only-binary=:all:", "--dest", "/build/wheels", "schemathesis==4.29.1")
requirements = []
dependencies = []
for wheel in sorted(wheels.glob("*.whl")):
    name, version = wheel.name.split("-")[:2]
    sha = digest(wheel.read_bytes())
    if previous and {"file": wheel.name, "sha256": sha} not in previous["preparation"]["dependencies"]:
        raise ValueError("E_INTEGRITY")
    requirements.append(f"{name}=={version} --hash=sha256:{sha}")
    dependencies.append({"file": wheel.name, "sha256": sha})
(out / "requirements.lock").write_text("\n".join(requirements) + "\n", encoding="utf-8")
broker_hash = digest((out / "catbridge").read_bytes())
images = {}
for tool in ["broker", "httpx", "katana", "schemathesis"]:
    content = f"FROM {base}\nCOPY --chmod=0555 catbridge /opt/catbridge\nRUN mkdir /ipc && chown 65532:65532 /ipc\n"
    if tool in tool_files:
        content += f"COPY --chmod=0555 {tool} /opt/tools/{tool}\n"
    if tool == "schemathesis":
        content += "COPY wheels /wheels\nCOPY requirements.lock /requirements.lock\nRUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-index --find-links=/wheels --require-hashes -r /requirements.lock && rm -rf /wheels /root/.cache\n"
    content += 'USER 65532:65532\nENTRYPOINT ["/opt/catbridge"]\n'
    (out / f"Dockerfile.{tool}").write_text(content, encoding="utf-8")
    docker("build", "--network=none" if tool != "schemathesis" else "--network=none", "-f", str(out / f"Dockerfile.{tool}"), "-t", f"catsuite-{tool}:sdk1.3", str(out))
    image = docker("image", "inspect", "--format", "{{.Id}}", f"catsuite-{tool}:sdk1.3")
    images[tool] = image
st_entry = docker("run", "--rm", "--network=none", "--entrypoint", "sha256sum", images["schemathesis"], "/opt/venv/bin/st").split()[0]
lock = {"format": "catbridge-tools", "version": 1, "broker": {"id": "catsuite.broker", "version": "1.3.0", "image": images["broker"], "binarySha256": broker_hash}, "tools": [{"id": tool, "version": version, "image": images[tool], "binarySha256": tool_files.get(tool, st_entry)} for tool, version in [("httpx", "1.12.0"), ("katana", "1.7.0"), ("schemathesis", "4.29.1")]], "preparation": {"base": base, "sources": sources, "dependencies": dependencies, "architecture": "linux/amd64"}}
key = Ed25519PrivateKey.generate()
public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
canonical = json.dumps(lock, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
lock["signature"] = {"publicKey": base64.b64encode(public).decode(), "value": base64.b64encode(key.sign(canonical)).decode()}
(out / "tools.lock.json").write_text(json.dumps(lock, indent=2, ensure_ascii=False), encoding="utf-8")
(out / "author.sha256").write_text(digest(public) + "\n", encoding="utf-8")
print(json.dumps({"manifest": "tools.lock.json", "author": digest(public), "images": images}))
