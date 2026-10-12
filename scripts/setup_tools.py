"""Install pinned Go locally, verifying official archive SHA-256. No cloud resources."""
import hashlib,json,pathlib,platform,shutil,subprocess,tarfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1];VERSION='go1.27.2';tools=ROOT/'.tools';cache=ROOT/'.cache';tools.mkdir(exist_ok=True);cache.mkdir(exist_ok=True)
local=tools/'go/bin/go';existing=str(local) if local.exists() else shutil.which('go')
if existing:
 r=subprocess.run([existing,'version'],capture_output=True,text=True)
 if VERSION in r.stdout:print(r.stdout.strip());raise SystemExit(0)
arch={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64'}.get(platform.machine());osname={'Darwin':'darwin','Linux':'linux'}.get(platform.system())
if not arch or not osname:raise RuntimeError('installer supports Linux/macOS arm64/amd64; install Go 1.27.2 manually for another platform')
with urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all',timeout=30) as r:releases=json.load(r)
f=next(f for v in releases if v['version']==VERSION for f in v['files'] if f['os']==osname and f['arch']==arch and f['kind']=='archive');p=cache/f['filename']
with urllib.request.urlopen('https://go.dev/dl/'+f['filename'],timeout=60) as r:p.write_bytes(r.read())
assert hashlib.sha256(p.read_bytes()).hexdigest()==f['sha256'],'toolchain checksum mismatch'
with tarfile.open(p) as t:
 for m in t.getmembers():
  target=(tools/m.name).resolve()
  if not target.is_relative_to(tools.resolve()):raise RuntimeError('unsafe archive path')
 if hasattr(tarfile,'data_filter'):t.extractall(tools,filter='data')
 else:t.extractall(tools)
(ROOT/'experiments/manifests/go-toolchain.json').write_text(json.dumps(f,indent=2)+'\n')
print(subprocess.run([str(local),'version'],capture_output=True,text=True,check=True).stdout.strip())
