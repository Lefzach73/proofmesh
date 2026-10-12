"""Bounded honest prover runner: preserve raw output and exact per-lemma status."""
import gzip,hashlib,json,os,pathlib,re,shutil,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1]

def required_checks():
 """Validate discovery against the reviewed contract before running any proof."""
 checks=json.loads((ROOT/'formal/required_checks.json').read_text())
 if not isinstance(checks,list) or not checks:
  raise ValueError('required check inventory must be a nonempty list')
 expected={}
 for check in checks:
  if not isinstance(check,dict) or set(check)!={'model','lemma','expected_status'}:
   raise ValueError('invalid required check entry')
  model,name,status=check['model'],check['lemma'],check['expected_status']
  if not isinstance(model,str) or not re.fullmatch(r'formal/models/[A-Za-z0-9_]+\.spthy',model):
   raise ValueError('invalid required model path')
  if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name) or status not in ('verified','counterexample'):
   raise ValueError('invalid required lemma or expected status')
  key=(model,name)
  if key in expected:
   raise ValueError('duplicate required check: '+repr(key))
  expected[key]=status
 models=sorted((ROOT/'formal/models').glob('*.spthy'))
 paths=[str(p.relative_to(ROOT)) for p in models]
 if len(paths)!=len(set(paths)) or set(paths)!={model for model,_ in expected}:
  raise ValueError('missing, duplicate or unexpected formal model')
 discovered={};model_bytes={}
 for p in models:
  model_bytes[p]=p.read_bytes()
  # Whitespace must not hide a helper; documentation comments are not lemmas.
  source=re.sub(r'//[^\n]*|/\*.*?\*/','',model_bytes[p].decode('utf-8'),flags=re.S)
  names=re.findall(r'^[ \t]*lemma[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b',source,re.M)
  model=str(p.relative_to(ROOT))
  if not names or len(names)!=len(set(names)):
   raise ValueError('empty or duplicate lemma discovery: '+model)
  discovered[p]=names
 actual={(str(p.relative_to(ROOT)),name) for p,names in discovered.items() for name in names}
 if actual!=set(expected):
  raise ValueError('required formal checks differ: missing='+repr(sorted(set(expected)-actual))+'; unexpected='+repr(sorted(actual-set(expected))))
 return discovered,expected,model_bytes

def snapshot_sources(model_bytes):
 """Create immutable-by-convention, exclusive snapshots; never replace bytes."""
 directory=ROOT/'formal/source_snapshots'
 directory.mkdir(parents=True,exist_ok=True)
 snapshots={}
 for p,raw in model_bytes.items():
  snapshot=directory/(hashlib.sha256(raw).hexdigest()+'.spthy')
  try:
   with snapshot.open('xb') as file:
    file.write(raw);file.flush();os.fsync(file.fileno())
   snapshot.chmod(0o444)
  except FileExistsError:
   pass
  if snapshot.is_symlink() or snapshot.read_bytes()!=raw:
   raise ValueError('conflicting source snapshot: '+str(snapshot.relative_to(ROOT)))
  snapshots[p]=snapshot
 return snapshots

def verify_source_bindings(model_bytes,snapshots):
 """Fail if a working model or executed snapshot changes during this run."""
 if set((ROOT/'formal/models').glob('*.spthy'))!=set(model_bytes):
  raise ValueError('formal model inventory changed during proof run')
 for p,raw in model_bytes.items():
  if p.read_bytes()!=raw:
   raise ValueError('working model changed during proof run: '+str(p.relative_to(ROOT)))
  snapshot=snapshots[p]
  if snapshot.is_symlink() or snapshot.read_bytes()!=raw:
   raise ValueError('source snapshot changed during proof run: '+str(snapshot.relative_to(ROOT)))

try:
 model_names,expected_checks,model_bytes=required_checks()
 snapshots=snapshot_sources(model_bytes)
 verify_source_bindings(model_bytes,snapshots)
except (OSError,ValueError) as error:
 print('Formal source/inventory validation failed: '+str(error),file=sys.stderr)
 raise SystemExit(1)

exe=os.environ.get('TAMARIN') or shutil.which('tamarin-prover')
local=ROOT/'.tools/tamarin/tamarin-prover/1.12.0/bin/tamarin-prover'
if not exe and local.exists():exe=str(local)
env=dict(os.environ)
if (ROOT/'.tools/maude/maude').exists():env['PATH']=str(ROOT/'.tools/maude')+os.pathsep+env.get('PATH','');env['MAUDE_LIB']=str(ROOT/'.tools/maude')
config_path=ROOT/'.tools/formal-paths.json'
if config_path.exists():
 config=json.loads(config_path.read_text());exe=exe or config['tamarin'];env['PATH']=config['maude_dir']+os.pathsep+env.get('PATH','');env['MAUDE_LIB']=config['maude_dir']
records=[];bad=False
version='unavailable'
if exe:
 r=subprocess.run([exe,'--version'],env=env,capture_output=True,text=True,timeout=20);version=r.stdout+r.stderr
for p,names in model_names.items():
 for name in names:
  snapshot=snapshots[p];digest=hashlib.sha256(model_bytes[p]).hexdigest()
  command=[exe or 'tamarin-prover',str(snapshot.relative_to(ROOT)),f'--prove={name}','--quit-on-warning','--bound=120','--heuristic=ci','+RTS','-N2','-RTS'];start=time.monotonic();output='';code=None;status='not-run';lemma_status='not-run';binding_error=None
  try:
   verify_source_bindings(model_bytes,snapshots)
   if exe:
    try:
     r=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=int(os.environ.get('PROOFMESH_FORMAL_TIMEOUT','45')));output=r.stdout+r.stderr;code=r.returncode
     match=re.search(r'^\s*'+name+r'\s*\([^\n]*\):\s*(verified|falsified|unknown)',output,re.M)
     if match:lemma_status={'verified':'verified','falsified':'counterexample','unknown':'unknown'}[match[1]]
     elif code==0:lemma_status='unknown'
     else:lemma_status='invalid'
     status='invalid' if code!=0 else ('completed' if match else 'unknown')
    except subprocess.TimeoutExpired as e:
     status=lemma_status='timeout';output=(e.stdout or b'').decode(errors='replace')+(e.stderr or b'').decode(errors='replace')
   else:output='Tamarin unavailable; no proof attempted.\n'
   verify_source_bindings(model_bytes,snapshots)
  except (OSError,ValueError) as error:
   binding_error=str(error);status=lemma_status='invalid'
   output+='\nSource binding validation failed: '+binding_error+'\n'
  log=ROOT/'formal/proof_logs'/f'{p.stem}-{name}.log'
  if len(output)>1024*1024:
   log=log.with_suffix('.log.gz')
   with log.open('wb') as file:
    with gzip.GzipFile(fileobj=file,mode='wb',mtime=0) as gz:gz.write(output.encode())
  else:log.write_text(output)
  expected=expected_checks[(str(p.relative_to(ROOT)),name)]
  record=dict(expected_status=expected,model=str(p.relative_to(ROOT)),sha256=digest,source_snapshot=str(snapshot.relative_to(ROOT)),source_snapshot_sha256=digest,source_binding_valid=binding_error is None,source_binding_error=binding_error,command=command,version=version,exit_code=code,runtime_seconds=time.monotonic()-start,status=status,lemmas={name:lemma_status},log=str(log.relative_to(ROOT)));records.append(record)
  (ROOT/'formal/proof_logs/status.json').write_text(json.dumps(records,indent=2)+'\n')
  print(p.name,name,lemma_status,flush=True)
  bad|=status!='completed' or lemma_status!=expected
  if binding_error:raise SystemExit(1)
# An explicitly named negative control must produce a real counterexample.
# Every positive claim and every helper must verify; unknown/timeouts fail.
try:
 verify_source_bindings(model_bytes,snapshots)
except (OSError,ValueError) as error:
 records[-1].update(status='invalid',lemmas={name:'invalid'},source_binding_valid=False,source_binding_error=str(error))
 (ROOT/'formal/proof_logs/status.json').write_text(json.dumps(records,indent=2)+'\n')
 print('Formal source binding validation failed: '+str(error),file=sys.stderr)
 bad=True
raise SystemExit(1 if bad else 0)
