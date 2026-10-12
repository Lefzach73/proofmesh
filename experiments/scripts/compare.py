"""Paired frozen-schedule diagnostics; no confirmatory held-out claim."""
import hashlib,json,pathlib,platform,subprocess,time
from oracle import labels,negative_control
ROOT=pathlib.Path(__file__).resolve().parents[2]
def main():
 frozen=json.loads((ROOT/'experiments/manifests/frozen.json').read_text());bin=ROOT/'bin/proofmesh';rows=[];failures=[];commands=[];start=time.monotonic()
 if not bin.exists():raise RuntimeError('make build first')
 for entry in frozen['files']:
  p=ROOT/entry['path'];raw=p.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise RuntimeError(f'frozen schedule modified: {p.name}')
  s=json.loads(raw);truth=labels(s)
  for i,value in truth.items():
   if value!=s['events'][i]['oracle_authorized']:raise RuntimeError(f'unadjudicated oracle disagreement {p.name}:{i}')
  arms=[('B1',None)]+[(arm,budget) for arm in ('B2','B3') for budget in frozen['freshness_grid']]
  for arm,budget in arms:
   previous=None
   for repeat in range(frozen['repeats']):
    if arm=='B1':decisions=negative_control(s);output=json.dumps(decisions,sort_keys=True);code=0;logs=[]
    else:
     command=[str(bin),'simulate','--scenario',str(p),'--budget',str(budget)]+(['--strict'] if arm=='B2' else []);commands.append([f'bin/proofmesh','simulate','--scenario',entry['path'],'--budget',str(budget)]+(['--strict'] if arm=='B2' else []))
     try:r=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=10);output=r.stdout;code=r.returncode;error=r.stderr
     except subprocess.TimeoutExpired:output='';code=None;error='timeout'
     if code!=0:failures.append(dict(scenario_id=s['scenario_id'],arm=arm,budget=budget,repeat=repeat,exit_code=code,error=error))
     try:logs=[json.loads(l) for l in output.splitlines()];decisions={l['event_index']:l['decision'] for l in logs if l.get('decision')}
     except (json.JSONDecodeError,KeyError) as e:decisions={};failures.append(dict(scenario_id=s['scenario_id'],arm=arm,budget=budget,repeat=repeat,error=str(e)))
    if previous is not None and previous!=output:raise RuntimeError('nondeterministic paired repeat')
    previous=output
    for i,value in truth.items():
     e=s['events'][i];d=decisions.get(i,dict(outcome='ERROR',reason='RUN_FAILURE',pq_authenticated=False))
     rows.append(dict(scenario_id=s['scenario_id'],family_id=s['family_id'],split=entry['split'],seed=s['seed'],repeat=repeat,arm=arm,budget=budget,event_index=i,at=e['at'],request_id=e['request_id'],oracle_authorized=value,eligible=value is not None,decision=d))
 out=ROOT/'experiments/raw';out.mkdir(parents=True,exist_ok=True);raw=out/'raw_attempts.jsonl';raw.write_text(''.join(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n' for r in rows));(out/'failures.json').write_text(json.dumps(failures,indent=2)+'\n')
 source=[p for d in ('internal','cmd','experiments/scripts') for p in (ROOT/d).rglob('*') if p.is_file() and p.suffix in ('.go','.py')]
 sha={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source)}
 commit=(subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True).stdout.strip() if (ROOT/'.git').exists() else '') or 'public-export-not-yet-committed'
 manifest=dict(study='exploratory diagnostics; confirmatory approval pending',oracle_independence='separate Python implementation, same AI engineer; human reviewer absent',freeze_sha256=hashlib.sha256((ROOT/'experiments/manifests/frozen.json').read_bytes()).hexdigest(),raw_attempts_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(bin.read_bytes()).hexdigest(),source_hashes=sha,git_commit=commit,os=platform.platform(),machine=platform.machine(),python=platform.python_version(),go='1.27.2',scenario_count=len(frozen['files']),family_count=27,seeds=frozen['seeds'],repeats=3,repeats_independent=False,attempt_rows=len(rows),failed_runs=len(failures),runtime_seconds=time.monotonic()-start,arms=['B1 unsafe']+[f'{a}/{b}' for a in ('B2','B3') for b in frozen['freshness_grid']],unavailable_arms={'B0':'Stock SPIRE issuance/validation measured separately; full paired federation/rotation arm not implemented','B4':'separate real OpenSSL loopback transport arm'},exclusions={'F18':'primitive-supported ML-DSA is not integrated into synthetic SVID policy; truth null'},primary_weighting='equal family means among families with defined denominator for that metric',secondary_weighting='traffic weighted, exact eligible attempts',inference='repeat 0 only; clustered family bootstrap; no deterministic repeat treated as independent',source_license='synthetic; licensing approval pending',commands=commands[:9])
 (ROOT/'experiments/MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n');print(f'{len(rows)} rows; {len(failures)} failures; raw hash {manifest["raw_attempts_sha256"]}');raise SystemExit(1 if failures else 0)
if __name__=='__main__':main()
