"""Independent OS-process restart exercise: accepted seq12 then rejected seq11."""
import json,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1];binary=ROOT/'bin/proofmesh';results=[]
with tempfile.TemporaryDirectory(prefix='proofmesh-restart-',dir=ROOT/'.cache') as td:
 folder=pathlib.Path(td);state=folder/'state.json';bundle=folder/'bundle.json'
 for seq in [12,11]:
  bundle.write_text(json.dumps(dict(synthetic_only=True,domain='alpha.local',sequence=seq,epoch=1,issuers=['synthetic-key'],authenticated=True)))
  command=[str(binary),'state','update','--file',str(state),'--domain','alpha.local','--at',str(24-seq),'--bundle',str(bundle)];r=subprocess.run(command,capture_output=True,text=True,timeout=10);results.append(dict(sequence=seq,exit_code=r.returncode,evidence=json.loads(r.stdout),stderr=r.stderr))
 r=subprocess.run([str(binary),'state','show','--file',str(state)],capture_output=True,text=True,timeout=10);saved=json.loads(r.stdout)
 passed=results[0]['exit_code']==0 and results[1]['exit_code']==1 and results[1]['evidence']['reason']=='BUNDLE_ROLLBACK' and saved['records'][0]['high_sequence']==12
 record=dict(passed=passed,separate_processes=True,attempts=results,checkpoint=saved,limitations='Trusted local filesystem; checksum is corruption detection, not protection against an owner replacing the entire state plus initialized marker.')
 (ROOT/'experiments/reports/progress-0.2/restart.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2));raise SystemExit(0 if passed else 1)
