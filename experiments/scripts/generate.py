"""Prospective synthetic fixtures. Manual authoritative labels, not B3 outputs.
Regeneration is explicit; the experiment runner verifies the frozen hashes.
"""
import copy, hashlib, json, pathlib, random
ROOT=pathlib.Path(__file__).resolve().parents[2]
A='spiffe://alpha.local/api-a'; B='spiffe://beta.local/api-b'; T='spiffe://alpha.local/db'
def bundle(domain='alpha.local',keys=None,seq=1):
 return dict(domain=domain,issuers=keys if keys is not None else ['a1' if domain=='alpha.local' else 'b1'],sequence=seq,epoch=1,authenticated=True)
def credential(name='a',id=A,issuer='a1',domain='alpha.local'):
 return dict(name=name,id=id,issuer_domain=domain,issuer=issuer,not_before=0,not_after=1000,signature_valid=True,auth_profile='classical')
def event(t,kind,**kw):return dict(at=t,type=kind,**kw)
def req(t=1,name='a',source=A,truth=True,outcome='ACCEPT',reason='AUTHORIZED',rid=None,**kw):
 return event(t,'REQUEST_AUTH',credential_name=name,source=source,target=T,audience=T,action='read',request_id=rid or f'r{t}',key_exchange_profile='classical',expected=dict(outcome=outcome,reason=reason),oracle_authorized=truth,**kw)
def scenario(f,seed):
 r=random.Random(seed);delay=r.randint(1,5)
 s=dict(schema_version='proofmesh-sim-1',scenario_id=f'{f}_s{seed}',family_id=f,seed=seed,synthetic_only=True,config=dict(local_domain='alpha.local',federated=['beta.local'],freshness_budget=120,epoch=1,require_pq=False,rules=[dict(source=A,target=T,action='read'),dict(source=B,target=T,action='read')]),initial_bundles=[bundle(),bundle('beta.local')],credentials=[credential(),credential('b',B,'b1','beta.local'),credential('new',A,'a2')],events=[req()])
 e=s['events'];c=s['credentials'][0]
 if f=='F02':e[:]=[req(name='b',source=B)]
 elif f=='F03':s['config']['federated']=[];e[:]=[req(name='b',source=B,truth=False,outcome='REJECT',reason='WRONG_DOMAIN')]
 elif f=='F04':e[:]=[req(),event(10,'ROTATE_ISSUER',bundle=bundle(keys=['a1','a2'],seq=2)),event(10+delay,'FETCH_BUNDLE',domain='alpha.local'),req(20,name='new'),req(21),event(140,'PUBLISH_NEW_BUNDLE',bundle=bundle(keys=['a2'],seq=3)),event(140+delay,'FETCH_BUNDLE',domain='alpha.local'),req(150,name='new'),req(151,truth=False,outcome='REJECT',reason='REVOKED_ISSUER')]
 elif f=='F05':e[:]=[req(name='new',truth=False,outcome='REJECT',reason='REVOKED_ISSUER')]
 elif f=='F06':e[:]=[event(1,'PARTITION',domain='alpha.local'),event(2,'REVOKE_ISSUER',domain='alpha.local',issuer='a1'),req(10,truth=False),req(130,truth=False,outcome='INDETERMINATE',reason='STALE_BUNDLE'),event(140,'HEAL',domain='alpha.local'),event(140+delay,'FETCH_BUNDLE',domain='alpha.local'),req(150,truth=False,outcome='REJECT',reason='REVOKED_ISSUER')]
 elif f=='F07':s['initial_bundles'][0]=bundle(seq=11);e[:]=[event(10,'PUBLISH_NEW_BUNDLE',bundle=bundle(keys=['a2'],seq=12)),event(10+delay,'FETCH_BUNDLE',domain='alpha.local'),event(30,'REPLAY_OLD_BUNDLE',domain='alpha.local',bundle=bundle(seq=11)),req(31,truth=False,outcome='REJECT',reason='REVOKED_ISSUER')]
 elif f=='F08':s['initial_bundles'][0]=bundle(seq=None);e[:]=[req(),event(10,'PUBLISH_NEW_BUNDLE',bundle=bundle(keys=['a1','a2'],seq=None)),event(10+delay,'FETCH_BUNDLE',domain='alpha.local'),req(20,name='new')]
 elif f=='F09':e[:]=[event(1,'PARTITION',domain='alpha.local'),event(130,'FETCH_BUNDLE',domain='alpha.local'),req(131,outcome='INDETERMINATE',reason='STALE_BUNDLE')]
 elif f=='F10':e[:]=[event(1,'PARTITION',domain='alpha.local'),event(20,'ROTATE_ISSUER',bundle=bundle(keys=['a1','a2'],seq=2)),req(130,name='new',outcome='REJECT',reason='REVOKED_ISSUER'),event(140,'HEAL',domain='alpha.local'),event(140+delay,'FETCH_BUNDLE',domain='alpha.local'),req(150,name='new')]
 elif f=='F11':e[:]=[event(1,'CLOCK_SKEW',offset=-2),req(1,outcome='INDETERMINATE',reason='UNKNOWN_VERIFIER_STATE'),event(5,'CLOCK_SKEW',offset=0),req(6)]
 elif f=='F12':c['not_after']=2;e[:]=[req(),req(2,truth=False,outcome='REJECT',reason='EXPIRED_SVID')]
 elif f=='F13':c['id']='spiffe://alpha.local/a%2Fb';e[:]=[req(source=c['id'],truth=False,outcome='REJECT',reason='MALFORMED_IDENTITY')]
 elif f=='F14':x=req(truth=False,outcome='REJECT',reason='POLICY_DENIED');x['audience']='spiffe://alpha.local/other';e[:]=[x]
 elif f=='F15':e[:]=[event(0,'COMPROMISE_ISSUER',domain='alpha.local',issuer='a1'),req(truth=False)]
 elif f=='F16':e[:]=[req(name='b',source=B),event(2,'REMOVE_FEDERATION',domain='beta.local'),req(3,name='b',source=B,truth=False,outcome='REJECT',reason='WRONG_DOMAIN')]
 elif f=='F17':x=req();x['key_exchange_profile']='X25519MLKEM768';e[:]=[x]
 elif f=='F18':c['auth_profile']='lab-ml-dsa';e[:]=[req(truth=None,outcome='INDETERMINATE',reason='CRYPTO_PROFILE_MISMATCH')]
 elif f=='F19':c['issuer']='unknown-key';e[:]=[req(truth=False,outcome='REJECT',reason='REVOKED_ISSUER')]
 elif f=='F20':s['initial_bundles'][0]=bundle(keys=[]);e[:]=[req(truth=False,outcome='REJECT',reason='REVOKED_ISSUER')]
 elif f=='F21':c['issuer_domain']='beta.local';c['issuer']='b1';e[:]=[req(truth=False,outcome='REJECT',reason='WRONG_DOMAIN')]
 elif f=='F22':e[:]=[req(unknown=True,outcome='INDETERMINATE',reason='UNKNOWN_VERIFIER_STATE')]
 elif f=='F23':e[:]=[req(rid='repeated'),req(2,rid='repeated',truth=False,outcome='REJECT',reason='REPLAY')]
 elif f=='F24':e[:]=[event(10,'FETCH_BUNDLE',domain='alpha.local',bundle=bundle(seq=None)),req(20)]
 elif f=='F25':e[:]=[event(10,'FETCH_BUNDLE',domain='alpha.local',bundle=bundle(keys=['a2'],seq=1)),req(20)]
 elif f=='F26':e[:]=[event(10,'FETCH_BUNDLE',domain='alpha.local',bundle=bundle('beta.local')),req(20)]
 elif f=='F27':s['initial_bundles']=s['initial_bundles'][1:];e[:]=[event(0,'PUBLISH_NEW_BUNDLE',bundle=bundle()),req(outcome='INDETERMINATE',reason='MISSING_BUNDLE')]
 return s

def main():
 entries=[]
 for i in range(1,28):
  f=f'F{i:02}';split='dev' if i<=12 else 'test_frozen'
  for seed in [17,42,101]:
   s=scenario(f,seed);p=ROOT/'scenarios'/split/(s['scenario_id']+'.json');raw=(json.dumps(s,indent=2,sort_keys=True)+'\n').encode();p.write_bytes(raw);entries.append(dict(path=str(p.relative_to(ROOT)),family_id=f,split=split,seed=seed,sha256=hashlib.sha256(raw).hexdigest()))
 (ROOT/'examples/federation_basic.scenario.json').write_text(json.dumps(scenario('F02',17),indent=2)+'\n')
 manifest=dict(schema='proofmesh-freeze-1',status='prospective-freeze; unapproved exploratory diagnostics only',seeds=[17,42,101],repeats=3,note='Deterministic repeats validate reproducibility; not independent statistical samples.',freshness_grid=[0,30,120,300],families=27,held_out_families=15,generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),files=entries,oracle='Manual authoritative labels in fixtures, separately checked by Python oracle; same AI engineer, no independent human review',source_license='Synthetic fixtures generated locally; public licensing pending human IP approval',exclusions=['F18 unavailable synthetic PQ credential verification: truth null'],approval_required='Human research lead preregistration and independently reviewed labels before confirmatory held-out study')
 (ROOT/'experiments/manifests/frozen.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
 print('Frozen 81 schedules, 27 families, 15 held-out families, before first evaluator tests.')
if __name__=='__main__':main()
