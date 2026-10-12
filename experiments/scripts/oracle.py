"""Authoritative-world oracle, independent Python code, no imports from Go policy.
Does not impose a cache-age cutoff: the authoritative truth is distinct from a
verifier's observation. This is NOT independent human scientific validation.
"""
import copy, re
URI=re.compile(r'spiffe://([a-z0-9._-]{1,255})(/[A-Za-z0-9._/-]+)$',re.ASCII)
def domain(uri):
 m=URI.fullmatch(uri)
 if not m or len(uri)>2048 or any(x in ('','.','..') for x in uri.split('/')[3:]):return None
 return m[1]
def labels(s):
 current={b['domain']:copy.deepcopy(b) for b in s['initial_bundles']};creds={c['name']:copy.deepcopy(c) for c in s['credentials']};rules={(r['source'],r['target'],r['action']) for r in s['config']['rules']};federated=set(s['config']['federated']);seen=set();compromised=set();denied=set();out={}
 for i,e in enumerate(s['events']):
  kind=e['type'];now=e['at']
  if kind in ('PUBLISH_NEW_BUNDLE','ROTATE_ISSUER'):current[e['bundle']['domain']]=copy.deepcopy(e['bundle'])
  elif kind=='REVOKE_ISSUER':current[e['domain']]['issuers']=[k for k in current[e['domain']]['issuers'] if k!=e['issuer']]
  elif kind=='ISSUE_IDENTITY':creds[e['credential']['name']]=copy.deepcopy(e['credential'])
  elif kind=='EXPIRE_SVID':creds[e['credential_name']]['not_after']=now
  elif kind=='COMPROMISE_ISSUER':compromised.add((e['domain'],e['issuer']))
  elif kind=='REMOVE_FEDERATION':federated.discard(e['domain'])
  elif kind=='DENY_AUDIENCE':denied.add(e['target'])
  elif kind=='REQUEST_AUTH':
   c=creds.get(e['credential_name']);src=domain(e['source']);dst=domain(e['target']);b=current.get(src)
   if c and c['auth_profile']!='classical':value=None
   else:value=bool(c and src and dst and c['id']==e['source'] and src==c['issuer_domain'] and dst==s['config']['local_domain'] and (src==dst or src in federated) and b and c['issuer'] in b['issuers'] and c['signature_valid'] and c['not_before']<=now<c['not_after'] and e['audience']==e['target'] and e['target'] not in denied and (e['source'],e['target'],e['action']) in rules and e['request_id'] not in seen and (src,c['issuer']) not in compromised and not s['config']['require_pq'])
   seen.add(e['request_id']);out[i]=value
 return out

def negative_control(s):
 """B1 unsafe stale cache + no sequence checking; only invoked by comparisons."""
 cache={b['domain']:copy.deepcopy(b) for b in s['initial_bundles']};published=copy.deepcopy(cache);creds={c['name']:copy.deepcopy(c) for c in s['credentials']};blocked=set();federated=set(s['config']['federated']);seen=set();denied=set();rules={(r['source'],r['target'],r['action']) for r in s['config']['rules']};out={}
 for i,e in enumerate(s['events']):
  k=e['type']
  if k in ('PUBLISH_NEW_BUNDLE','ROTATE_ISSUER'):published[e['bundle']['domain']]=copy.deepcopy(e['bundle'])
  elif k=='REVOKE_ISSUER':
   b=published[e['domain']];b['issuers']=[v for v in b['issuers'] if v!=e['issuer']]
  elif k=='FETCH_BUNDLE' and e['domain'] not in blocked:
   if e.get('bundle') or e['domain'] in published:cache[e['domain']]=copy.deepcopy(e.get('bundle') or published[e['domain']])
  elif k=='REPLAY_OLD_BUNDLE':cache[e['domain']]=copy.deepcopy(e['bundle'])
  elif k=='PARTITION':blocked.add(e['domain'])
  elif k=='HEAL':blocked.discard(e['domain'])
  elif k=='REMOVE_FEDERATION':federated.discard(e['domain']);cache.pop(e['domain'],None)
  elif k=='ISSUE_IDENTITY':creds[e['credential']['name']]=copy.deepcopy(e['credential'])
  elif k=='EXPIRE_SVID':creds[e['credential_name']]['not_after']=e['at']
  elif k=='DENY_AUDIENCE':denied.add(e['target'])
  elif k=='REQUEST_AUTH':
   c=creds.get(e['credential_name'],{});src=domain(e['source']);dst=domain(e['target']);b=cache.get(src,{})
   accept=bool(src and src==c.get('issuer_domain') and c.get('id')==e['source'] and dst==s['config']['local_domain'] and (src==dst or src in federated) and c.get('issuer') in b.get('issuers',[]) and c.get('signature_valid') and c.get('not_before',0)<=e['at']<c.get('not_after',0) and e['audience']==e['target'] and e['target'] not in denied and (e['source'],e['target'],e['action']) in rules and e['request_id'] not in seen and not e.get('unknown'))
   seen.add(e['request_id']);out[i]=dict(outcome='ACCEPT' if accept else 'REJECT',reason='UNSAFE_NEGATIVE_CONTROL',pq_authenticated=accept and e['key_exchange_profile']=='X25519MLKEM768',verification_mode='simulated-unsafe-negative-control')
 return out
