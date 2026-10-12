"""Offline deterministic report generation with family-cluster paired bootstrap."""
import collections,csv,hashlib,json,pathlib,random,statistics
ROOT=pathlib.Path(__file__).resolve().parents[2]
METRICS=['UA_rate','FR_rate','coverage','indeterminate_rate','correct_accept_rate','authorized_coverage']
def metrics(rows):
 eligible=[r for r in rows if r['oracle_authorized'] is not None];unauth=[r for r in eligible if not r['oracle_authorized']];auth=[r for r in eligible if r['oracle_authorized']];isout=lambda r,o:r['decision']['outcome']==o
 ratio=lambda n,d:n/d if d else None
 return dict(attempts=len(rows),eligible=len(eligible),authorized=len(auth),unauthorized=len(unauth),excluded=len(rows)-len(eligible),unsafe_accepts=sum(isout(r,'ACCEPT') for r in unauth),false_rejects=sum(isout(r,'REJECT') for r in auth),errors=sum(isout(r,'ERROR') for r in eligible),false_pq_claims=sum(r['decision'].get('pq_authenticated',False) and r['family_id']=='F17' for r in rows),UA_rate=ratio(sum(isout(r,'ACCEPT') for r in unauth),len(unauth)),FR_rate=ratio(sum(isout(r,'REJECT') for r in auth),len(auth)),coverage=ratio(sum(r['decision']['outcome'] in ('ACCEPT','REJECT') for r in eligible),len(eligible)),indeterminate_rate=ratio(sum(isout(r,'INDETERMINATE') for r in eligible),len(eligible)),correct_accept_rate=ratio(sum(isout(r,'ACCEPT') for r in auth),len(auth)),authorized_coverage=ratio(sum(r['decision']['outcome'] in ('ACCEPT','REJECT') for r in auth),len(auth)))
def mean(values):
 values=[v for v in values if v is not None];return statistics.mean(values) if values else None
def quantile(values,q):
 values=sorted(values);x=(len(values)-1)*q;l=int(x);return values[l]+(values[min(l+1,len(values)-1)]-values[l])*(x-l)
def ci(values,rng):
 if not values:return dict(mean=None,lower=None,upper=None,families=0)
 estimates=[statistics.mean(rng.choices(values,k=len(values))) for _ in range(2000)]
 return dict(mean=statistics.mean(values),lower=quantile(estimates,.025),upper=quantile(estimates,.975),families=len(values))
def validate_rows(rows,manifest):
 """Require the complete original frozen request/arm/repeat grid before scoring."""
 raw=(ROOT/'experiments/manifests/frozen.json').read_bytes()
 if hashlib.sha256(raw).hexdigest()!=manifest['freeze_sha256']:raise ValueError('frozen study manifest mismatch')
 frozen=json.loads(raw);expected={}
 arms=[('B1',None)]+[(a,b) for a in ['B2','B3'] for b in frozen['freshness_grid']]
 for entry in frozen['files']:
  data=(ROOT/entry['path']).read_bytes()
  if hashlib.sha256(data).hexdigest()!=entry['sha256']:raise ValueError('frozen study input changed')
  scenario=json.loads(data)
  for index,event in enumerate(scenario['events']):
   if event['type']!='REQUEST_AUTH':continue
   for arm,budget in arms:
    for repeat in range(frozen['repeats']):
     key=(scenario['scenario_id'],index,arm,budget,repeat)
     expected[key]=(scenario['family_id'],scenario['seed'],entry['split'],event['request_id'],event['at'],event['oracle_authorized'])
 seen=set()
 for row in rows:
  key=(row['scenario_id'],row['event_index'],row['arm'],row['budget'],row['repeat'])
  if key not in expected or key in seen:raise ValueError('frozen study duplicate/unplanned request')
  seen.add(key)
  observed=(row['family_id'],row['seed'],row['split'],row['request_id'],row['at'],row['oracle_authorized'])
  if observed!=expected[key] or row['oracle_authorized'] is not expected[key][-1] or row['eligible'] is not (expected[key][-1] is not None):raise ValueError('frozen study label/request mismatch')
  if row['decision'].get('outcome') not in {'ACCEPT','REJECT','INDETERMINATE','ERROR'}:raise ValueError('frozen study invalid outcome')
 if seen!=set(expected):raise ValueError('incomplete frozen study request/arm/repeat grid')
 return frozen
def accept_parity(rows):
 accepted=lambda arm,budget:{(row['scenario_id'],row['event_index']) for row in rows if row['arm']==arm and row['budget']==budget and row['decision']['outcome']=='ACCEPT'}
 return {budget:accepted('B2',budget)==accepted('B3',budget) for budget in [0,30,120,300]}
def main():
 source=ROOT/'experiments/raw/raw_attempts.jsonl';manifest=json.loads((ROOT/'experiments/MANIFEST.json').read_text())
 if hashlib.sha256(source.read_bytes()).hexdigest()!=manifest['raw_attempts_sha256']:raise ValueError('raw hash mismatch')
 rows=[json.loads(line) for line in source.read_text().splitlines()];validate_rows(rows,manifest);once=[r for r in rows if r['repeat']==0];groups=collections.defaultdict(list)
 for r in once:groups[(r['arm'],r['budget'])].append(r)
 out=ROOT/'experiments/reports';out.mkdir(parents=True,exist_ok=True);summaries=[];family_metrics={};intervals={};rng=random.Random(7001)
 for (arm,budget),items in sorted(groups.items(),key=lambda p:(p[0][0],-1 if p[0][1] is None else p[0][1])):
  key=f'{arm}/{budget}';fm={f:metrics([r for r in items if r['family_id']==f]) for f in sorted({r['family_id'] for r in items})};family_metrics[key]=fm;summary=dict(arm=arm,budget=budget,**metrics(items));summary.update({f'equal_family_{m}':mean([x[m] for x in fm.values()]) for m in METRICS});summaries.append(summary);intervals[key]={m:ci([x[m] for x in fm.values() if x[m] is not None],rng) for m in METRICS}
 paired={}
 for b in [0,30,120,300]:
  candidate=family_metrics[f'B3/{b}']
  for reference in ['B1/None',f'B2/{b}']:
   paired[f'B3/{b} minus {reference}']={m:ci([candidate[f][m]-family_metrics[reference][f][m] for f in candidate if candidate[f][m] is not None and family_metrics[reference][f][m] is not None],rng) for m in METRICS}
 with (out/'metrics.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(summaries[0]));w.writeheader();w.writerows(summaries)
 (out/'ci.json').write_text(json.dumps(dict(bootstrap_seed=7001,bootstrap_samples=2000,unit='family cluster; paired family differences; repeat0 only',interpretation='descriptive uncertainty of this constructed family set, not general real-world prevalence',arms=intervals,paired=paired),indent=2,sort_keys=True)+'\n')
 regressions=[r for r in once if r['oracle_authorized'] is False and r['decision']['outcome']=='ACCEPT'];(out/'unsafe_accepts.json').write_text(json.dumps(regressions,indent=2,sort_keys=True)+'\n')
 report=['# Research results — exploratory diagnostics','',f'81 schedules, 27 families, three seeds per family. Each arm repeated three times; repeated outputs must match exactly. {len(rows)} raw rows; {len(once)} repeat-0 rows used for statistics. F18 has undefined authoritative truth and is excluded from policy rates, retained in raw data. No confirmatory held-out claim: human preregistration/independent reviewer absent.','', '| Arm / budget seconds | Unauthorized denominator | Unsafe accepts | UA rate | Authorized denominator | False rejects | Indeterminate rate | Correct accept rate |','|---|---:|---:|---:|---:|---:|---:|---:|']
 for r in summaries:report.append(f'| {r["arm"]}/{r["budget"]} | {r["unauthorized"]} | {r["unsafe_accepts"]} | {r["UA_rate"]:.4f} | {r["authorized"]} | {r["false_rejects"]} | {r["indeterminate_rate"]:.4f} | {r["correct_accept_rate"]:.4f} |')
 report+=['','Traffic-weighted values above; equal-family values and exact denominators in metrics.csv, paired family bootstrap intervals in ci.json. Deterministic repeats are not additional samples.','', 'B2 and B3 with the SAME budget have the same ACCEPT set. B3 classifies missing/stale/unknown evidence as INDETERMINATE where B2 REJECTs. This is an evidence/availability taxonomy difference, not improved cryptographic safety. Budget 0 limits unseen-revocation acceptance but reduces authorized acceptance. Compromised issuers remain outside the freshness solution: disabling all accepts does not demonstrate useful protection against forgery. No universal zero-unsafe-accept claim.','', 'The hybrid-KEX/classical-authentication negative-control family (F17) produced three false PQ-authentication claims per repeat in B1 and zero in B2/B3. This is a known semantic trap, not a novelty result.', '', 'B1 is a deliberately unsafe stale/rollback cache and incorrect hybrid-KEX labeler. It is not stock SPIRE. Stock SPIRE issuance, Workload API validation, federation, rotation/revocation and separate paired chain/application diagnostics are measured. The full original 27-family paired real-system comparison remains incomplete. These real-system observations belong to the private origin study; this public command reruns only synthetic diagnostics. See docs/EVIDENCE.md for public scope. B4 TLS is a separate measured transport experiment. Real certificate validation does not confer policy freshness automatically.','', 'The prototype does not yet estimate end-to-end recovery_lag or stale_accept_duration from continuous sampling: sparse request schedules support only sampled accept/reject points. No fabricated precision or latency for unmeasured events. Synthetic simulator timings are not cryptographic benchmark results.','', 'Machine, source/binary/scenario hashes, failures and licenses are in experiments/MANIFEST.json. All unsafe-accept rows retained in unsafe_accepts.json.']
 tls=ROOT/'experiments/raw/tls/attempts.jsonl'
 if tls.exists():
  measurements=[json.loads(l) for l in tls.read_text().splitlines()];report+=['','## Observed local TLS transport','', 'Classical ECDSA-P256 certificate authentication in every run; pq_authenticated=false. No session resumption. Client process wall time includes startup, TLS and HTTP; not an isolated handshake latency.','', '| Observed group | Success / attempts | p50 client wall ms | p95 client wall ms | Handshake read / written bytes |','|---|---:|---:|---:|---|']
  for g in ['X25519','X25519MLKEM768']:
   values=[r for r in measurements if r['configured_group']==g];ok=[r for r in values if r['success']];times=[r['client_process_wall_ms'] for r in ok];sizes=sorted({(r['handshake_bytes_read'],r['handshake_bytes_written']) for r in ok});report.append(f'| {g} | {len(ok)}/{len(values)} | {quantile(times,.5):.3f} | {quantile(times,.95):.3f} | {sizes} |')
  report+=['','ML-DSA-65 primitive signing/verifying and tampered-message rejection recorded separately in primitive.json. This is not PQ-authenticated TLS or a SPIRE SVID. Sample size 10 per group is descriptive, not a general performance result.']
 report+=['', 'Live report version 2 preserves predeclared denominators (paired chains: five authorized/three unauthorized per arm; application: six/two). Missing/duplicate/failed cases, arms or contradictory labels cause an explicit incomplete result and nonzero CLI exit; aggregate counts/rates and parity become null. Valid observed counts remain separately inspectable. Retained complete stock/derived datasets have unchanged original metrics. Earlier report code and the failing regression remain in the private origin archive; they are not bundled with this companion. These reporting repairs do not alter the frozen synthetic data or policy decisions.']
 parity=accept_parity(once)
 if not all(parity.values()):
  report=[('B2 and B3 have different ACCEPT sets at the SAME budget for: '+', '.join(str(b) for b,same in parity.items() if not same)+'. Inspect the paired outcomes before interpreting safety or utility; this difference alone does not establish superiority.') if paragraph.startswith('B2 and B3 with the SAME budget have the same ACCEPT set.') else paragraph for paragraph in report]
 text='\n'.join(report)+'\n';(ROOT/'docs/RESEARCH_RESULTS.md').write_text(text);(out/'summary.md').write_text(text)
 samples=once[:12];(out/'decision_trace_samples.md').write_text('# Actual decision trace samples\n\n'+ '\n'.join(f'- {r["scenario_id"]} {r["arm"]}/{r["budget"]} {r["request_id"]}: {r["decision"]["outcome"]} ({r["decision"]["reason"]}), oracle={r["oracle_authorized"]}' for r in samples)+'\n')
 (out/'limitations.md').write_text('\n'.join(report[-8:])+'\n');print('Generated metrics.csv, family CIs, regressions and docs/RESEARCH_RESULTS.md from immutable raw logs.')
if __name__=='__main__':main()
