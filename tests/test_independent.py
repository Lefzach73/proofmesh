import copy, hashlib, importlib.util, json, pathlib, subprocess, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/'experiments/scripts'/f'{name}.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
oracle=module('oracle')
class IndependentTests(unittest.TestCase):
 def test_frozen_hashes_and_labels(self):
  manifest=json.loads((ROOT/'experiments/manifests/frozen.json').read_text())
  self.assertEqual(hashlib.sha256((ROOT/'experiments/scripts/generate.py').read_bytes()).hexdigest(),manifest['generator_sha256'])
  for entry in manifest['files']:
   raw=(ROOT/entry['path']).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),entry['sha256']);s=json.loads(raw)
   for i,v in oracle.labels(s).items():self.assertEqual(v,s['events'][i]['oracle_authorized'],(s['scenario_id'],i))
 def test_oracle_catches_accept_all_mutant(self):
  failures=[]
  for p in ROOT.glob('scenarios/*/*.json'):
   s=json.loads(p.read_text());failures.extend((s['scenario_id'],i) for i,v in oracle.labels(s).items() if v is False)
  self.assertGreater(len(failures),10)
 def test_mutation_domain_binding(self):
  p=ROOT/'scenarios/dev/F01_s17.json';s=json.loads(p.read_text());s['credentials'][0]['issuer_domain']='beta.local';s['events'][0]['oracle_authorized']=False
  self.assertIs(oracle.labels(s)[0],False)
 def test_simulation_no_network_dependencies(self):
  prod='\n'.join(p.read_text() for p in (ROOT/'internal').rglob('*.go') if not p.name.endswith('_test.go') and 'state' not in p.parts)
  for package in ['"net"','"net/http"','"os/exec"','"time"']:self.assertNotIn(package,prod)
 def test_no_secret_material(self):
  for d in ['scenarios','experiments/manifests','internal','cmd','docs']:
   for p in (ROOT/d).rglob('*'):
    if p.is_file():self.assertNotIn('-----BEGIN '+'PRIVATE KEY-----',p.read_text(),str(p))
if __name__=='__main__':unittest.main()
