"""Proof-gate contract mutations. Stub results are not formal proof evidence."""
import contextlib
import hashlib
import io
import json
import os
import pathlib
import subprocess
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / 'formal/required_checks.json'
CHECKS = json.loads(INVENTORY.read_text())
MODELS = sorted((ROOT / 'formal/models').glob('*.spthy'))
SOURCES = {p: p.read_text() for p in MODELS}
RUNNER = compile((ROOT / 'formal/run.py').read_text(), str(ROOT / 'formal/run.py'), 'exec')


class FormalGateTests(unittest.TestCase):
    def run_gate(self, *, models=None, sources=None, inventory=None, missing_inventory=False,
                 outcomes=None, snapshots=None, after_proof=None):
        sources = dict(SOURCES if sources is None else sources)
        outcomes = outcomes or {}
        snapshots = {} if snapshots is None else snapshots
        self.snapshot_creates, self.prover_commands = [], []
        self.last_snapshots = snapshots
        snapshot_dir = ROOT / 'formal/source_snapshots'
        snapshot_models = {str((snapshot_dir / (hashlib.sha256(raw.encode()).hexdigest() + '.spthy')).relative_to(ROOT)): str(p.relative_to(ROOT))
                           for p, raw in sources.items()}
        writes, proved = {}, []
        real_read_text = pathlib.Path.read_text
        real_read_bytes = pathlib.Path.read_bytes
        real_open = pathlib.Path.open

        def read_text(path, *args, **kwargs):
            if path == INVENTORY:
                if missing_inventory:
                    raise FileNotFoundError(str(path))
                return json.dumps(CHECKS if inventory is None else inventory)
            if path in sources:
                return sources[path]
            return real_read_text(path, *args, **kwargs)

        def read_bytes(path, *args, **kwargs):
            if path.parent == snapshot_dir:
                if path not in snapshots:
                    raise FileNotFoundError(str(path))
                return snapshots[path]
            return sources[path].encode() if path in sources else real_read_bytes(path, *args, **kwargs)

        class SnapshotFile(io.BytesIO):
            def __init__(self, path):
                super().__init__()
                self.path = path

            def fileno(self):
                return -1  # os.fsync is also stubbed.

            def close(self):
                if not self.closed:
                    snapshots[self.path] = self.getvalue()
                super().close()

        def open_snapshot(path, mode='r', *args, **kwargs):
            if path.parent != snapshot_dir:
                return real_open(path, mode, *args, **kwargs)
            self.assertEqual(mode, 'xb')
            if path in snapshots:
                raise FileExistsError(str(path))
            snapshots[path] = b''
            self.snapshot_creates.append(path)
            return SnapshotFile(path)

        def run(command, **kwargs):
            if '--version' in command:
                return subprocess.CompletedProcess(command, 0, 'synthetic test prover\n', '')
            name = next(arg.split('=', 1)[1] for arg in command if arg.startswith('--prove='))
            self.prover_commands.append(command)
            model = snapshot_models.get(command[1], command[1])
            proved.append((model, name))
            expected = next((c['expected_status'] for c in CHECKS
                             if (c['model'], c['lemma']) == (model, name)), 'verified')
            outcome = outcomes.get((model, name), expected)
            raw = 'falsified - found trace' if outcome == 'counterexample' else outcome
            if after_proof:
                after_proof(sources, snapshots, len(proved))
            return subprocess.CompletedProcess(command, 0, f'{name} (all-traces): {raw} (1 steps)\n', '')

        with patch.object(pathlib.Path, 'glob', side_effect=lambda _: iter(MODELS if models is None else models)), \
                patch.object(pathlib.Path, 'read_text', read_text), \
                patch.object(pathlib.Path, 'read_bytes', read_bytes), \
                patch.object(pathlib.Path, 'open', open_snapshot), \
                patch.object(pathlib.Path, 'mkdir'), \
                patch.object(pathlib.Path, 'chmod'), \
                patch.object(pathlib.Path, 'is_symlink', return_value=False), \
                patch.object(pathlib.Path, 'write_text', lambda p, text: writes.__setitem__(p, text)), \
                patch('os.fsync'), \
                patch.dict(os.environ, {'TAMARIN': '/synthetic-test-prover'}), \
                patch('subprocess.run', side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                exec(RUNNER, {'__file__': str(ROOT / 'formal/run.py'), '__name__': '__main__'})
            except SystemExit as error:
                code = error.code
            else:
                self.fail('runner did not report an exit status')
        return code, proved, writes

    def assert_discovery_refused(self, **kwargs):
        code, proved, writes = self.run_gate(**kwargs)
        self.assertNotEqual(code, 0)
        self.assertEqual(proved, [])
        self.assertEqual(writes, {})

    def test_reviewed_inventory_is_complete(self):
        self.assertEqual(len(CHECKS), 19)
        self.assertEqual(sum(c['expected_status'] == 'counterexample' for c in CHECKS), 1)
        code, proved, writes = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(set(proved), {(c['model'], c['lemma']) for c in CHECKS})
        self.assertEqual(len(proved), 19)
        self.assertEqual(len(json.loads(writes[ROOT / 'formal/proof_logs/status.json'])), 19)

    def test_empty_model_discovery_fails_before_retaining_success(self):
        self.assert_discovery_refused(models=[])

    def test_missing_or_unexpected_model_is_refused(self):
        self.assert_discovery_refused(models=MODELS[1:])
        extra = ROOT / 'formal/models/unreviewed.spthy'
        self.assert_discovery_refused(models=MODELS + [extra], sources={**SOURCES, extra: 'theory Extra begin end'})

    def test_missing_negative_control_is_refused(self):
        model = ROOT / 'formal/models/authentication.spthy'
        changed = SOURCES[model].replace('lemma unconditional_authentication_negative_control:', '// removed required control:')
        self.assert_discovery_refused(sources={**SOURCES, model: changed})

    def test_duplicate_or_unexpected_lemma_is_refused(self):
        model = ROOT / 'formal/models/claim_semantics.spthy'
        for name in ('downgrade_claim_safety', 'unreviewed_negative_control'):
            with self.subTest(name=name):
                self.assert_discovery_refused(sources={**SOURCES, model: SOURCES[model] + '\nlemma ' + name + ': "F"\n'})

    def test_missing_empty_duplicate_or_substituted_inventory_is_refused(self):
        self.assert_discovery_refused(missing_inventory=True)
        for inventory in ([], CHECKS[1:], CHECKS + [CHECKS[0]],
                          CHECKS[:-1] + [{**CHECKS[-1], 'lemma': 'substituted'}]):
            with self.subTest(inventory_size=len(inventory)):
                self.assert_discovery_refused(inventory=inventory)

    def test_malformed_inventory_is_refused(self):
        for inventory in ({'checks': CHECKS}, [None], [{**CHECKS[0], 'expected_status': 'unknown'}],
                          [{**CHECKS[0], 'unexpected_field': True}]):
            with self.subTest(inventory=inventory):
                self.assert_discovery_refused(inventory=inventory)

    def test_indentation_does_not_hide_a_reused_helper(self):
        model = ROOT / 'formal/models/authentication.spthy'
        changed = SOURCES[model].replace('lemma request_credential_origin', '  lemma request_credential_origin')
        code, proved, _ = self.run_gate(sources={**SOURCES, model: changed})
        self.assertEqual(code, 0)
        self.assertIn(('formal/models/authentication.spthy', 'request_credential_origin'), proved)
        self.assertEqual(len(proved), 19)

    def test_comments_do_not_create_discovered_lemmas(self):
        model = ROOT / 'formal/models/claim_semantics.spthy'
        changed = SOURCES[model] + '\n/*\nlemma documentation_example: "F"\n*/\n'
        code, proved, _ = self.run_gate(sources={**SOURCES, model: changed})
        self.assertEqual(code, 0)
        self.assertEqual(len(proved), 19)

    def test_unexpected_falsification_unknown_or_negative_control_success_fails(self):
        for check, result in ((CHECKS[0], 'counterexample'), (CHECKS[0], 'unknown'),
                              (next(c for c in CHECKS if c['expected_status'] == 'counterexample'), 'verified')):
            with self.subTest(lemma=check['lemma'], result=result):
                code, _, _ = self.run_gate(outcomes={(check['model'], check['lemma']): result})
                self.assertNotEqual(code, 0)

    def test_prover_uses_content_addressed_snapshot_and_records_original_identity(self):
        code, _, writes = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.snapshot_creates), 3)
        records = json.loads(writes[ROOT / 'formal/proof_logs/status.json'])
        for record in records:
            raw = SOURCES[ROOT / record['model']].encode()
            digest = hashlib.sha256(raw).hexdigest()
            snapshot = 'formal/source_snapshots/' + digest + '.spthy'
            self.assertEqual(record['sha256'], digest)
            self.assertEqual(record['source_snapshot'], snapshot)
            self.assertEqual(record['source_snapshot_sha256'], digest)
            self.assertTrue(record['source_binding_valid'])
            self.assertEqual(record['command'][1], snapshot)
            self.assertEqual(self.last_snapshots[ROOT / snapshot], raw)

    def test_existing_snapshot_is_verified_without_overwriting(self):
        snapshots = {ROOT / 'formal/source_snapshots' / (hashlib.sha256(raw.encode()).hexdigest() + '.spthy'): raw.encode()
                     for raw in SOURCES.values()}
        before = dict(snapshots)
        code, _, _ = self.run_gate(snapshots=snapshots)
        self.assertEqual(code, 0)
        self.assertEqual(self.snapshot_creates, [])
        self.assertEqual(snapshots, before)

    def test_conflicting_snapshot_fails_before_prover_and_is_not_overwritten(self):
        raw = SOURCES[MODELS[0]].encode()
        path = ROOT / 'formal/source_snapshots' / (hashlib.sha256(raw).hexdigest() + '.spthy')
        snapshots = {path: b'corrupted existing snapshot'}
        code, proved, writes = self.run_gate(snapshots=snapshots)
        self.assertNotEqual(code, 0)
        self.assertEqual(proved, [])
        self.assertEqual(writes, {})
        self.assertEqual(snapshots[path], b'corrupted existing snapshot')

    def test_working_source_change_during_proof_invalidates_gate(self):
        def mutate(sources, snapshots, count):
            if count == 1:
                sources[MODELS[-1]] += '\n// concurrent source edit\n'
        code, proved, writes = self.run_gate(after_proof=mutate)
        self.assertNotEqual(code, 0)
        self.assertEqual(len(proved), 1)
        record = json.loads(writes[ROOT / 'formal/proof_logs/status.json'])[-1]
        self.assertEqual(record['status'], 'invalid')
        self.assertFalse(record['source_binding_valid'])

    def test_snapshot_change_during_proof_invalidates_gate(self):
        def mutate(sources, snapshots, count):
            if count == 1 and snapshots:
                snapshots[next(iter(snapshots))] += b'corrupt'
        code, proved, writes = self.run_gate(after_proof=mutate)
        self.assertNotEqual(code, 0)
        self.assertEqual(len(proved), 1)
        record = json.loads(writes[ROOT / 'formal/proof_logs/status.json'])[-1]
        self.assertEqual(record['status'], 'invalid')
        self.assertFalse(record['source_binding_valid'])


if __name__ == '__main__':
    unittest.main()
