"""Run with python3 -m unittest discover -s internal/scriptcatalog -p '*_test.py'."""
import contextlib
import io
import importlib.util
import json
import sys
import asyncio
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock
from datetime import datetime, timezone

FIXED_NOW = datetime(2026, 1, 15, 12, tzinfo=timezone.utc).timestamp()

SCRIPT = Path(__file__).with_name('bat-sweep-report-v1.py').resolve()
spec = importlib.util.spec_from_file_location('sweep', SCRIPT)
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)

# Fixtures are created under a service umask: the sweep refuses group- or
# other-writable trees, and a login umask of 002 would make every fixture unsafe.
_saved_umask = None

def setUpModule():
    global _saved_umask
    _saved_umask = os.umask(0o022)

def tearDownModule():
    os.umask(_saved_umask)

class SweepTests(unittest.TestCase):
    def test_classification(self):
        now = FIXED_NOW
        def messages(text):
            return [{'role': 'assistant', 'text': text}]
        for text, expected in [('Please provide the password?', 'needs_human'), ('Phase 2 complete', 'milestone'), ('[BAT-STATUS: NEED_HUMAN] review', 'needs_human'), ('[BAT-STATUS: CONTINUE] next step', 'nudge'), ('Unclear next step', 'needs_human')]:
            self.assertEqual(sweep.classify(messages(text), now)[0], expected)
        self.assertEqual(sweep.classify(messages('continue') + [{'role': 'user', 'text': 'hello', 'ts': datetime.fromtimestamp(now, timezone.utc).isoformat()}], now), ('skip', 'Ted active'))
        for command in ['git push origin example', 'rm -rf /', 'sudo test', 'terraform apply', 'gh pr merge 1']:
            self.assertTrue(sweep.DESTRUCTIVE_CMD.search(command))
        self.assertFalse(sweep.DESTRUCTIVE_CMD.search('python3 -m unittest'))
        self.assertLessEqual(len(sweep.excerpt('sk-' + 'a'*60)), 120)
        self.assertNotIn('a'*32, sweep.excerpt('sk-' + 'a'*60))

    def run_fake(self, missing=False, forbidden_write=False, package_missing=False, mismatch=False, symlink=False, oversized=False, include_excerpts=False, native=False, unsafe=False, poison=False, temporary_write=False, escaped_import=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / '.config/bat-agent-connector'
            cfg.mkdir(parents=True)
            cfg.joinpath('discord-channels.toml').write_text(''.join(f'[[channels]]\nhost="sample-host"\nworkspace="w{i}"\n' for i in range(10)))
            package = root / '.local/lib' / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'site-packages/bat_agent_connector'
            package.mkdir(parents=True)
            package.joinpath('__init__.py').write_text('raise ModuleNotFoundError()\n' if package_missing else '')
            package.joinpath('config.py').write_text('def load_config():\n    ' + ('raise FileNotFoundError()' if missing else "from pathlib import Path; (Path.home() / 'forbidden-state').write_text('attempt'); return object()" if forbidden_write else 'return object()') + '\n')
            package.joinpath('fleet.py').write_text('class Fleet:\n    def __init__(self, *a, **k): pass\n    async def close(self): pass\n')
            package.joinpath('registry.py').write_text('def list_entries(host): return []\n')
            package.joinpath('triage.py').write_text('QUOTA_PATTERNS=[]\nasync def sessions_triage(*a, **k):\n    ids = range(3) if k.get("agent") else range(2)\n    return {"sessions": [{"session_id": str(i), "workspace": "w"+str(i)} for i in ids]}\n')
            package.joinpath('service.py').write_text(textwrap.dedent('''
                from datetime import datetime, timezone, timedelta
                def stamp(): return (datetime.fromtimestamp(__FIXED_NOW__, timezone.utc)-timedelta(minutes=40)).isoformat()
                async def sessions_list(*a, **k):
                    return {"sessions": [{"session_id": str(i), "workspace": "w"+str(i), "agent_kind": "claude" if i < 3 else "codex", "state": "quota_exhausted" if i < 3 else "idle", "loaded": True, "last_activity": stamp()} for i in range(10)]}
                async def session_read(fleet, host, sid, **k):
                    msgs = [{"role": "assistant", "text": "[BAT-STATUS: CONTINUE] next", "ts": stamp()}]
                    if sid == '9' and k.get('last_n') == 20:
                        msgs = [{"role": "user", "text": "[BAT hourly sweep]", "ts": stamp()} for _ in range(6)] + msgs
                    return {"pending": {"kind": "permission", "toolUseId": "example", "input_preview": "git push" if sid == '0' else "python3 -m unittest"} if sid in ('0','1') else None, "messages": msgs}
                def forbidden(*a, **k):
                    raise AssertionError('WRITE CALLED')
                session_answer = session_send = forbidden
            ''').replace('__FIXED_NOW__', repr(FIXED_NOW)))
            for name in ['lifecycle', 'jev']:
                package.joinpath(name+'.py').write_text("raise AssertionError('FORBIDDEN MODULE IMPORT')\n")
            if temporary_write:
                package.joinpath('config.py').write_text("import os\ndef load_config():\n    with open(os.environ['TMPDIR']+'/connector-temp', 'w') as f: f.write('temporary')\n    return object()\n")
            if escaped_import:
                sibling = package.parent/'outside'
                sibling.mkdir()
                sibling.joinpath('config.py').write_text('def load_config(): return object()\n')
                package.joinpath('__init__.py').write_text("from pathlib import Path\n__path__.insert(0,str(Path(__file__).parent.parent/'outside'))\n")
            if oversized:
                with package.joinpath('service.py').open('a') as stream:
                    stream.write("\nasync def sessions_list(*a, **k): return {'sessions': [{'session_id':str(i)} for i in range(51)]}\n")
            if native:
                package.joinpath('extension.so').write_bytes(b'fake native')
            if unsafe:
                package.chmod(0o777)
            if symlink:
                cfg.joinpath('discord-channels.toml').unlink()
                outside = root / 'outside.toml'
                outside.write_text('[[channels]]\nhost="sample-host"\nworkspace="outside"\n')
                cfg.joinpath('discord-channels.toml').symlink_to(outside)
            if poison:
                root.joinpath('sitecustomize.py').write_text("raise RuntimeError('PYTHONPATH imported')\n")
            try:
                digest = sweep.connector_digest(package)
            except sweep.Refused:
                digest = 'a'*64
            if not native and not unsafe:
                helper = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', str(SCRIPT), '--print-connector-digest'], text=True, capture_output=True, env={**os.environ, 'HOME': tmp, 'PYTHONPATH': tmp, 'TZ': 'UTC'})
                self.assertEqual(helper.returncode, 0)
                self.assertEqual(helper.stdout.strip(), digest)
                self.assertEqual(helper.stderr, '')
            args = {'hosts': ['sample-host'], 'connector_tree_sha256': '0'*64 if mismatch else digest, 'include_excerpts': include_excerpts}
            # Inject through a Python argument; the production CLI has no clock hook.
            harness = "import runpy, sys; sweep = runpy.run_path(sys.argv[1]); sys.argv = [sys.argv[1]]; sweep['main'](now=" + repr(FIXED_NOW) + ")"
            result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', '-c', harness, str(SCRIPT)], input=json.dumps(args), text=True, capture_output=True, env={**os.environ, 'HOME': tmp, 'PYTHONPATH': tmp, 'TZ': 'UTC'})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, '')
            self.assertFalse((root / '.local/state').exists())
            self.assertFalse((root / 'forbidden-state').exists())
            return json.loads(result.stdout)

    def test_unavailable(self):
        self.assertEqual(self.run_fake(True)['status'], 'unavailable')
        self.assertEqual(self.run_fake(package_missing=True)['status'], 'unavailable')
        self.assertEqual(self.run_fake(forbidden_write=True)['status'], 'unavailable')

    def test_fake_reads_caps_and_no_writes(self):
        report = self.run_fake()
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['generated_at'], datetime.fromtimestamp(FIXED_NOW, timezone.utc).isoformat())
        self.assertEqual(report['counts']['approve'], 1)
        self.assertEqual(report['counts']['escalate'], 1)
        self.assertEqual(report['counts']['failover'], 2)
        self.assertEqual(report['counts']['nudge'], 3)
        reasons = [x['reason'] for x in report['hosts']['sample-host']]
        self.assertIn('host_failover_cap', reasons)
        self.assertIn('host_nudge_cap', reasons)
        self.assertIn('session_daily_cap', reasons)

    def test_digest_refusals_and_isolation(self):
        self.assertEqual(self.run_fake(mismatch=True), {'status':'refused','reason':'connector_digest_mismatch'})
        self.assertEqual(self.run_fake(native=True)['status'], 'refused')
        self.assertEqual(self.run_fake(unsafe=True)['status'], 'refused')
        self.assertEqual(self.run_fake(poison=True)['status'], 'ok')
        self.assertEqual(self.run_fake(temporary_write=True)['status'], 'ok')
        self.assertEqual(self.run_fake(escaped_import=True)['status'], 'unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)/'bat_agent_connector'
            package.mkdir()
            package.joinpath('__init__.py').write_text('')
            package.joinpath('linked.py').symlink_to(package/'__init__.py')
            with self.assertRaises(sweep.Refused): sweep.connector_digest(package)

    def test_snapshot_import_survives_source_replacement(self):
        original_path = list(sys.path)
        original_finders = list(sys.meta_path)
        original_bytecode = sys.dont_write_bytecode
        previous = {k:v for k,v in sys.modules.items() if k == 'bat_agent_connector' or k.startswith('bat_agent_connector.')}
        for key in previous:
            del sys.modules[key]
        try:
            with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory(prefix='connector-snapshot-') as snapshot_dir:
                source = Path(source_dir)/'bat_agent_connector'
                source.mkdir()
                source.joinpath('__init__.py').write_text('')
                module = source/'sample.py'
                module.write_text('VALUE = "approved"\n')
                expected = sweep.connector_digest(source)
                snapshot = Path(snapshot_dir)/'bat_agent_connector'
                snapshot.mkdir(mode=0o700)
                self.assertEqual(Path(snapshot_dir).stat().st_mode & 0o777, 0o700)
                self.assertEqual(sweep.connector_digest(source, snapshot), expected)
                replacement = source/'replacement'
                replacement.write_text('VALUE = "replaced"\n')
                replacement.replace(module)
                self.assertNotEqual(sweep.connector_digest(source), expected)
                sweep.isolated_imports(snapshot)
                imported = importlib.import_module('bat_agent_connector.sample')
                self.assertEqual(imported.VALUE, 'approved')
                self.assertTrue(Path(imported.__file__).is_relative_to(snapshot))
                self.assertNotIn(str(source.parent), sys.path)
            self.assertFalse(Path(snapshot_dir).exists())
        finally:
            sys.path[:] = original_path
            sys.meta_path[:] = original_finders
            sys.dont_write_bytecode = original_bytecode
            for key in list(sys.modules):
                if key == 'bat_agent_connector' or key.startswith('bat_agent_connector.'):
                    del sys.modules[key]
            sys.modules.update(previous)

    def test_channels_symlink_refused(self):
        self.assertEqual(self.run_fake(symlink=True)['status'], 'refused')

    def test_mapping_fd_survives_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=Path(tmp)/'.config/bat-agent-connector'
            cfg.mkdir(parents=True)
            mapping=cfg/'discord-channels.toml'
            mapping.write_text('[[channels]]\nhost="sample-host"\nworkspace="original"\n')
            outside=Path(tmp)/'outside'
            outside.write_text('[[channels]]\nhost="sample-host"\nworkspace="outside"\n')
            real_open=os.open
            def replaced(path, flags, *args, **kwargs):
                fd=real_open(path, flags, *args, **kwargs)
                if path == 'discord-channels.toml':
                    mapping.unlink()
                    mapping.symlink_to(outside)
                return fd
            with mock.patch.dict(os.environ, {'HOME': tmp}), mock.patch.object(os, 'open', replaced):
                self.assertEqual(sweep.channel_mapping()[0]['workspace'], 'original')
            mapping.unlink()
            mapping.write_text('')
            mapping.chmod(0o666)
            with mock.patch.dict(os.environ, {'HOME':tmp}), self.assertRaises(sweep.Refused):
                sweep.channel_mapping()

    def test_structured_default(self):
        report = self.run_fake()
        for item in report['hosts']['sample-host']:
            self.assertEqual(set(item), {'host','session_id','action','reason'})
            self.assertRegex(item['session_id'], r'^[a-f0-9]{12}$')
        self.assertNotIn('python3 -m unittest', json.dumps(report))
        self.assertTrue(any('excerpt' in item for item in self.run_fake(include_excerpts=True)['hosts']['sample-host']))

    def test_redaction(self):
        cases = [('Authorization: Basic YWxwaGE6YnJhdm8=', 'YWxwaGE6YnJhdm8='),
                 ('Authorization: Bearer short-value', 'short-value'),
                 ('AKIA'+'A'*16, 'AKIA'), ('ASIA'+'B'*16, 'ASIA'),
                 ('-----BEGIN PRIVATE KEY-----\nexample material\n-----END PRIVATE KEY-----', 'example material'),
                 ('https://sample:credential@example.invalid/path', 'credential'),
                 ('password=short-secret', 'short-secret'),
                 ('{"api_key": "quoted secret value"}', 'quoted secret value'),
                 ("secret='another secret'", 'another secret'), ('A1b2C3d4'*5, 'A1b2C3d4')]
        for value, secret in cases:
            rendered=sweep.excerpt(value)
            self.assertNotIn(secret, rendered)
            self.assertLessEqual(len(rendered),120)
        self.assertEqual(sweep.excerpt('safe text'), 'safe text')

    def test_budgets(self):
        report=self.run_fake(oversized=True)
        self.assertEqual((report['status'],report['reason']),('partial','session_budget'))
        numeric = sweep.Budget()
        numeric.chars = sweep.MAX_DECODED_CHARS-2
        with self.assertRaises(sweep.BudgetHit): numeric.decoded([12345])
        with self.assertRaisesRegex(sweep.BudgetHit,'response_item_budget'): sweep.Budget().decoded({str(i):0 for i in range(1001)})
        b=sweep.Budget()
        for _ in range(200): b.charge_call()
        with self.assertRaisesRegex(sweep.BudgetHit,'read_call_budget'): b.charge_call()
        for value, reason in [({'messages':[{'text':'a'*2001}]},'message_char_budget'),
                              ({'messages':[{}]*21},'message_count_budget'),
                              ('x'*(2*1024*1024+1),'decoded_char_budget')]:
            with self.assertRaisesRegex(sweep.BudgetHit,reason): sweep.Budget().decoded(value)

    def test_boundary(self):
        module = type('Fake', (), {'session_send': lambda: self.fail('write called')})
        wrapped = sweep.ReadOnly(module, ('sessions_list',))
        with self.assertRaises(RuntimeError):
            wrapped.session_send()

    def test_output_cap(self):
        report = {'hosts': {'sample-host': [{'excerpt': 'x'*120} for _ in range(1000)]}, 'counts': {'nudge': 1000}, 'would_actions': [], 'needs_human': []}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sweep.emit(report)
        self.assertLessEqual(len(out.getvalue().encode()), 65536)
        parsed = json.loads(out.getvalue())
        self.assertTrue(parsed['truncated'])
        self.assertEqual(parsed['counts']['nudge'], 1000)

    def test_windows(self):
        self.assertEqual((sweep.TED_ACTIVE_S, sweep.MIN_IDLE_S, sweep.KEEPGOING_WINDOW_S, sweep.FAILOVER_WINDOW_S), (1800, 600, 259200, 7200))

if __name__ == '__main__':
    unittest.main()
