"""Run with python3 -m unittest discover -s internal/scriptcatalog -p '*_test.py'."""
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import time
import unittest
from datetime import datetime, timezone

SCRIPT = Path(__file__).with_name('bat-sweep-report-v1.py').resolve()
spec = importlib.util.spec_from_file_location('sweep', SCRIPT)
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)

class SweepTests(unittest.TestCase):
    def test_classification(self):
        now = time.time()
        def messages(text):
            return [{'role': 'assistant', 'text': text}]
        for text, expected in [('Please provide the password?', 'needs_human'), ('Phase 2 complete', 'milestone'), ('[BAT-STATUS: NEED_HUMAN] review', 'needs_human'), ('[BAT-STATUS: CONTINUE] next step', 'nudge'), ('Unclear next step', 'needs_human')]:
            self.assertEqual(sweep.classify(messages(text), now)[0], expected)
        self.assertEqual(sweep.classify(messages('continue') + [{'role': 'user', 'text': 'hello', 'ts': datetime.now(timezone.utc).isoformat()}], now), ('skip', 'Ted active'))
        for command in ['git push origin example', 'rm -rf /', 'sudo test', 'terraform apply', 'gh pr merge 1']:
            self.assertTrue(sweep.DESTRUCTIVE_CMD.search(command))
        self.assertFalse(sweep.DESTRUCTIVE_CMD.search('python3 -m unittest'))
        self.assertLessEqual(len(sweep.excerpt('sk-' + 'a'*60)), 120)
        self.assertNotIn('a'*32, sweep.excerpt('sk-' + 'a'*60))

    def run_fake(self, missing=False, forbidden_write=False, package_missing=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / '.config/bat-agent-connector'
            cfg.mkdir(parents=True)
            cfg.joinpath('discord-channels.toml').write_text(''.join(f'[[channels]]\nhost="sample-host"\nworkspace="w{i}"\n' for i in range(10)))
            package = root / 'bat_agent_connector'
            package.mkdir()
            package.joinpath('__init__.py').write_text('raise ModuleNotFoundError()\n' if package_missing else '')
            package.joinpath('config.py').write_text('def load_config():\n    ' + ('raise FileNotFoundError()' if missing else "from pathlib import Path; (Path.home() / 'forbidden-state').write_text('attempt'); return object()" if forbidden_write else 'return object()') + '\n')
            package.joinpath('fleet.py').write_text('class Fleet:\n    def __init__(self, *a, **k): pass\n    async def close(self): pass\n')
            package.joinpath('registry.py').write_text('def list_entries(host): return []\n')
            package.joinpath('triage.py').write_text('QUOTA_PATTERNS=[]\nasync def sessions_triage(*a, **k):\n    ids = range(3) if k.get("agent") else range(2)\n    return {"sessions": [{"session_id": str(i), "workspace": "w"+str(i)} for i in ids]}\n')
            package.joinpath('service.py').write_text(textwrap.dedent('''
                from datetime import datetime, timezone, timedelta
                def stamp(): return (datetime.now(timezone.utc)-timedelta(minutes=40)).isoformat()
                async def sessions_list(*a, **k):
                    return {"sessions": [{"session_id": str(i), "workspace": "w"+str(i), "agent_kind": "codex", "loaded": True, "last_activity": stamp()} for i in range(10)]}
                async def session_read(fleet, host, sid, **k):
                    msgs = [{"role": "assistant", "text": "[BAT-STATUS: CONTINUE] next", "ts": stamp()}]
                    if sid == '9' and k.get('last_n') == 500:
                        msgs = [{"role": "user", "text": "[BAT hourly sweep]", "ts": stamp()} for _ in range(6)] + msgs
                    return {"pending": {"kind": "permission", "toolUseId": "example", "input_preview": "git push" if sid == '0' else "python3 -m unittest"}, "messages": msgs}
                def forbidden(*a, **k):
                    raise AssertionError('WRITE CALLED')
                session_answer = session_send = forbidden
            '''))
            for name in ['lifecycle', 'jev']:
                package.joinpath(name+'.py').write_text("raise AssertionError('FORBIDDEN MODULE IMPORT')\n")
            result = subprocess.run(['/usr/bin/python3', '-B', str(SCRIPT)], input=json.dumps({'hosts': ['sample-host']}), text=True, capture_output=True, env={**os.environ, 'HOME': tmp, 'PYTHONPATH': tmp})
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
        self.assertEqual(report['counts']['approve'], 1)
        self.assertEqual(report['counts']['escalate'], 1)
        self.assertEqual(report['counts']['failover'], 2)
        self.assertEqual(report['counts']['nudge'], 3)
        reasons = [x['reason'] for x in report['hosts']['sample-host']]
        self.assertIn('host failover cap', reasons)
        self.assertIn('host nudge cap', reasons)
        self.assertIn('session daily cap', reasons)

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
