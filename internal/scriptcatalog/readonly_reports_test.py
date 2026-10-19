"""Offline integration tests: every external command is a PATH shim."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
SHIM = '''#!/usr/bin/python3
import json, os, sys, time
from pathlib import Path
home = Path(os.environ['HOME'])
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with (home/'calls').open('a') as stream:
    stream.write(json.dumps([name, args, sorted(os.environ)])+'\\n')
cfg = json.loads((home/'fake.json').read_text())
case = cfg.get(name, {})
if name == 'oci':
    if 'availability-domain' in args:
        case = cfg.get('iam', {'out': 'ocid1.'+'tenancy.example'})
    elif 'usage-summary' in args:
        case = cfg.get('usage', {})
        if '--page' in args:
            case = cfg.get('usage_page', case)
    elif 'compartment' in args:
        case = cfg.get('compartments', {'json': []})
    else:
        case = cfg.get('instances', {'json': 2})
time.sleep(case.get('sleep', 0))
if 'json' in case:
    print(json.dumps(case['json']))
else:
    print(case.get('out', ''))
print(case.get('err', ''), file=sys.stderr)
sys.exit(case.get('code', 0))
'''


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(ports):
    return hashlib.sha256(''.join(str(p)+'\n' for p in sorted(set(ports))).encode()).hexdigest()


class Reports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.bin = self.home/'bin'
        self.bin.mkdir()
        self.cfg = {
            'usage': {'json': {'data': {'items': [{'computed-amount': '0', 'currency': 'USD'}]}}},
            'tailscale': {'json': {'BackendState': 'Running', 'Peer': {
                'opaque': {'HostName': 'peer-a', 'Online': True, 'Active': True,
                           'Relay': 'relay-region', 'CurAddr': 'direct-address'}}}},
            'ip': {'json': [{'dst': 'default'}]},
            'getent': {'out': 'address resolved-name'},
            'systemctl': {'out': 'active'},
            'ss': {'out': 'LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\nLISTEN 0 128 127.0.0.1:9999 0.0.0.0:*'},
            # A poisonous gh output verifies the script never loads gh auth or uses it.
            'gh': {'out': 'forbidden-authenticated-client', 'code': 99},
        }
        for name in ('oci', 'tailscale', 'ip', 'getent', 'systemctl', 'ss', 'curl', 'gh'):
            path = self.bin/name
            path.write_text(SHIM)
            path.chmod(0o700)
        (self.home/'.oci').mkdir()
        (self.home/'.oci/config').write_text('[sample-oci-a]\nkey_file=NEVER-OPEN\n[sample-oci-b]\n')
        self.env = {**os.environ, 'HOME': str(self.home), 'PATH': str(self.bin),
                    'GH_TOKEN': 'test-secret', 'GITHUB_TOKEN': 'test-secret',
                    'PYTHONPATH': str(self.home)}
        (self.home/'sitecustomize.py').write_text("raise RuntimeError('ambient import')")

    def invoke(self, name, args, root=False):
        (self.home/'fake.json').write_text(json.dumps(self.cfg))
        # Simulate uid explicitly so CI also exercises script guards on root runners.
        harness = 'import os,runpy,sys; os.geteuid=lambda: '+('0' if root else '1000')+'; runpy.run_path(sys.argv[1],run_name="__main__")'
        p = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', '-c', harness,
                            str(ROOT/(name+'.py'))], input=args if isinstance(args, str) else json.dumps(args),
                           text=True, capture_output=True, timeout=15, env=self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, '')
        self.assertEqual(len(p.stdout.splitlines()), 1)
        self.assertLessEqual(len(p.stdout.encode()), 64 << 10)
        self.assertNotIn('test-secret', p.stdout)
        self.assertNotIn('ocid1.', p.stdout)
        self.assertNotIn('forbidden-authenticated-client', p.stdout)
        result = json.loads(p.stdout)
        self.assertEqual(result['schema_version'], 1)
        self.assertIn(result['status'], ('ok', 'warn', 'urgent', 'error'))
        self.assertEqual(set(result), {'schema_version', 'status', 'summary', 'metrics', 'findings'})
        return result

    def calls(self):
        path = self.home/'calls'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def reasons(self, result):
        return [f['reason'] for f in result['findings']]

    def release(self, installed='v3.9.0', latest='v3.10.0'):
        install = self.home/'installed'
        install.mkdir(exist_ok=True)
        (install/'VERSION').write_text(installed+'\n')
        self.cfg['systemctl'] = {'out': 'BAT_INSTALL_DIR='+str(install)+' IGNORED=test-secret'}
        self.cfg['curl'] = {'out': json.dumps({'tag_name': latest, 'draft': False,
                'prerelease': False, 'published_at': '2026-10-18T00:00:00Z'})+'\n200'}
        return install

    def test_root_invalid_json_unknown_and_oversize_args(self):
        for name, args in [('oci-cost-report-v1', {'profile': 'sample-oci-a'}), ('network-watch-v1', {}), ('bat-release-check-v1', {})]:
            self.assertEqual(self.reasons(self.invoke(name, args, root=True)), ['root_execution_forbidden'])
            for bad in ('{', '[]', ' '*4097, '{"command":"sudo"}'):
                self.assertEqual(self.invoke(name, bad)['status'], 'error')
        self.assertEqual(self.calls(), [])

    def test_oci_cost_thresholds_and_decimal_sum(self):
        for amounts, status in [(['0'], 'ok'), (['0.01'], 'warn'), (['5'], 'warn'), (['4.99', '0.02'], 'urgent'), (['0.1', '0.2'], 'warn')]:
            self.cfg['usage']['json']['data']['items'] = [{'computed-amount': a, 'currency': 'USD'} for a in amounts]
            result = self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})
            self.assertEqual(result['status'], status)
            self.assertAlmostEqual(result['metrics']['mtd_usd'], sum(map(float, amounts)))
            self.assertEqual(result['metrics']['running_instances'], 2)
        result = self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a', 'warn_usd': 0.3, 'urgent_usd': 0.3})
        self.assertEqual(result['status'], 'ok')
        for _, args, env in self.calls():
            self.assertNotIn('GH_TOKEN', env)
            if 'usage-summary' in args:
                self.assertEqual(args[args.index('--granularity')+1], 'MONTHLY')
                self.assertEqual(args[args.index('--query-type')+1], 'COST')

    def test_oci_period_at_month_year_and_leap_boundaries(self):
        module = load('oci-cost-report-v1')
        for now, start, end in [('2026-12-31T12:30:00+00:00', '2026-12-01T00:00:00Z', '2027-01-01T00:00:00Z'),
                                ('2028-02-29T23:59:59+00:00', '2028-02-01T00:00:00Z', '2028-03-01T00:00:00Z')]:
            with mock.patch.dict(os.environ, self.env), mock.patch.object(module, 'oci_call', side_effect=['ocid1.'+'tenancy.example', json.dumps(self.cfg['usage']['json']), '[]', '1']):
                result = module.check({'profile': 'sample-oci-a'}, dt.datetime.fromisoformat(now))
            self.assertEqual(result['metrics']['period_start'], start)
            self.assertEqual(result['metrics']['period_end'], end)

    def test_oci_cli_lookup_missing_profile_and_threshold_errors(self):
        (self.bin/'oci').rename(self.bin/'hidden-oci')
        self.assertEqual(self.reasons(self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})), ['oci_cli_missing'])
        local = self.home/'.local/bin'
        local.mkdir(parents=True)
        (self.bin/'hidden-oci').rename(local/'oci')
        self.assertEqual(self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})['status'], 'ok')
        self.assertEqual(self.reasons(self.invoke('oci-cost-report-v1', {'profile': 'absent'})), ['profile_missing'])
        for args in [{'profile': '../bad'}, {'profile': 'sample-oci-a', 'warn_usd': -1}, {'profile': 'sample-oci-a', 'urgent_usd': True}, {'profile': 'sample-oci-a', 'warn_usd': 6}]:
            self.assertEqual(self.invoke('oci-cost-report-v1', args)['status'], 'error')

    def test_oci_auth_and_permission_failures_are_typed(self):
        for error, reason in [('NotAuthenticated', 'oci_auth_failed'), ('NotAuthorizedOrNotFound', 'oci_permission_denied'), ('TooManyRequests', 'oci_rate_limited'), ('opaque', 'oci_request_failed')]:
            self.cfg['iam'] = {'code': 1, 'err': error+' token=test-secret'}
            self.assertEqual(self.reasons(self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-b'})), [reason])

    def test_oci_pagination_and_child_compartments(self):
        self.cfg['usage']['json']['opc-next-page'] = 'page-two'
        self.cfg['usage_page'] = {'json': {'data': {'items': [{'computed-amount': '1.25', 'currency': 'USD'}]}}}
        self.cfg['compartments'] = {'json': ['ocid1.'+'compartment.example']}
        result = self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})
        self.assertEqual(result['metrics']['mtd_usd'], 1.25)
        self.assertEqual(result['metrics']['running_instances'], 4)
        self.assertTrue(any('--page' in args for _, args, _ in self.calls()))
        self.cfg['usage_page']['json']['opc-next-page'] = 'page-two'
        self.assertIn('oci_usage_pagination_invalid', self.reasons(self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})))

    def test_oci_no_silent_undercount_or_currency_conversion(self):
        for row in [{'computed-amount': 'NaN', 'currency': 'USD'}, {'computed-amount': None, 'currency': 'USD'}, {'computed-amount': '1', 'currency': 'EUR'}]:
            self.cfg['usage']['json']['data']['items'] = [row]
            self.assertEqual(self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})['status'], 'error')
        self.cfg['usage']['json']['data']['items'] = []
        self.cfg['compartments'] = {'json': ['ocid1.'+'compartment.example']*33}
        self.assertEqual(self.reasons(self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})), ['oci_compartment_scope_limit'])
        self.cfg['compartments'] = {'json': []}
        self.cfg['instances'] = {'code': 1, 'err': 'NotAuthorizedOrNotFound token=test-secret'}
        self.assertEqual(self.reasons(self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})), ['oci_permission_denied'])

    def test_oci_cli_empty_list_rendering(self):
        self.cfg['compartments'] = {'out': ''}
        self.cfg['instances'] = {'out': ''}
        result = self.invoke('oci-cost-report-v1', {'profile': 'sample-oci-a'})
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['metrics']['running_instances'], 0)

    def test_network_healthy_digest_and_no_identity(self):
        result = self.invoke('network-watch-v1', {'expected_peers': ['peer-a']})
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['metrics']['listen_digest'], digest([22,443]))
        self.assertEqual(result['metrics']['listen_count'], 2)
        self.assertEqual(result['metrics']['online_peer_count'], 1)
        self.assertFalse(result['metrics']['listen_baseline_available'])
        self.assertIsNone(result['metrics']['listen_ports_changed'])
        self.assertNotIn('address', json.dumps(result))
        self.assertEqual([args for name, args, _ in self.calls() if name == 'getent'], [['hosts','github.com'], ['hosts','cloudflare.com']])

    def test_network_offline_missing_peer_derp_and_health(self):
        peers = self.cfg['tailscale']['json']['Peer']
        peers['opaque']['CurAddr'] = ''
        peers['offline'] = {'HostName': 'peer-b', 'Online': False}
        self.cfg['tailscale']['json']['Health'] = ['test-secret']
        result = self.invoke('network-watch-v1', {'expected_peers': ['peer-b', 'peer-missing']})
        self.assertEqual(result['status'], 'warn')
        self.assertEqual(result['metrics']['expected_offline_count'], 2)
        self.assertEqual(result['metrics']['derp_only_count'], 1)
        self.assertIn('tailscale_health_warning', self.reasons(result))
        peers['opaque']['Active'] = False
        result = self.invoke('network-watch-v1', {})
        self.assertEqual(result['metrics']['derp_only_count'], 0)

    def test_network_listen_comparison_and_actual_diff(self):
        args = {'baseline_listen_digest': digest([22,80]), 'baseline_listen_ports': ['80','22']}
        result = self.invoke('network-watch-v1', args)
        self.assertEqual(result['metrics']['added_ports'], [443])
        self.assertTrue(result['metrics']['listen_baseline_available'])
        self.assertTrue(result['metrics']['listen_ports_changed'])
        self.assertEqual(result['metrics']['removed_ports'], [80])
        del args['baseline_listen_ports']
        self.assertIn('listen_diff_unavailable', self.reasons(self.invoke('network-watch-v1', args)))
        args['baseline_listen_ports'] = ['23']
        self.assertEqual(self.reasons(self.invoke('network-watch-v1', args)), ['baseline_digest_mismatch'])
        self.assertEqual(self.invoke('network-watch-v1', {'baseline_listen_digest': digest([22,443])})['status'], 'ok')

    def test_network_route_dns_service_and_daily_coverage(self):
        self.cfg['ip'] = {'json': []}
        self.cfg['getent'] = {'code': 2}
        self.cfg['systemctl'] = {'code': 3, 'out': 'inactive'}
        result = self.invoke('network-watch-v1', {'mode': 'daily', 'resolve': ['example.invalid']})
        for reason in ('default_route_missing', 'dns_resolution_failed', 'cloudflared_inactive', 'security_coverage_incomplete'):
            self.assertIn(reason, self.reasons(result))
        self.assertEqual(result['metrics']['dns_failure_count'], 1)
        self.assertEqual(len(result['metrics']['coverage_gaps']), 4)

    def test_network_missing_malformed_and_bounded_inputs(self):
        (self.bin/'tailscale').unlink()
        self.assertIn('tailscale_cli_missing', self.reasons(self.invoke('network-watch-v1', {})))
        for args in [{'expected_peers':['peer']*33}, {'resolve':['a']*9}, {'resolve':['-option']}, {'mode':'shell'}, {'baseline_listen_digest':'bad'}, {'baseline_listen_ports':['65536']}]:
            self.assertEqual(self.invoke('network-watch-v1', args)['status'], 'error')
        self.cfg['ss'] = {'out': 'malformed token=test-secret'}
        self.assertIn('invalid_listen_response', self.reasons(self.invoke('network-watch-v1', {})))

    def test_network_missing_configuration_is_error(self):
        self.cfg['tailscale']['json']['BackendState'] = 'NeedsLogin'
        result = self.invoke('network-watch-v1', {})
        self.assertEqual(result['status'], 'error')
        self.assertIn('tailscale_config_missing', self.reasons(result))
        self.cfg['tailscale']['json']['BackendState'] = 'Running'
        self.cfg['systemctl'] = {'code': 4, 'out': 'unknown'}
        result = self.invoke('network-watch-v1', {})
        self.assertEqual(result['status'], 'error')
        self.assertIn('cloudflared_service_missing', self.reasons(result))
        self.cfg['systemctl'] = {'code': 1}
        self.assertIn('cloudflared_status_failed', self.reasons(self.invoke('network-watch-v1', {})))
        self.cfg['tailscale'] = {'json': {}}
        self.assertIn('invalid_tailscale_response', self.reasons(self.invoke('network-watch-v1', {})))

    def test_bat_semver_current_newer_and_installed_ahead(self):
        for installed, latest, expected in [('v3.9.0','v3.10.0',True), ('3.10.0','v3.10.0',False), ('v4.0.0','v3.10.0',False)]:
            self.release(installed, latest)
            result = self.invoke('bat-release-check-v1', {})
            self.assertEqual(result['metrics']['newer_available'], expected)
            self.assertEqual(result['status'], 'warn' if expected else 'ok')
        self.assertFalse(any(name == 'gh' for name, _, _ in self.calls()))
        for name, args, env in self.calls():
            if name == 'curl':
                self.assertEqual(args[0], '-q')
                self.assertNotIn('--output', args)
                self.assertNotIn('GH_TOKEN', env)
                self.assertNotIn('GITHUB_TOKEN', env)

    def test_bat_symlink_source_matches_updater(self):
        install = self.release()
        (install/'VERSION').unlink()
        install.rmdir()
        target = self.home/'bat-server-v3.8.0'
        target.mkdir()
        install.symlink_to(target)
        result = self.invoke('bat-release-check-v1', {})
        self.assertEqual(result['metrics']['installed_version'], 'v3.8.0')

    def test_bat_api_limits_errors_and_missing_install(self):
        install = self.release()
        for status in ('403','429'):
            self.cfg['curl'] = {'out': '{"message":"test-secret"}\n'+status}
            result = self.invoke('bat-release-check-v1', {})
            self.assertEqual(result['status'], 'warn')
            self.assertEqual(result['metrics']['latest_stable'], None)
        for response in ('{}\n500', 'not-json\n200', '{"tag_name":"v3.11.0-rc1","draft":false,"prerelease":false}\n200'):
            self.cfg['curl'] = {'out': response}
            self.assertEqual(self.invoke('bat-release-check-v1', {})['status'], 'error')
        (install/'VERSION').unlink()
        self.assertEqual(self.reasons(self.invoke('bat-release-check-v1', {})), ['installed_version_missing'])

    def test_bat_prerelease_draft_and_missing_curl(self):
        self.release()
        for field in ('draft','prerelease'):
            value = json.loads(self.cfg['curl']['out'].rsplit('\n',1)[0])
            value[field] = True
            self.cfg['curl']['out'] = json.dumps(value)+'\n200'
            self.assertEqual(self.reasons(self.invoke('bat-release-check-v1', {})), ['stable_release_unavailable'])
        (self.bin/'curl').unlink()
        self.assertEqual(self.reasons(self.invoke('bat-release-check-v1', {})), ['curl_cli_missing'])

    def test_command_timeout_output_limit_and_no_writes(self):
        module = load('network-watch-v1')
        (self.home/'fake.json').write_text(json.dumps({'ss': {'sleep': 2}}))
        with mock.patch.dict(os.environ, self.env), self.assertRaisesRegex(module.Failure, 'cli_timeout'):
            module.run([str(self.bin/'ss')], timeout=0.1)
        self.cfg['ss'] = {'out': 'x'*(4*1024*1024+1)}
        self.assertIn('cli_output_limit', self.reasons(self.invoke('network-watch-v1', {})))
        self.assertFalse((self.home/'.cache').exists())
        self.assertFalse((self.home/'Downloads').exists())
        self.assertFalse((self.home/'.config').exists())


if __name__ == '__main__':
    unittest.main()
