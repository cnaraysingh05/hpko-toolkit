"""Portable workflow tests. Network and privileged operations are mocked."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'linux'))
import review
import start
spec = importlib.util.spec_from_file_location('check_services', ROOT / 'tools/check_services.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ReviewTests(unittest.TestCase):
    def test_extra_root_and_shell_account_flagged(self):
        text = 'root:x:0:0::/root:/bin/bash\nevil:x:0:0::/tmp:/bin/sh\nsvc:x:100:100::/:/sbin/nologin\n'
        findings = review.account_findings(text)
        self.assertIn('Additional UID 0 account: evil', findings)
        self.assertFalse(any('svc' in finding for finding in findings))

    def test_ssh_error_is_not_clean_result(self):
        self.assertIn('unavailable', review.ssh_findings({'error': 'missing'})[0])

    def test_risky_ssh_settings_reported(self):
        findings = review.ssh_findings({'returncode': 0, 'stdout': 'permitrootlogin yes\npermitemptypasswords yes\npasswordauthentication yes\n'})
        self.assertEqual(len(findings), 3)


class LauncherTests(unittest.TestCase):
    def test_failure_propagates(self):
        with patch('start.subprocess.run', return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(RuntimeError):
                start.invoke('firewall.py', 'plan')

    def test_args_passed_without_shell(self):
        with patch('start.subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
            start.invoke('credentials.py', 'user; touch /tmp/no')
            args, kwargs = run.call_args
            self.assertEqual(args[0][-1], 'user; touch /tmp/no')
            self.assertNotIn('shell', kwargs)

    def test_baseline_collects_only_readonly_scripts(self):
        with tempfile.TemporaryDirectory() as tmp, patch('start.tempfile.mkdtemp', return_value=tmp), \
                patch('start.invoke') as invoke, contextlib.redirect_stdout(io.StringIO()):
            start.baseline()
            self.assertEqual([call.args[0] for call in invoke.call_args_list], ['recon.py', 'persistence.py', 'review.py'])
            self.assertEqual(os.stat(tmp).st_mode & 0o777, 0o700)

    def test_menu_apply_cancel_never_applies(self):
        old = os.umask(0o077)
        try:
            with patch('start.require_linux'), patch('start.os.geteuid', return_value=0), \
                    patch('start.sys.stdin.isatty', return_value=True), \
                    patch('builtins.input', side_effect=['5', 'config/this-host.json', 'NO', '0']), \
                    patch('start.invoke') as invoke, contextlib.redirect_stdout(io.StringIO()):
                start.main()
                self.assertEqual(invoke.call_count, 1)
                self.assertEqual(invoke.call_args.args[:2], ('firewall.py', 'plan'))
        finally:
            os.umask(old)

    def test_bootstrap_check_never_installs(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            # Simulate Linux and missing Python without contacting any package manager.
            for name, content in {'uname': '#!/bin/sh\necho Linux\n', 'python3': '#!/bin/sh\nexit 1\n',
                                  'apt-get': '#!/bin/sh\necho UNEXPECTED_INSTALL\nexit 99\n'}.items():
                p = directory / name
                p.write_text(content)
                p.chmod(0o700)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ['PATH'])
            result = subprocess.run(['bash', str(ROOT/'linux/start.sh'), '--check'], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('No packages were changed', result.stderr)
            self.assertNotIn('UNEXPECTED_INSTALL', result.stdout)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tcp = {'name': 'ssh', 'type': 'tcp', 'host': '192.0.2.20', 'port': 22}
        self.http = {'name': 'web', 'type': 'http', 'url': 'https://example.com/', 'status': 200}

    def test_example_valid(self):
        checker.validate(json.loads((ROOT/'config/checks.example.json').read_text()))

    def test_bad_targets_rejected(self):
        for host in ['bad;command', 'a/b', '', '10.0.0.0/24', 'fe80::1%eth0']:
            with self.subTest(host=host), self.assertRaises(ValueError):
                checker.validate([dict(self.tcp, host=host)])
        for port in [True, 0, 65536, '22']:
            with self.subTest(port=port), self.assertRaises(ValueError):
                checker.validate([dict(self.tcp, port=port)])

    def test_url_credentials_and_non_http_rejected(self):
        for url in ['file:///etc/passwd', 'https://user:secret@example.com/', 'https://example.com:0/', 'http://example.com/\r\nInjected:1']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                checker.validate([dict(self.http, url=url)])

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):
            checker.validate([self.tcp, self.tcp])

    def test_plan_never_contacts_targets(self):
        with patch.object(sys, 'argv', ['check_services.py', '--config', str(ROOT/'config/checks.example.json')]), \
                patch.object(checker, 'check') as check, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(checker.main(), 0)
            check.assert_not_called()

    def test_tcp_success_and_failure(self):
        with patch.object(checker.socket, 'create_connection', return_value=MagicMock()):
            self.assertTrue(checker.check(self.tcp, 5)['passed'])
        with patch.object(checker.socket, 'create_connection', side_effect=TimeoutError('timed out')):
            self.assertFalse(checker.check(self.tcp, 5)['passed'])

    def test_https_keeps_tls_validation_and_no_redirect(self):
        connection = MagicMock()
        connection.getresponse.return_value.status = 302
        with patch.object(checker.http.client, 'HTTPSConnection', return_value=connection) as create, \
                patch.object(checker.ssl, 'create_default_context') as context:
            result = checker.check(self.http, 5)
            self.assertFalse(result['passed'])
            context.assert_called_once_with()
            self.assertIn('context', create.call_args.kwargs)
            connection.request.assert_called_once()
            connection.close.assert_called_once()

    def test_failed_check_sets_nonzero_exit(self):
        with patch.object(sys, 'argv', ['check_services.py', '--config', str(ROOT/'config/checks.example.json'), '--run']), \
                patch.object(checker, 'check', return_value={'passed': False}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(checker.main(), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
