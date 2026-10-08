"""Portable unit tests: no real passwords, firewall, or elevated execution."""
import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'linux'))
import firewall
import credentials
import common


def config():
    return json.loads((ROOT / 'config/linux-web.example.json').read_text())


class ValidationTests(unittest.TestCase):
    def test_ipv4_ipv6_render(self):
        text = firewall.render(config())
        self.assertIn('ip saddr 192.0.2.10/32 tcp dport { 22 }', text)
        self.assertIn('ip6 saddr ::/0 tcp dport { 80, 443 }', text)
        self.assertIn('ct state established,related accept', text)
        self.assertIn('ipv6-icmp', text)
        self.assertNotIn('flush', text)
        self.assertNotIn('hook output', text)
        self.assertNotIn('hook forward', text)

    def test_invalid_ports(self):
        for value in [[], [0], [65536], [True], ['22'], [22.5], '22']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                firewall.ports(value)

    def test_invalid_sources(self):
        for value in [[], ['any'], ['192.0.2.1/24'], ['1.2.3.4; drop'], [1], ['fe80::1%eth0']]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                firewall.sources(value)

    def test_unrestricted_management_rejected(self):
        for address in ['0.0.0.0/0', '::/0']:
            c = config()
            c['management']['sources'] = [address]
            with self.assertRaises(ValueError):
                firewall.render(c)

    def test_malformed_schema_rejected(self):
        for c in [None, [], {}, {'management': None, 'services': []}]:
            with self.subTest(config=c), self.assertRaises(ValueError):
                firewall.render(c)

    def test_typo_and_injection_rejected(self):
        for key, value in [('name', 'web"; drop'), ('protocol', 'sctp'), ('ports', ['80-90'])]:
            c = config()
            c['services'][0][key] = value
            with self.assertRaises(ValueError):
                firewall.render(c)
        c = config()
        c['servcies'] = c.pop('services')
        with self.assertRaises(ValueError):
            firewall.render(c)

    def test_dns_needs_both_protocols(self):
        c = config()
        c['services'] = [{'name':'dns', 'protocol':p, 'ports':[53], 'sources':['192.0.2.0/24']} for p in ('tcp','udp')]
        rendered = firewall.render(c)
        self.assertIn('tcp dport { 53 }', rendered)
        self.assertIn('udp dport { 53 }', rendered)

    def test_local_account_exact_match(self):
        rows = 'alice:x:1000:1000::/home/alice:/bin/bash\n'
        self.assertEqual(credentials.local_account('alice', rows)[0], 'alice')
        for name in ['ali', 'root', '-alice', 'alice\n', 'a/b']:
            with self.assertRaises(ValueError):
                credentials.local_account(name, rows)
        with self.assertRaises(ValueError):
            credentials.local_account('alice', rows + rows)

    def test_missing_collector_visible(self):
        with patch('common.subprocess.run', side_effect=FileNotFoundError('missing')):
            self.assertIn('error', common.collect(['missing-tool']))

    def test_plan_never_executes_or_writes(self):
        with patch.object(sys, 'argv', ['firewall.py', 'plan', '--config', str(ROOT/'config/linux-web.example.json')]), \
             patch('firewall.subprocess.run') as run, patch('firewall.secure_state') as state, \
             contextlib.redirect_stdout(io.StringIO()):
            firewall.main()
            run.assert_not_called()
            state.assert_not_called()


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        self.calls = []
        self.table_exists = False
        self.fail_apply = False
        self.manager_active = False
        self.old_umask = os.umask(0o077)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch('firewall.STATE', self.state))
        self.stack.enter_context(patch('firewall.require_linux'))
        self.stack.enter_context(patch('firewall.os.geteuid', return_value=0))
        self.stack.enter_context(patch('firewall.secure_state'))
        self.stack.enter_context(patch('firewall.subprocess.run', side_effect=self.fake_run))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def tearDown(self):
        self.stack.close()
        os.umask(self.old_umask)
        self.temp.cleanup()

    def fake_run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == 'systemctl':
            return subprocess.CompletedProcess(argv, 0 if self.manager_active else 3, '', '')
        output = ''
        if argv == ['nft', '-j', 'list', 'tables']:
            output = json.dumps({'nftables': [{'table': {'name': firewall.TABLE, 'family': 'inet'}}] if self.table_exists else []})
        if argv == ['nft', 'list', 'ruleset']:
            output = 'table inet original { }\n'
        if argv == ['nft', '--file', '-']:
            self.assertTrue((self.state/'active.json').exists(), 'journal must precede mutation')
            self.assertTrue((self.state/'before.nft').exists(), 'backup must precede mutation')
            if self.fail_apply:
                raise subprocess.CalledProcessError(1, argv, stderr='simulated rejection')
            self.table_exists = True
        if argv == ['nft', 'delete', 'table', 'inet', firewall.TABLE]:
            self.table_exists = False
        return subprocess.CompletedProcess(argv, 0, output, '')

    def invoke(self, action, console=True):
        args = ['firewall.py', action]
        if action != 'rollback':
            args.extend(['--config', str(ROOT/'config/linux-web.example.json')])
            if console:
                args.append('--console-confirmed')
        with patch.object(sys, 'argv', args):
            firewall.main()

    def test_apply_then_scoped_rollback(self):
        self.invoke('apply')
        self.assertTrue(self.table_exists)
        self.assertEqual((self.state/'before.nft').read_text(), 'table inet original { }\n')
        self.invoke('rollback')
        self.assertFalse(self.table_exists)
        self.assertFalse((self.state/'active.json').exists())
        self.assertTrue((self.state/'before.nft').exists())
        mutations = [a for a, _ in self.calls if a[:2] == ['nft','delete']]
        self.assertEqual(mutations, [['nft','delete','table','inet',firewall.TABLE]])

    def test_repeat_apply_refused(self):
        self.invoke('apply')
        with self.assertRaises(RuntimeError):
            self.invoke('apply')

    def test_atomic_failure_removes_journal(self):
        self.fail_apply = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('apply')
        self.assertFalse((self.state/'active.json').exists())
        self.assertFalse(self.table_exists)

    def test_existing_unowned_table_refused(self):
        self.table_exists = True
        with self.assertRaises(RuntimeError):
            self.invoke('apply')
        self.assertFalse((self.state/'active.json').exists())

    def test_active_manager_refused(self):
        self.manager_active = True
        with self.assertRaises(RuntimeError):
            self.invoke('apply')
        self.assertFalse((self.state/'active.json').exists())

    def test_console_required(self):
        with self.assertRaises(ValueError):
            self.invoke('apply', console=False)
        self.assertFalse(self.calls)

    def test_rollback_requires_journal(self):
        with self.assertRaises(RuntimeError):
            self.invoke('rollback')
        self.assertFalse(self.calls)

    def test_reboot_missing_table_rollback(self):
        self.invoke('apply')
        self.table_exists = False
        self.invoke('rollback')
        self.assertFalse((self.state/'active.json').exists())


class CredentialTests(unittest.TestCase):
    def invoke(self, args, confirmation='alice'):
        stack = contextlib.ExitStack()
        with stack:
            stack.enter_context(patch.object(sys, 'argv', ['credentials.py', 'alice'] + args))
            stack.enter_context(patch('credentials.require_linux'))
            stack.enter_context(patch('credentials.Path.read_text', return_value='alice:x:1000:1000::/home/alice:/bin/bash\n'))
            stack.enter_context(patch('credentials.os.geteuid', return_value=0))
            stack.enter_context(patch('credentials.os.isatty', return_value=True))
            stack.enter_context(patch('builtins.input', return_value=confirmation))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            credentials.main()

    def test_preview_never_invokes_passwd(self):
        with patch('credentials.subprocess.run') as run:
            self.invoke([])
            run.assert_not_called()

    def test_only_named_account_passed_to_native_prompt(self):
        with patch('credentials.subprocess.run') as run:
            self.invoke(['--apply', '--ack-service-impact'])
            run.assert_called_once_with(['passwd', 'alice'], check=True)

    def test_impact_ack_required(self):
        with patch('credentials.subprocess.run') as run:
            with self.assertRaises(ValueError):
                self.invoke(['--apply'])
            run.assert_not_called()

    def test_wrong_confirmation_cannot_mutate(self):
        with patch('credentials.subprocess.run') as run:
            with self.assertRaises(ValueError):
                self.invoke(['--apply', '--ack-service-impact'], confirmation='bob')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
