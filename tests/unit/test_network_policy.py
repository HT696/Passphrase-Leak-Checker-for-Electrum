import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from passphrase_leak_checker.electrum.network_policy import get_network_proxy
from passphrase_leak_checker.client import LeakCheckError, PwnedClient, SocksProxy
from tests.support import ENDPOINT, policy


class PolicyTests(unittest.TestCase):
    def test_direct_allowed(self):
        self.assertIsNone(get_network_proxy(*policy()))

    def test_offline_unknown_and_transition_refused(self):
        for args in (policy(offline=True), policy(configured_proxy=True),
                     policy(active_proxy=True), policy(configured_proxy='false'),
                     policy(active_proxy=None), (policy()[0], None), (object(), object())):
            with self.subTest(args=args), self.assertRaises(LeakCheckError):
                get_network_proxy(*args)

    def test_worker_rechecks_policy_before_dns_or_connect(self):
        config, network = policy()
        client = PwnedClient(ENDPOINT, network_guard=lambda: get_network_proxy(config, network))
        # Change the route after consent and before the worker connects.
        config.NETWORK_PROXY_ENABLED = True
        with patch('socket.getaddrinfo') as dns, patch('socket.socket.connect') as connect:
            with self.assertRaises(LeakCheckError):
                client.check_secret('password')
            dns.assert_not_called()
            connect.assert_not_called()

    def test_every_offline_and_proxy_combination(self):
        for offline in (False, True):
            for configured in (False, True):
                for active in (False, True):
                    with self.subTest(offline=offline, configured=configured, active=active):
                        config, network = proxied_policy()
                        config.NETWORK_OFFLINE = offline
                        config.NETWORK_PROXY_ENABLED = configured
                        network.get_parameters().proxy.enabled = active
                        if offline or configured != active:
                            with self.assertRaises(LeakCheckError):
                                get_network_proxy(config, network)
                        elif configured:
                            self.assertEqual(get_network_proxy(config, network),
                                             SocksProxy('127.0.0.1', 9050, 'socks5'))
                        else:
                            self.assertIsNone(get_network_proxy(config, network))

    def test_falsey_non_boolean_settings_fail_closed(self):
        for value in (0, 1, '', 'false', 'true', None, [], {}):
            for field in ('NETWORK_OFFLINE', 'NETWORK_PROXY_ENABLED', 'active'):
                with self.subTest(field=field, value=value):
                    config, network = policy()
                    if field == 'active':
                        network.get_parameters = lambda: SimpleNamespace(proxy=SimpleNamespace(enabled=value))
                    else:
                        setattr(config, field, value)
                    with self.assertRaises(LeakCheckError):
                        get_network_proxy(config, network)

    def test_missing_proxy_interfaces_fail_closed(self):
        for parameters in (None, object(), SimpleNamespace(proxy=None),
                           SimpleNamespace(proxy=object())):
            with self.subTest(parameters=parameters), self.assertRaises(LeakCheckError):
                get_network_proxy(policy()[0], SimpleNamespace(get_parameters=lambda: parameters))

    def test_host_accessor_exceptions_are_handled(self):
        network = Mock()
        network.get_parameters.side_effect = RuntimeError('public sentinel detail')
        with self.assertRaises(LeakCheckError) as raised:
            get_network_proxy(policy()[0], network)
        self.assertNotIn('public sentinel detail', str(raised.exception))

    def test_offline_policy_does_not_need_to_query_proxy_state(self):
        network = Mock()
        with self.assertRaises(LeakCheckError):
            get_network_proxy(policy(offline=True)[0], network)
        network.get_parameters.assert_not_called()


def proxied_policy(mode='socks5', host='127.0.0.1', port='9050', user=None, password=None):
    config, network = policy(configured_proxy=True, active_proxy=True)
    config.NETWORK_PROXY = f'{mode}:{host}:{port}'
    config.NETWORK_PROXY_USER = user
    config.NETWORK_PROXY_PASSWORD = password
    active = SimpleNamespace(enabled=True, mode=mode, host=host, port=port, user=user, password=password)
    active.serialize_proxy_cfgstr = lambda: ':'.join((active.mode, active.host, str(active.port)))
    network.get_parameters = lambda: SimpleNamespace(proxy=active)
    return config, network


class ProxyRouteTests(unittest.TestCase):
    def test_consistent_direct_state_returns_no_proxy(self):
        self.assertIsNone(get_network_proxy(*policy()))

    def test_consistent_socks_routes_include_active_host_port_and_credentials(self):
        for mode, user, password in (('socks5', None, None), ('socks5', 'public-user', 'public-password'),
                                     ('socks4', None, None), ('socks4', 'public-user', None)):
            with self.subTest(mode=mode, auth=bool(user)):
                self.assertEqual(get_network_proxy(*proxied_policy(mode, user=user, password=password)),
                                 SocksProxy('127.0.0.1', 9050, mode, user, password))

    def test_offline_and_every_enabled_state_transition_refuse_io(self):
        for config, network in (policy(offline=True), policy(configured_proxy=True),
                                policy(active_proxy=True), (policy()[0], None)):
            with self.subTest(config=config), self.assertRaises(LeakCheckError):
                get_network_proxy(config, network)

    def test_invalid_boolean_states_cannot_enable_a_direct_fallback(self):
        for value in (None, '', 'false', 0, 1, [], {}):
            for name in ('NETWORK_OFFLINE', 'NETWORK_PROXY_ENABLED', 'active'):
                config, network = policy()
                if name == 'active':
                    network.get_parameters = lambda: SimpleNamespace(proxy=SimpleNamespace(enabled=value))
                else:
                    setattr(config, name, value)
                with self.subTest(name=name, value=value), self.assertRaises(LeakCheckError):
                    get_network_proxy(config, network)

    def test_pending_proxy_endpoint_and_credential_changes_are_refused(self):
        for name, value in (('NETWORK_PROXY', 'socks5:127.0.0.1:9150'),
                            ('NETWORK_PROXY_USER', 'changed-user'),
                            ('NETWORK_PROXY_PASSWORD', 'changed-password'),
                            ('NETWORK_PROXY_USER', False), ('NETWORK_PROXY', None)):
            config, network = proxied_policy()
            setattr(config, name, value)
            with self.subTest(name=name), self.assertRaises(LeakCheckError):
                get_network_proxy(config, network)

    def test_invalid_active_proxy_or_missing_host_accessors_are_refused(self):
        for name, value in (('mode', 'http'), ('host', ''), ('port', 'bad'),
                            ('port', True), ('password', [])):
            config, network = proxied_policy()
            setattr(network.get_parameters().proxy, name, value)
            with self.subTest(name=name), self.assertRaises(LeakCheckError):
                get_network_proxy(config, network)
        with self.assertRaises(LeakCheckError):
            get_network_proxy(object(), object())
