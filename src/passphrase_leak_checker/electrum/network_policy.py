"""Read a consistent route from Electrum network settings."""

from .pwned_api import LeakCheckError, PwnedClient, SocksProxy


def get_network_proxy(config, network):
    """Require an online host with consistent proxy settings."""
    try:
        offline = config.NETWORK_OFFLINE
        configured = config.NETWORK_PROXY_ENABLED
        if type(offline) is not bool or type(configured) is not bool:
            raise LeakCheckError("Cannot verify Electrum's network settings. Leak check unavailable.")
        if offline or network is None:
            raise LeakCheckError('Leak checks are disabled while Electrum is offline.')
        active = network.get_parameters().proxy
        if type(active.enabled) is not bool:
            raise LeakCheckError("Cannot verify whether Electrum's proxy is enabled. Leak check unavailable.")
        if configured != active.enabled:
            raise LeakCheckError('Electrum proxy settings are changing. Retry after the proxy is connected.')
        if not configured:
            return None
        proxy = SocksProxy(host=active.host, port=PwnedClient._integer_setting(active.port),
                           mode=active.mode, username=active.user, password=active.password)
        # Recheck the endpoint and credentials before connecting, including
        # changes between two enabled proxies.
        expected = active.serialize_proxy_cfgstr()
        if not isinstance(expected, str):
            raise LeakCheckError('Cannot serialize the Electrum proxy route.')
        if config.NETWORK_PROXY != expected:
            raise LeakCheckError('Electrum proxy configuration is changing or unsupported. Reapply proxy settings and retry.')
        credentials = (config.NETWORK_PROXY_USER, config.NETWORK_PROXY_PASSWORD)
        if any(value is not None and not isinstance(value, str) for value in credentials):
            raise LeakCheckError('Cannot verify the Electrum proxy username and password.')
        if tuple(value or None for value in credentials) != (proxy.username, proxy.password):
            raise LeakCheckError('The Electrum proxy username or password changed. Reapply proxy settings and retry.')
        return proxy
    except LeakCheckError:
        raise
    except Exception:
        raise LeakCheckError("Cannot verify Electrum's network settings. Leak check unavailable.") from None
