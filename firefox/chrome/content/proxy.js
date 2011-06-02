var nsIProtocolProxyFilter = Components.interfaces.nsIProtocolProxyFilter;

function PAKEProxyFilter() {
}

PAKEProxyFilter.prototype = {
    setFilter: function(on) {
        var proxyService = Components.classes
            ["@mozilla.org/network/protocol-proxy-service;1"]
            .getService(Components.interfaces.nsIProtocolProxyService);
        proxyService.unregisterFilter(this);
        if (on)
            proxyService.registerFilter(this, 0);
    },

    applyFilter: function(proxyService, uri, proxy) {
        if (uri.scheme != "https")
            return null;

        var proxyInfo = proxyService.newProxyInfo("http", "localhost", "8443",
                                                  0, 0, null);
        return proxyInfo;
    }
}

pakeproxyFilter = new PAKEProxyFilter();
