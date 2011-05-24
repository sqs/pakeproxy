/* adapted from http://codefromthe70s.org/sslblacklist.aspx */
function getServerCert() {
    var sec = gBrowser.securityUI;
    if (!sec)
        return null;

    var sslprov = sec.QueryInterface(Components.interfaces.nsISSLStatusProvider);
    if (!sslprov)
        return null;

    var status = sslprov.SSLStatus;
    if (!status)
        return null;

    status = status.QueryInterface(Components.interfaces.nsISSLStatus);
    if (!status)
        return null;

    return status.serverCert;
}

