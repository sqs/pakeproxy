const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
const nsIX509CertDB = Components.interfaces.nsIX509CertDB;
const nsIX509Cert = Components.interfaces.nsIX509Cert;


function getContents(aURL){
  var ioService=Components.classes["@mozilla.org/network/io-service;1"]
    .getService(Components.interfaces.nsIIOService);
  var scriptableStream=Components
    .classes["@mozilla.org/scriptableinputstream;1"]
    .getService(Components.interfaces.nsIScriptableInputStream);

  var channel=ioService.newChannel(aURL,null,null);
  var input=channel.open();
  scriptableStream.init(input);
  var str=scriptableStream.read(input.available());
  scriptableStream.close();
  input.close();
  return str;
}

function importRootCert() {
    var certdb = Components.classes[nsX509CertDB].getService(nsIX509CertDB);
    var certData = getContents("resource://pakeproxy/ca-cert.pem");
    certData = certData.replace("-----BEGIN CERTIFICATE-----\n", "")
        .replace("-----END CERTIFICATE-----", "").replace(/\n/g,"");
    var c    = certdb.constructX509FromBase64(certData);

    var certCache =
        Components.classes["@mozilla.org/security/nsscertcache;1"]
        .getService(Components.interfaces.nsINSSCertCache);

    var caTreeView = 
	Components.classes["@mozilla.org/security/nsCertTree;1"]
        .createInstance(Components.interfaces.nsICertTree);

    // check whether cert is already imported
    certCache.cacheAllCerts();
    caTreeView.loadCertsFromCache(certCache,
		                  Components.interfaces.nsIX509Cert.CA_CERT);
    for (var i = 0; i < caTreeView.rowCount; i++) {
        var cert = caTreeView.getCert(i);
	if (!cert)
	    continue;
	if (cert.commonName == c.commonName)
	    return;
    }

    var cert = new Object();
    var len = new Object();
    x = c.getRawDER(len, cert);

    alert("PAKEProxy: You will be asked to trust a new certificate authority (CA). Choose \"Trust this CA to identify Web sites\" and click OK. You should either remove it when you're done or generate your own (see `make certs` in the pakeproxy root).");

    certdb.importCertificates(x, x.length, nsIX509Cert.CA_CERT, null);
}

window.addEventListener("load", function() {
  setTimeout(importRootCert, 500);
}, false);
