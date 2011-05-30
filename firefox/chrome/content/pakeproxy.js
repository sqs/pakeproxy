var nsIHttpActivityObserver = Components.interfaces.nsIHttpActivityObserver;
var nsISocketTransport = Components.interfaces.nsISocketTransport;
Components.utils.import("resource://gre/modules/AddonManager.jsm");

var USE_EXISTING_PAKEPROXY = false;

function dlog(s) {
  dump(s + "\n");
}

var process = {
  instance: null,
  
  run: function() {
    if (USE_EXISTING_PAKEPROXY)
      return;

    AddonManager.getAddonByID("pakeproxy@trustedhttp.org", function(addon) {
      var file = addon.getResourceURI("resource/pakeproxy")
        .QueryInterface(Components.interfaces.nsIFileURL).file;
      if (file.exists()) {
        process.instance = Components.classes['@mozilla.org/process/util;1']
          .getService(Components.interfaces.nsIProcess);
        process.instance.init(file);

        var caCert = addon.getResourceURI("resource/public/ca-cert.pem").path;
        var caKey = addon.getResourceURI("resource/ca-key.pem").path;
        var certCache = addon.getResourceURI("resource/tmp").path;
        certCache = certCache.substring(0, certCache.length-1);
        var args = ['-C', caCert, '-K', caKey, '-m', certCache];
        
        process.instance.run(false, args, args.length);
        window.setTimeout(function() {
          dlog("Reloading page after pakeproxy had time to start...");
          gBrowser.reload();
        }, 150);
      }
    });
  },

  kill: function() {
    if (process.instance)
      process.instance.kill();
  },

  observe: function(subject, topic, data) {
    if (topic == "quit-application-requested")
      pakeproxyProcess.kill();
  }
};

var tabListener = {
  onSecurityChange: function(browser, webProgress, request, state) {
    // dlog("onSecurityChange: " + request.toString());
    tabListener._updateSecurityStatus();
  },

  onTabSelected: function(event) {
    //dlog("onTabSelected");
    tabListener._updateSecurityStatus();
  },

  //////////////////////////////////////////////////////////////////////////////

  _updateSecurityStatus: function() {
    var cert = getServerCert();
    if (cert && cert.issuerCommonName == "PAKEProxy CA Certificate") {
      var org = cert.organization;
      var name = org.substring(0, org.indexOf('@'));
      var site = org.substring(org.indexOf('@') + 1, org.indexOf(' (SRP)'));
      this._setIdentity(name, site);
    } else {
      this._setIdentity("", null);
    }
  },

  _setIdentity: function(name, host) {
    httpRequestObserver.currentTLSLoginHost = host;
    this._setIdentityLabel(name);
  },

  _setIdentityLabel: function(name) {
    //dlog("_setIdentityLabel: " + name);
    var label = document.getElementById("pake-identity-name");
    var box = document.getElementById("pake-identity-box");
    label.value = name;
    box.hidden = (name == "");
  }

};

window.addEventListener("load", function() {
  var container = gBrowser.tabContainer;
  process.run();
  gBrowser.addTabsProgressListener(tabListener);
  container.addEventListener("TabSelect", tabListener.onTabSelected, false);
}, false);

window.addEventListener("unload", function() {
  var container = gBrowser.tabContainer;
  gBrowser.removeTabsProgressListener(tabListener);
  container.removeEventListener("TabSelect", tabListener.onTabSelected, false);
}, false);

var observerService = Components.classes["@mozilla.org/observer-service;1"]
  .getService(Components.interfaces.nsIObserverService);
observerService.addObserver(process, "quit-application-requested", false);
