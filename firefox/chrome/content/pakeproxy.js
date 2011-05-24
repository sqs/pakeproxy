function dlog(s) {
  dump(s + "\n");
}

var tabListener = {
  onSecurityChange: function(browser, webProgress, request, state) {
    dlog("onSecurityChange: " + request.toString());
    tabListener._updateSecurityStatus();
  },

  onTabSelected: function(event) {
    dlog("onTabSelected");
    tabListener._updateSecurityStatus();
  },

  //////////////////////////////////////////////////////////////////////////////

  _updateSecurityStatus: function() {
    var cert = getServerCert();
    if (cert && cert.issuerCommonName == "PAKEProxy CA Certificate") {
      var org = cert.organization;
      var name = org.substring(0, org.indexOf('@'));
      this._setIdentityLabel(name);
    } else {
      this._setIdentityLabel("");
    }
  },

  _setIdentityLabel: function(name) {
    dlog("_setIdentityLabel: " + name);
    var label = document.getElementById("pake-identity-name");
    var box = document.getElementById("pake-identity-box");
    label.value = name;
    label.tooltiptext = "Hello";
    box.hidden = (name == "");
  }

};

window.addEventListener("load", function() {
  var container = gBrowser.tabContainer;
  gBrowser.addTabsProgressListener(tabListener);
  container.addEventListener("TabSelect", tabListener.onTabSelected, false);
}, false);

window.addEventListener("unload", function() {
  var container = gBrowser.tabContainer;
  gBrowser.removeTabsProgressListener(tabListener);
  container.removeEventListener("TabSelect", tabListener.onTabSelected, false);
}, false);