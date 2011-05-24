var pakeproxy;

function log(s) {
  Firebug.Console.log(s);
}

function PAKEProxy() { }

PAKEProxy.prototype = {
  onLoad: function() {
    this._setTabSelectListener(true);
    this.initialized = true;
    this.onTabSelected({target: gBrowser.selectedTab});
  },

  onTabSelected: function(event) {
    var cert = getServerCert();
    if (cert && cert.issuerCommonName == "PAKEProxy CA Certificate") {
      var org = cert.organization;
      var name = org.substring(0, org.indexOf('@'));
      this._setIdentityLabel(name);
    }
  },

  _setTabSelectListener: function(on) {
    var container = gBrowser.tabContainer;
    if (on) {
      container.addEventListener("TabSelect", this.onTabSelected, false);
      container.addEventListener("TabOpen", this.onTabSelected, false);
    } else {
      container.removeEventListener("TabSelect", this.onTabSelected, false);
      container.removeEventListener("TabOpen", this.onTabSelected, false);
    }
  },

  _setIdentityLabel: function(name) {
    var label = document.getElementById("pake-identity-name");
    label.value = name;
    label.hidden = (name == "");
  }

};


function pakeproxy_window_onLoad() {
  gBrowser.addEventListener("load", function() {
    pakeproxy = new PAKEProxy();
    pakeproxy.onLoad();
  }, true);
}

window.addEventListener("load", pakeproxy_window_onLoad, false);
