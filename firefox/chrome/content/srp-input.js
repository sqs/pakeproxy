var paranoid = 0; // TODO(sqs): make true?


function srp_make_salt(bytes) {
  return sjcl.random.randomWords(bytes/4, paranoid);
}

function srp_form_submit(button) {
  // TODO(sqs): cleanse this value - it's used in code string below
  var username = document.getElementById('srp_username').value;
  var password = document.getElementById('srp_password').value;

  button.value = "Computing...";
  button.disabled = true;

  var group = sjcl.keyexchange.srp.knownGroup(1024);
  var salt = srp_make_salt(16);
  var verifier = sjcl.keyexchange.srp.makeVerifier(username, password,
                                                   salt, group);

  var srps = sjcl.codec.base64.fromBits(salt);
  var srpv = sjcl.codec.base64.fromBits(verifier.toBits());
  
  button.value = "Finished";

  // Fill in forms on page
  var inputs = gBrowser.contentDocument.getElementsByTagName('input');
  for (var j = 0; j < inputs.length; j++) {
    if (inputs[j].attributes['type'].value == 'srp-verifier') {
      inputs[j].value = srpv;
    } else if (inputs[j].attributes['type'].value == 'srp-salt') {
      inputs[j].value = srps;
    } else if (inputs[j].name == 'username') {
      inputs[j].value = username;
    }
  }

  var panel = document.getElementById("srp-input-panel");
  panel.hidePopup();
}


var srpInputListener = {
  init: function() {
    srpInputListener.loadSJCL();
    var appcontent = document.getElementById("appcontent");
    if (appcontent) {
      appcontent.addEventListener("DOMContentLoaded", srpInputListener.onPageLoad, true);
    }

    AddonManager.getAddonByID("firebug@software.joehewitt.com", function(addon) {
      dlog("ADDON = " + addon.isActive);
      if (addon && addon.isActive) {
        document.getElementById("srp_firebug_warning").hidden = false;
      }
    });
  },

  onPageLoad: function(ev) {
    var doc = ev.originalTarget;
    if (doc.nodeName == "#document") {
      srpInputListener.checkPageForSRPInputs(doc);
    }
  },

  onTabSelected: function(ev) {
    srpInputListener.onPageLoad({'originalTarget': gBrowser.contentDocument});
  },

  checkPageForSRPInputs: function(doc) {
    if (!doc.forms)
      return;
    for (var i = 0; i < doc.forms.length; i++) {
      var form = doc.forms[i];
      var inputs = form.getElementsByTagName('input');
      for (var j = 0; j < inputs.length; j++) {
        if (inputs[j].attributes['type'].value == "srp-verifier") {
          srpInputListener.setSRPInputVisible(true);
          return;
        }
      }
    }
    // else none found
    srpInputListener.setSRPInputVisible(false);
  },

  setSRPInputVisible: function(visible) {
    document.getElementById("srp-input-box").hidden = !visible;
  },

  loadSJCL: function() {
    if (!sjcl.keyexchange.srp) {
        alert("Fatal error: SJCL was not built with SRP support.");
        return;
    }
    sjcl.random.startCollectors();
  },

  onClick: function() {
    var panel = document.getElementById("srp-input-panel");
    var box = document.getElementById("srp-input-box");
    panel.openPopup(box, "after_start", 0, 0, false, false);
  }


}


window.addEventListener("load", function() {
  var container = gBrowser.tabContainer;
  srpInputListener.init();
  gBrowser.addTabsProgressListener(srpInputListener);
  container.addEventListener("TabSelect", srpInputListener.onTabSelected, false);
}, false);

window.addEventListener("unload", function() {
  var container = gBrowser.tabContainer;
  gBrowser.removeTabsProgressListener(srpInputListener);
  container.removeEventListener("TabSelect", srpInputListener.onTabSelected, false);
}, false);


