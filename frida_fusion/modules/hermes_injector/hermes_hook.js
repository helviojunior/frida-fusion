// hermes_hook.js
/*
(function () {
  var root = (typeof globalThis !== 'undefined') ? globalThis
           : (typeof global !== 'undefined')     ? global
           : this;

  var PREFIX = '[FUSION] '; // <-- mantenha igual no lado Frida
  var sink = (typeof root.print === 'function') ? root.print : function(){};

  function send(level, arr) {
    var msg = Array.prototype.map.call(arr, function (x) { return String(x); }).join(' ');
    // tenta caminho nativo do RN (leva até android.util.Log):
    try {
      if (typeof root.nativeLoggingHook === 'function') {
        root.nativeLoggingHook(level, PREFIX + msg);
        return;
      }
    } catch (_) {}
    // fallback: stdout do Hermes
    try { sink(PREFIX + msg); } catch (_) {}
  }

  // shim de console + atalho __fusionLog
  if (!root.console) root.console = {};
  var c = root.console;
  if (typeof c.log   !== 'function') c.log   = function(){ send(0, arguments); };
  if (typeof c.info  !== 'function') c.info  = function(){ send(0, arguments); };
  if (typeof c.debug !== 'function') c.debug = function(){ send(0, arguments); };
  if (typeof c.warn  !== 'function') c.warn  = function(){ send(1, arguments); };
  if (typeof c.error !== 'function') c.error = function(){ send(2, arguments); };

  // helper explícito
  root.__fusionLog = function(level, message) { send(level|0, [message]); };
})();
*/