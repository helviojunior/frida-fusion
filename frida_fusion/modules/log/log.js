// log.js
// Intercept android.util.Log.*

setTimeout(function () {

    Java.perform(function () {
        var Log = null;
        try {
            Log = Java.use("android.util.Log");
        } catch (err) {
            fusion_sendMessage('E', `Class android.util.Log not found: ${err}`);
            return;
        }

        var methods = ['d', 'i', 'w', 'e', 'v', 'wtf', 'println'];

        function argToStr(a) {
            try {
                if (a === null || a === undefined) return String(a);
                // alguns objetos Java têm toString() seguros
                return a.toString();
            } catch (e) {
                try { return JSON.stringify(a); } catch(_) { return '[unprintable]'; }
            }
        }

        methods.forEach(function (m) {
            if (typeof Log[m] === 'undefined') return;

            var overloads = Log[m].overloads;
            for (var j = 0; j < overloads.length; j++) {
                (function (ov, methodName, idx) {
                    // guarda referência à implementação existente (pode ser null)
                    var origImpl = ov.implementation;

                    ov.implementation = function () {
                        var args = [];
                        for (var k = 0; k < arguments.length; k++) args.push(arguments[k]);

                        // tenta extrair tag/msg conforme padrões conhecidos
                        var tag = args.length > 0 ? argToStr(args[0]) : "";
                        var msg = args.length > 1 ? argToStr(args[1]) : "";
                        var extra = "";
                        if (args.length === 3 && typeof args[0] === 'number') {
                            extra = "priority=" + args[0] + " ";
                            tag = argToStr(args[1]);
                            msg = argToStr(args[2]);
                        }

                        fusion_sendKeyValueData('android.util.Log', [
                            { key: "Level", value: m },
                            { key: "Tag", value: tag },
                            { key: "Message", value: msg },
                            { key: "RawArgs", value: args }
                        ]);

                        // se quiser enviar para o host:
                        // send({type: "log", level: methodName, tag: tag, msg: msg, rawArgs: args});

                        // chama implementação original se for uma função válida
                        try {
                            if (origImpl && typeof origImpl === 'function') {
                                return origImpl.apply(this, arguments);
                            } else {
                                // fallback seguro:
                                // a maioria dos métodos Log.* retorna int (0 em caso de "ok")
                                // retornar 0 evita crashes quando não há implementação original
                                return 0;
                            }
                        } catch (callErr) {
                            // captura qualquer erro ao chamar a implementação original
                            fusion_sendMessage('E', `Erro ao chamar implementação original de Log.${methodName}: ${callErr}`);
                            return 0;
                        }
                    };
                })(overloads[j], m, j);
            }
        });

        fusion_sendMessage('W', "Hook android.util.Log to: " + methods.join(", "));
    });

}, 0);
