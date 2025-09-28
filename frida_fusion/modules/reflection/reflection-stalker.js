// Script Frida: Method.invoke -> build object + enviar via fusion_sendKeyValueData
Java.perform(function () {

    var jlrmethod = Java.use("java.lang.reflect.Method");
    var origInvoke = jlrmethod.invoke; // referência original

    function safeGetClassName(obj) {
        try {
            if (obj === null || obj === undefined) return null;
            var cls = obj.getClass();
            return cls.getName();
        } catch (e) {
            try { if (obj && obj.$className) return obj.$className; } catch(e2) {}
            try { return Object.prototype.toString.call(obj); } catch(_) { return typeof obj; }
        }
    }

    function buildParamInfo(param, depth) {
        depth = depth || 0;
        var maxDepth = 3;
        var info = { type: null, class_name: null, value: null };

        if (param === null || param === undefined) {
            info.type = 'null';
            return info;
        }

        var className = safeGetClassName(param);
        info.class_name = className;
        info.type = className;

        try {
            if (className && className.charAt(0) === '[') {
                info.type = className;
                if (className === '[B') {
                    try {
                        var buffer = Java.array('byte', param);
                        try { info.value = toBase64(buffer); } catch (e) { 
                            var sb = []; for (var i=0;i<Math.min(buffer.length,256);i++) sb.push((buffer[i]&0xff).toString(16));
                            info.value = sb.join('');
                        }
                    } catch (errByte) { info.value = '[unreadable byte array]'; }
                    return info;
                }
                if (className.indexOf('Ljava.lang.String') !== -1) {
                    try {
                        var arrLen = param.length;
                        var vals = [];
                        for (var i=0;i<Math.min(arrLen,50);i++) { vals.push(String(param[i])); }
                        info.value = { length: arrLen, preview: vals };
                    } catch(e) { info.value = '[unreadable string array]'; }
                    return info;
                }
                if (depth >= maxDepth) { info.value = '[array - depth limit]'; return info; }
                try {
                    var n = param.length;
                    var items = [];
                    for (var j=0; j<Math.min(n,50); j++) items.push(buildParamInfo(param[j], depth+1));
                    info.value = { length: n, preview: items };
                } catch(e) { info.value = '[unreadable array]'; }
                return info;
            }
        } catch(eArrDetect) {}

        try {
            if (className === 'java.lang.String' || (typeof param === 'string')) { info.value = String(param); return info; }
            if (className && (
                className.indexOf('java.lang.Number') !== -1 ||
                className.indexOf('java.lang.Integer') !== -1 ||
                className.indexOf('java.lang.Long') !== -1 ||
                className.indexOf('java.lang.Boolean') !== -1 ||
                className.indexOf('java.lang.Double') !== -1 ||
                className.indexOf('java.lang.Float') !== -1 ||
                className.indexOf('java.lang.Short') !== -1 ||
                className.indexOf('java.lang.Character') !== -1)) {
                try { info.value = param.toString(); } catch(e){ info.value = String(param); }
                return info;
            }
            try { info.value = param.toString(); } catch (e) { info.value = '[toString failed]'; }
            return info;
        } catch(errGeneric) {
            info.value = '[error building param]';
            return info;
        }
    }

    function buildInvokeObject(methodRef, targetObject, parameters) {
        var obj = {
            timestamp: (new Date()).toISOString(),
            method: {
                toString: String(methodRef),
                name: null,
                declaring_class: null,
                b64: null
            },
            target: {
                class_name: null,
                toString: null
            },
            parameters: [],
            return: {
                class_name: null,
                value: null
            }
        };

        try {
            if (methodRef && methodRef.getName) obj.method.name = methodRef.getName(); else obj.method.name = String(methodRef);
            try {
                var decl = methodRef.getDeclaringClass();
                obj.method.declaring_class = decl ? decl.getName() : null;
            } catch(e) { obj.method.declaring_class = null; }
        } catch(_) {}

        try {
            var tName = "" + methodRef;
            try { obj.method.b64 = fusion_stringToBase64(tName); } catch(e){ obj.method.b64 = null; }
        } catch(_) { obj.method.b64 = null; }

        try {
            if (targetObject === null || targetObject === undefined) {
                obj.target.class_name = null; obj.target.toString = null;
            } else {
                obj.target.class_name = safeGetClassName(targetObject);
                try { obj.target.toString = targetObject.toString(); } catch(e){ obj.target.toString = '[toString failed]'; }
            }
        } catch(e) {}

        try {
            var type = Object.prototype.toString.call(parameters);
            if (parameters === null || parameters === undefined) {
                obj.parameters = [];
            } else if (type === '[object Array]') {
                var arrLen = parameters.length;
                for (var i=0; i<Math.min(arrLen,200); i++) {
                    obj.parameters.push({ index: i, info: buildParamInfo(parameters[i], 0) });
                }
                if (arrLen > 200) obj.parameters_truncated = true;
            } else {
                try {
                    var maybeLen = parameters.length;
                    if (typeof maybeLen === 'number') {
                        for (var k=0; k<Math.min(maybeLen,100); k++) obj.parameters.push({ index: k, info: buildParamInfo(parameters[k],0) });
                    } else {
                        obj.parameters.push({ index: 0, info: buildParamInfo(parameters,0) });
                    }
                } catch(e2) {
                    obj.parameters.push({ index: 0, info: buildParamInfo(parameters,0) });
                }
            }
        } catch(errParams) {
            obj.parameters = [{ index:0, info: { type: '[error enumerating parameters]' } }];
        }

        return obj;
    }

    // coleta backtrace da Thread Java atual e retorna [pretty, raw]
    function collectBacktrace() {
        var pretty = "[unavailable]";
        var raw = [];
        try {
            var Thread = Java.use('java.lang.Thread');
            var trace = Thread.currentThread().getStackTrace(); // array of StackTraceElement
            var prettyLines = [];
            for (var i=0; i<trace.length; i++) {
                try {
                    var ste = trace[i];
                    var line = ste.toString(); // ex: com.foo.Bar.method(File.java:123)
                    prettyLines.push(line);
                    raw.push(String(ste));
                } catch(eSte) { /* ignore */ }
            }
            pretty = prettyLines.join('\n');
        } catch(e) {
            try {
                // fallback: usar Java.perform stack (menos informativo)
                pretty = (new Error()).stack;
                raw = [pretty];
            } catch(e2) {}
        }
        return { pretty: pretty, raw: raw };
    }

    // sobrescreve invoke para montar objeto e enviar via fusion_sendKeyValueData
    jlrmethod.invoke.implementation = function(object, parameters) {
        // monta objeto
        var infoObj = buildInvokeObject(this, object, parameters);

        // coletar backtrace
        var bt = collectBacktrace();

        // chamar o método original e capturar retorno
        var retvalue;
        try {
            retvalue = origInvoke.call(this, object, parameters);
        } catch (invokeErr) {
            // enviar também quando lançar (pode ser útil)
            try {
                fusion_sendKeyValueData("java.lang.reflect.Method!invoke!throw", [
                    { key: "method", value: String(infoObj.method.toString) },
                    { key: "declaring_class", value: String(infoObj.method.declaring_class) },
                    { key: "method_b64", value: String(infoObj.method.b64) },
                    { key: "target_class", value: String(infoObj.target.class_name) },
                    { key: "params_count", value: String(infoObj.parameters.length) },
                    { key: "params_preview", value: JSON.stringify(infoObj.parameters) },
                    { key: "backtrace", value: bt.pretty },
                    { key: "backtrace_raw", value: JSON.stringify(bt.raw) },
                    { key: "error", value: String(invokeErr) }
                ]);
            } catch(eSendErr) { fusion_sendMessage("W", "fusion_sendKeyValueData error: " + eSendErr); }

            throw invokeErr; // rethrow para manter comportamento
        }

        // preencher retorno infoObj.return
        try {
            if (retvalue === null || retvalue === undefined) {
                infoObj.return.class_name = null; infoObj.return.value = null;
            } else {
                infoObj.return.class_name = safeGetClassName(retvalue);
                if (infoObj.return.class_name && infoObj.return.class_name.charAt(0) === '[') {
                    if (infoObj.return.class_name === '[B') {
                        try { infoObj.return.value = toBase64(Java.array('byte', retvalue)); } catch(e) { infoObj.return.value = '[unreadable byte array]'; }
                    } else {
                        try {
                            var lenR = retvalue.length, itemsR = [];
                            for (var ri=0; ri<Math.min(lenR,50); ri++) { itemsR.push(String(retvalue[ri])); }
                            infoObj.return.value = { length: lenR, preview: itemsR };
                        } catch(eArrR) { infoObj.return.value = '[unreadable array]'; }
                    }
                } else {
                    try { infoObj.return.value = retvalue.toString(); } catch(e) { infoObj.return.value = '[toString failed]'; }
                }
            }
        } catch(eRetFill) { infoObj.return.value = '[error reading return]'; }

        // preparar payload para fusion_sendKeyValueData (array de {key, value})
        var payload = [];
        try {
            payload.push({ key: "method", value: String(infoObj.method.toString) });
            payload.push({ key: "method_name", value: String(infoObj.method.name) });
            payload.push({ key: "declaring_class", value: String(infoObj.method.declaring_class) });
            payload.push({ key: "method_b64", value: String(infoObj.method.b64) });
            payload.push({ key: "target_class", value: String(infoObj.target.class_name) });
            payload.push({ key: "target_tostring", value: String(infoObj.target.toString) });
            payload.push({ key: "params_count", value: String(infoObj.parameters.length) });

            // params_preview como JSON string (pode truncar se muito grande)
            try {
                var paramsJson = JSON.stringify(infoObj.parameters);
                if (paramsJson.length > 20000) paramsJson = paramsJson.slice(0,20000) + "...(truncated)";
                payload.push({ key: "params_preview", value: paramsJson });
            } catch(ePJ) {
                payload.push({ key: "params_preview", value: "[error serializing params]" });
            }

            // retorno
            try {
                var retSummary = (infoObj.return.class_name === null && infoObj.return.value === null) ? "null" :
                                 ("(" + String(infoObj.return.class_name) + ") " + String(infoObj.return.value));
                if (retSummary.length > 4000) retSummary = retSummary.slice(0,4000) + "...(truncated)";
                payload.push({ key: "return_summary", value: retSummary });
                payload.push({ key: "return_class", value: String(infoObj.return.class_name) });
            } catch(eRetPush) {
                payload.push({ key: "return_summary", value: "[error]" });
            }

            // backtrace
            payload.push({ key: "backtrace", value: bt.pretty });
            payload.push({ key: "backtrace_raw", value: JSON.stringify(bt.raw) });

            // timestamp
            payload.push({ key: "timestamp", value: infoObj.timestamp });

        } catch(ePayload) {
            fusion_sendMessage("W", "Erro ao preparar payload: " + ePayload);
        }

        // enviar pelo canal customizado
        try {
            fusion_sendKeyValueData("java.lang.reflect.Method!invoke!call", payload);
        } catch(eSend) {
            // se fusion_sendKeyValueData não existir, fallback para console + fusion_sendMessage (se existir)
            try { fusion_sendMessage("E", "fusion_sendKeyValueData missing or failed"); } catch(_) {}
        }

        return retvalue;
    };

    try { fusion_sendMessage("I", "Reflection module with fusion_sendKeyValueData loaded!"); } catch(e) { fusion_sendMessage("W", "Reflection module loaded!"); }

});
