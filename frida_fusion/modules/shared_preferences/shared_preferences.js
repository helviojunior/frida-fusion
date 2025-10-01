// hook_sharedprefs.js
// Hook automático de todas as classes que implementam/derivam de android.content.SharedPreferences
// e seus Editors. Usa fusion_sendKeyValueData quando disponível; senão console.log.

setTimeout(function () {
       
    // ----------------- CONFIG -----------------
    // Set to true to hook ONLY known implementation classes (faster, less noisy).
    // Set to false to scan all loaded classes and detect those that implement the interface.
    var knownsOnly = false; // <--- your requested flag (bool knownsOnly = true)
    // ------------------------------------------

    // utilitário de logging (usa fusion_sendKeyValueData se existir)
    function logKeyValue(tag, arr) {
        try {
            if (typeof fusion_sendKeyValueData === 'function') {
                fusion_sendKeyValueData(tag, arr);
                return;
            }
        } catch (e) { 
            // fallback
            var s = tag + " | ";
            arr.forEach(function (kv) { s += kv.key + "=" + kv.value + " ; "; });
            console.log(s);
        }
    }

    const TARGET_CLASS = "android.content.SharedPreferences";
    const TARGET_INTERFACE = "android.content.SharedPreferences";
    const EDITOR_INTERFACE = "android.content.SharedPreferences$Editor";

    const JClass = Java.use('java.lang.Class');
    const isAssignableFrom = JClass.isAssignableFrom.overload('java.lang.Class');

    // Guarda nomes de editor já hookados para evitar repetir
    var hookedEditors = {};

    // ----- Helper: convertir objetos Java complexos para JS-friendly -----
    function javaObjectToJs(obj, seen) {
        // 'seen' para evitar loops circulares
        seen = seen || new WeakMap();

        try {
            if (obj === null || obj === undefined) return null;

            // tipos primitivos / toString seguros
            if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') return obj;

            // Se já vimos esse objeto (evita loop), retorna placeholder
            if (obj && typeof obj === 'object' && seen.has(obj)) return "[Circular]";

            // Try to cast to enforce Java Class
            if (obj && typeof obj === 'object') {
                try{
                    let cName = fusion_getClassName(obj);
                    obj = Java.cast(obj, Java.use(cName))
                } catch (_) {}
            }

            // Objetos Java têm getClass(); verifique isso
            if (obj && typeof obj.getClass === 'function') {
                var clsName = null;
                try { clsName = obj.getClass().getName(); } catch (e) { clsName = null; }

                // Strings/java.lang.String
                if (clsName === 'java.lang.String') {
                    return obj.toString();
                }

                // Números embalados
                if (clsName && (clsName.indexOf('java.lang.Integer') !== -1 ||
                                clsName.indexOf('java.lang.Long') !== -1 ||
                                clsName.indexOf('java.lang.Boolean') !== -1 ||
                                clsName.indexOf('java.lang.Float') !== -1 ||
                                clsName.indexOf('java.lang.Double') !== -1 ||
                                clsName.indexOf('java.lang.Short') !== -1 ||
                                clsName.indexOf('java.lang.Byte') !== -1)) {
                    return obj.toString();
                }

                // Detectar Map (java.util.Map, HashMap, LinkedHashMap, etc.)
                try {
                    // testar se tem keySet() e get(key)
                    if (typeof obj.keySet === 'function' && typeof obj.get === 'function') {

                        // prevenir loops
                        seen.set(obj, true);
                        var out = {};
                        try {
                            var keySetArr = [];
                            try {
                                // keySet().toArray() costuma funcionar
                                var ks = obj.keySet();
                                if (ks && typeof ks.toArray === 'function') {
                                    keySetArr = Java.from(ks.toArray());
                                } else {
                                    // alternativa: iterador
                                    try {
                                        var it = ks.iterator();
                                        while (it.hasNext()) {
                                            keySetArr.push(it.next());
                                        }
                                    } catch (ie) {}
                                }
                            } catch (ke) {
                                // fallback: tentar entrySet -> toArray
                                try {
                                    var es = obj.entrySet();
                                    if (es && typeof es.toArray === 'function') {
                                        var entries = Java.from(es.toArray());
                                        for (var ei = 0; ei < entries.length; ei++) {
                                            var entry = entries[ei];
                                            try {
                                                var k = entry.getKey();
                                                var v = entry.getValue();
                                                out[String(javaObjectToJs(k, seen))] = javaObjectToJs(v, seen);
                                            } catch (ee) {}
                                        }
                                        seen.delete(obj);
                                        return out;
                                    }
                                } catch (ee) {}
                            }
                            // agora percorre keys obtidas
                            for (var i = 0; i < keySetArr.length; i++) {
                                var k = keySetArr[i];
                                try {
                                    var v = obj.get(k);
                                    out[String(javaObjectToJs(k, seen))] = javaObjectToJs(v, seen);
                                } catch (e) {
                                    out[String(k)] = "[unreadable]";
                                }
                            }
                        } catch (e) {
                            // se falhar, devolve descrição
                            seen.delete(obj);
                            return "[Map:unreadable:" + clsName + "]";
                        }
                        seen.delete(obj);

                        return out;
                    }
                } catch (e) { /* ignore */ }

                // Detectar Collection/List (java.util.List, ArrayList ...)
                try {
                    if (typeof obj.size === 'function' && typeof obj.get === 'function') {
                        seen.set(obj, true);
                        var arr = [];
                        try {
                            var sz = obj.size();
                            for (var ii = 0; ii < sz; ii++) {
                                try {
                                    arr.push(javaObjectToJs(obj.get(ii), seen));
                                } catch (e) {
                                    arr.push("[unreadable]");
                                }
                            }
                        } catch (e) {
                            // fallback para toArray()
                            try {
                                var a = Java.from(obj.toArray());
                                for (var ai = 0; ai < a.length; ai++) arr.push(javaObjectToJs(a[ai], seen));
                            } catch (ee) { arr.push("[unreadable-list]"); }
                        }
                        seen.delete(obj);
                        return arr;
                    }
                } catch (e) { /* ignore */ }

                // Arrays Java
                try {
                    if (obj.getClass().isArray && obj.getClass().isArray()) {
                        var jarr = Java.from(obj);
                        var outArr = [];
                        for (var k = 0; k < jarr.length; k++) outArr.push(javaObjectToJs(jarr[k], seen));
                        return outArr;
                    }
                } catch (e) { /* ignore */ }

                // Para outros objetos Java: tentar toString() (útil para resultados simples)
                try {
                    var s = obj.toString();
                    return String(s);
                } catch (e) {
                    return "[JavaObject:" + (clsName || "unknown") + "]";
                }
            }

            // Se chegou aqui, é um objeto JS normal (possivelmente já convertido)
            try {
                return JSON.parse(JSON.stringify(obj));
            } catch (e) {
                return String(obj);
            }

        } catch (outer) {
            return "[unserializable]";
        }
    }

    // Verifica se a classe (java.lang.Class) ou qualquer superclasse implementa a interface alvo
    function classImplementsInterface(jclass, ifaceName) {
        if (jclass === null) return false;
        try {
            // verifica interfaces diretas
            var interfaces = jclass.getInterfaces();
            for (var i = 0; i < interfaces.length; i++) {
                var iname = interfaces[i].getName();
                if (iname === ifaceName) return true;
                // checar recursivamente nas interfaces
                if (classImplementsInterface(interfaces[i], ifaceName)) return true;
            }
            // sobe na hierarquia de superclasses
            var superc = jclass.getSuperclass();
            if (superc !== null) {
                return classImplementsInterface(superc, ifaceName);
            }
        } catch (e) {
            // algumas classes podem lançar; ignore
        }
        return false;
    }

    // Hook genérico de todos os overloads de um método com logging antes/depois
    function hookAllOverloads(targetClass, methodName, onEnter) {
        try {
            if (!targetClass[methodName] || !targetClass[methodName].overloads) return;
            var overloads = targetClass[methodName].overloads;
            for (var i = 0; i < overloads.length; i++) {
                (function (idx) {
                    var orig = overloads[idx];
                    overloads[idx].implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        try {
                            onEnter && onEnter.call(this, args, orig);
                        } catch (e) {
                            fusion_sendMessage('W', `onEnter hook error for ${methodName}: ${e}`);
                        }
                        // chamar método original
                        var res = orig.call(this, ...args);
                        return res;
                    };
                })(i);
            }
        } catch (e) {
            fusion_sendMessage('W', "Erro ao hookar " + methodName + " em " + targetClass.$className + ` -> ${e}`);
        }
    }

    // Hook nos métodos do Editor (put*, remove, clear, apply, commit)
    function hookEditorClass(edClass) {
        if (!edClass || !edClass.$className) return;
        var name = edClass.$className;
        if (hookedEditors[name]) return;
        hookedEditors[name] = true;
        fusion_sendMessage('D', "Hooking SharedPreferences.Editor class: " + name);

        var editorMethods = [
            "putString", "putInt", "putLong", "putFloat", "putBoolean", "putFloat",
            "remove", "clear", "apply", "commit"
        ];

        editorMethods.forEach(function (m) {
            try {
                if (!edClass[m]) return;
                var ovs = edClass[m].overloads;
                for (var j = 0; j < ovs.length; j++) {
                    (function (idx) {
                        var orig = ovs[idx];
                        ovs[idx].implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            var parsedArgs = args.map(a => javaObjectToJs(a));
                            var kv = [
                                { key: "EditorClass", value: name },
                                { key: "Method", value: m },
                                { key: "Args", value: JSON.stringify(parsedArgs) }
                            ];
                            logKeyValue("SharedPreferences$Editor." + m, kv);
                            return orig.call(this, ...args);
                        };
                    })(j);
                }
            } catch (e) {
                fusion_sendMessage('W', "Erro ao hookar Editor method " + m + " em " + name + ` -> ${e}`);
            }
        });
    }

    // Hook nas classes que implementam SharedPreferences
    function hookSharedPreferencesClass(clsWrapper, className) {
        fusion_sendMessage('W', "Hookando SharedPreferences class: " + className);

        // métodos a monitorar
        var methodsToHook = [
            "getString", "getInt", "getBoolean", "getLong", "getFloat",
            "getAll", "contains", "edit", "getStringSet", "getFloat",
            "registerOnSharedPreferenceChangeListener", "unregisterOnSharedPreferenceChangeListener"
        ];

        methodsToHook.forEach(function (m) {
            try {
                if (!clsWrapper[m]) return;
                var ovs = clsWrapper[m].overloads;
                for (var i = 0; i < ovs.length; i++) {
                    (function (idx) {
                        var orig = ovs[idx];
                        ovs[idx].implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            var parsedArgs = args.map(a => javaObjectToJs(a));
                            var entry = [
                                { key: "Class", value: className },
                                { key: "Method", value: m },
                                { key: "Args", value: JSON.stringify(parsedArgs) }
                            ];

                            if (m === "getString" || m === "getInt" || m === "getBoolean" || m === "getLong" || m === "getFloat" || m === "contains") {
                                var result = orig.call(this, ...args);
                                entry.push({ key: "Result", value: javaObjectToJs(result) });
                                logKeyValue("SharedPreferences." + m, entry);
                                return result;
                            }

                            if (m === "getAll") {
                                var result = orig.call(this, ...args);
                                // resultado costuma ser java.util.Map
                                var jResult = javaObjectToJs(result);
                                if (fusion_getClassName(jResult) != 'java.lang.String'){
                                    try {
                                        jResult = JSON.stringify(jResult);
                                    } catch (_) {}
                                }
                                entry.push({ key: "Result", value: jResult });
                                logKeyValue("SharedPreferences.getAll", entry);
                                return result;
                            }

                            if (m === "edit") {
                                var editorObj = orig.call(this, ...args);
                                try {
                                    if (editorObj !== null) {
                                        var editorClassName = editorObj.getClass().getName();
                                        entry.push({ key: "EditorClass", value: editorClassName });
                                        logKeyValue("SharedPreferences.edit", entry);
                                        try {
                                            var edClsWrapper = Java.use(editorClassName);
                                            hookEditorClass(edClsWrapper);
                                        } catch (ee) {
                                            try {
                                                var edIface = Java.use(EDITOR_INTERFACE);
                                                hookEditorClass(edIface);
                                            } catch (eee) {
                                                fusion_sendMessage('W', "Não foi possível hookar editor por classe: " + ee);
                                            }
                                        }
                                    } else {
                                        logKeyValue("SharedPreferences.edit", entry);
                                    }
                                } catch (e) {
                                    logKeyValue("SharedPreferences.edit", entry);
                                }
                                return editorObj;
                            }

                            if (m.indexOf("register") !== -1 || m.indexOf("unregister") !== -1) {
                                entry.push({ key: "Note", value: "register/unregister called" });
                                logKeyValue("SharedPreferences." + m, entry);
                                return orig.call(this, ...args);
                            }

                            return orig.call(this, ...args);
                        };
                    })(i);
                }
            } catch (e) {
                fusion_sendMessage('W', "Erro ao hookar método " + m + " em " + className + ` -> ${e}`);
            }
        });
    }

    function hookPrefs() {
        // MAIN: enumera classes carregadas e detecta implementações de SharedPreferences
        try {
            fusion_sendMessage('W', `Enumerating loaded classes to find implementations of ${TARGET_INTERFACE} ... (this process may take a while)`);
            var classes = Java.enumerateLoadedClassesSync();
            const targetClass = Java.use(TARGET_CLASS).class;

            if (knownsOnly) classes = classes.filter(n => n.indexOf("SharedPreferences") !== -1);

            for (var i = 0; i < classes.length; i++) {
                var name = classes[i];

                // filtro rápido: pular pacotes java/lang, dalvik etc para economizar tempo
                if (name.indexOf("java.") === 0 || name.indexOf("dalvik.") === 0 || name.indexOf("sun.") === 0) continue;
                try {
                    var clsWrapper = null;
                    // Alguns nomes lançam se usarmos Java.use direto; proteger
                    try {
                        clsWrapper = Java.use(name);
                    } catch (e) {
                        continue;
                    }
                    // obter java.lang.Class do wrapper
                    var jclass = null;
                    try {
                        jclass = clsWrapper.class;
                    } catch (e) {
                        continue;
                    }
                    if (!jclass) continue;

                    //Checagens básicas para optimizar o tempo
                    if (!(clsWrapper.getString && clsWrapper.getString.overloads)) continue;

                    // checar se implementa a interface alvo
                    if (classImplementsInterface(jclass, TARGET_INTERFACE)) {
                        hookSharedPreferencesClass(clsWrapper, name);
                    }else {
                        if (name.indexOf("android.") === 0) continue;
                        if (!isAssignableFrom.call(targetClass, jclass)) continue;

                        hookSharedPreferencesClass(clsWrapper, name);
                    }
                } catch (e) {
                    // ignore classes que falham
                }
            }
            fusion_sendMessage('W', "Scan finished of SharedPreferences.");
        } catch (e) {
            fusion_sendMessage('W', `Erro no scanner principal: ${e}`);
        }
    }

    Java.perform(function () {
        var likelyRN = fusion_isReactNativeApp();
        if (!likelyRN) {
            hookPrefs();
        }else{
            fusion_sendMessage("W", "App looks like React Native — waiting for React classes to load...");
            fusion_waitForClass("com.facebook.react.bridge.ReactContext", function(){
                fusion_sendMessage("D", "React classes are present — running callback now.");
                hookPrefs();
            })

        }
    });

}, 0);
