/*  Frida Fusion helper functions
    Author: Helvio Junior - M4v3r1ck
*/

// Lista de classes típicas do React Native (pode ampliar se quiser)
const FUSION_DEFAULT_REACT_CLASSES = [
    "com.facebook.react.ReactApplication",
    "com.facebook.react.ReactInstanceManager",
    "com.facebook.react.bridge.ReactContext",
    "com.facebook.react.bridge.JavaScriptModule",
    "com.facebook.react.bridge.NativeModule",
    "com.facebook.react.modules.core.DeviceEventManagerModule",
    "com.facebook.react.bridge.ReactApplicationContext"
];

/**
 * Tenta determinar se a app tem indícios de ser React Native.
 * Estratégia:
 *  - tenta Java.use em classes conhecidas (se lançar, ignora)
 *  - verifica classes já carregadas (enumerateLoadedClassesSync)
 *
 * Retorna true/false.
 */
function fusion_isReactNativeApp(reactClasses) {
    reactClasses = reactClasses || FUSION_DEFAULT_REACT_CLASSES;
    if (!Java.available) return false;

    try {
        // 1) tentativa de usar as classes (pode carregar a classe se presente)
        for (var i = 0; i < reactClasses.length; i++) {
            try {
                Java.use(reactClasses[i]);
                return true; // encontrou uma classe RN na ClassLoader
            } catch (e) {
                // não encontrado/erro: continuar
            }
        }

        // 2) se nada foi encontrado via Java.use, verificar classes já carregadas
        try {
            var loaded = Java.enumerateLoadedClassesSync();
            for (var j = 0; j < loaded.length; j++) {
                var name = loaded[j];
                for (var k = 0; k < reactClasses.length; k++) {
                    if (name.indexOf(reactClasses[k]) !== -1 || name === reactClasses[k]) {
                        return true;
                    }
                }
            }
        } catch (e) {
            // enumerateLoadedClassesSync pode falhar em alguns contextos; ignorar
        }
    } catch (outer) {
        // fallback
    }
    return false;
}

function fusion_rawSend(payload1){
    send(payload1);
}

function fusion_Send(payload1, payload2){
    const info = fusion_getCallerInfo();

    const message = {
        payload: payload1,
        location: info
    };

    // if payload1 is objet and has "type"
    if (payload1 && typeof payload1 === 'object' && 'type' in payload1) {
        message.type = payload1.type;
    }

    send(message, payload2);
}

function fusion_classExists(name) { try { Java.use(name); return true; } catch (_) { return false; } }

function fusion_useOrNull(name) { try { return Java.use(name); } catch (e) { return null; } }

function fusion_waitForClass(name, onReady) {
    var intv = setInterval(function () {
      try {
        var C = Java.use(name);
        clearInterval(intv);
        onReady(C);
      } catch (e) { /* ainda não carregou */ }
    }, 100);
}

function fusion_printStackTrace(){
    var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    trace = trace.replace("java.lang.Exception\n", "Stack trace:\n");
    fusion_sendMessage("I", trace);
}

function fusion_toLongPrimitive(v, fallback /* opcional */) {
  const FB = (typeof fallback === 'number') ? fallback : -1;

  try {
    // Já é número JS
    if (typeof v === 'number') {
      // garante inteiro (contentLength é integral)
      return Math.trunc(v);
    }

    if (v === null || v === undefined) return FB;

    // java.lang.Long / Integer / Short (ou qualquer Number com longValue/intValue)
    if (v.longValue)  { try { return v.longValue();  } catch (_) {} }
    if (v.intValue)   { try { return v.intValue();   } catch (_) {} }
    if (v.shortValue) { try { return v.shortValue(); } catch (_) {} }

    // String numérica
    if (typeof v === 'string' || (v.toString && typeof v.toString() === 'function')) {
      const s = String(v);
      if (/^-?\d+$/.test(s)) {
        const JLong = Java.use('java.lang.Long');
        // parseia com Java para respeitar faixa de long
        return JLong.parseLong(s);
      }
    }
  } catch (_) {}

  return FB;
}

function fusion_toBytes(message){
    try{
        const StringClass = Java.use('java.lang.String');
        var bTxt = StringClass.$new(message).getBytes('utf-8');

        return bTxt;
    } catch (err) {
        fusion_sendMessage("W", err)
    }
}

function fusion_stringToBase64(message){
    try{
        const StringClass = Java.use('java.lang.String');
        const Base64Class = Java.use('android.util.Base64');
        var bTxt = StringClass.$new(message).getBytes('utf-8');
        var b64Msg = Base64Class.encodeToString(bTxt, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        return b64Msg;
    } catch (err) {
        fusion_sendMessage("W", err)
    }
}

function fusion_bytesToBase64(byteArray){

    if (byteArray === null || byteArray === undefined) return "IA==";
    try {
        // 1) Confirma tipo byte[], se não tenta converter em string
        byteArray = Java.array('byte', byteArray);

        // 2) Tem 'length' numérico
        const len = byteArray.length;
        if (typeof len !== "number") return "IA==";

        // 3) (opcional) Exigir conteúdo
        if (len === 0) return "IA==";

    } catch (e) {
        return "IA==";
    }

    try{
        
        const Base64Class = Java.use('android.util.Base64');
        var b64Msg = Base64Class.encodeToString(byteArray, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        return b64Msg;
    } catch (err) {
        fusion_sendMessage("W", err)
        return "IA==";
    }
}

function fusion_base64ToString(b64) {
  try {
    const StringClass  = Java.use('java.lang.String');
    const Base64Class  = Java.use('android.util.Base64');

    // Flags úteis (só para referência/legibilidade)
    const BASE64_DEFAULT  = 0x00000000; // decode padrão
    const BASE64_URL_SAFE = 0x00000008; // para strings base64 url-safe

    // Normaliza entrada
    let s = ('' + b64).trim();
    // Remove prefixo data URI, se existir
    s = s.replace(/^data:.*;base64,/, '');
    // Remove espaços/linhas quebradas
    s = s.replace(/\s+/g, '');

    // Função para padding quando faltam '='
    function padBase64(x) {
      const m = x.length % 4;
      return m === 0 ? x : x + '===='.slice(m);
    }

    let decoded = null;

    // 1) Tenta DEFAULT
    try {
      decoded = Base64Class.decode(s, BASE64_DEFAULT);
    } catch (e1) {
      // 2) Tenta URL_SAFE
      try {
        decoded = Base64Class.decode(s, BASE64_URL_SAFE);
      } catch (e2) {
        // 3) Tenta com padding
        const sp = padBase64(s);
        decoded = Base64Class.decode(sp, BASE64_DEFAULT);
      }
    }

    // Converte bytes -> String UTF-8
    const result = StringClass.$new(decoded, 'utf-8').toString();
    return result;

  } catch (err) {
    // mesmo logger que você usa na encode
    fusion_sendMessage("W", err);
    return null;
  }
}

function fusion_normalizePtr(addr) {
  let p = ptr(addr);
  if (Process.arch === 'arm64') p = p.and('0x00FFFFFFFFFFFFFF'); // limpa TBI
  return p;
}

function fusion_getCallerInfo() {
  try{
    const stack = new Error().stack.split("\n");

    //Skip Error and getCallerInfo from stack trace
    for (let i = 2; i < stack.length; i++) {
      const line = stack[i].trim();

      // Extrai: functionName (file:line:col)
      // ou apenas (file:line:col) se não tiver nome
      const m = line.match(/at\s+(?:(\S+)\s+)?[\( ]?(\S+):(\d+)\)?$/);
      if (m) {
        const func = m[1] || "";
        const file = m[2];
        const ln   = parseInt(m[3], 10);

        // Ignore helper functions (with name "send")
        if (/^send/i.test(func)) continue;
        if (/^fusion_Send/i.test(func)) continue;

        return { file_name: file, function_name: func, line: ln };
      }
    }
  } catch (err) {
    console.log(`Error: ${err}`)
  }
  return null;
}

function fusion_sendKeyValueData(module, items) {
    try{
      var st = fusion_getB64StackTrace();

      var data = [];

      // Force as String
      for (let i = 0; i < items.length; i++) {
          data = data.concat([{key: `${items[i].key}`, value:`${items[i].value}`}]);
      }

      fusion_Send({
        type: "key_value_data",
        module: module,
        data: data,
        stack_trace: st
      }, null);
    } catch (err) {
      fusion_sendMessage("W", `Error: ${err}`)
    }
    return null;
}

function fusion_sendMessage(level, message){
    try{
        const StringClass = Java.use('java.lang.String');
        const Base64Class = Java.use('android.util.Base64');
        var bTxt = StringClass.$new(message).getBytes('utf-8');
        var b64Msg = Base64Class.encodeToString(bTxt, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        //send('{"type" : "message", "level" : "'+ level +'", "message" : "'+ b64Msg +'"}');
        fusion_Send({
          type: "message",
          level: level,
          message: b64Msg
        }, null)
    } catch (err) {
        fusion_sendMessage("W", `Error: ${err}`)
    }
}

function fusion_sendMessageWithTrace(level, message){
    try{
        const StringClass = Java.use('java.lang.String');
        const Base64Class = Java.use('android.util.Base64');

        var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        trace = trace.replace("java.lang.Exception\n", "Stack trace:\n");
        message += "\n"
        message += trace

        var bTxt = StringClass.$new(message).getBytes('utf-8');
        var b64Msg = Base64Class.encodeToString(bTxt, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        //send('{"type" : "message", "level" : "'+ level +'", "message" : "'+ b64Msg +'"}');
        fusion_Send({
          type: "message",
          level: level,
          message: b64Msg
        }, null)
    } catch (err) {
        fusion_sendMessage("W", `Error: ${err}`)
    }
}

function fusion_sendError(error) {
    try{
        fusion_sendMessage("E", `${error}\n${error.stack}`);
    } catch (err) {
        fusion_sendMessage("W", `Error: ${err}`);
    }
}

function fusion_encodeHex(byteArray) {
    
    const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
    const StringClass = Java.use('java.lang.String');
    const hexChars = HexClass.encodeHex(byteArray);
    return StringClass.$new(hexChars).toString();
    
}

function fusion_getB64StackTrace(){

    try{
        const StringClass = Java.use('java.lang.String');
        const Base64Class = Java.use('android.util.Base64');
        var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        trace = trace.replace("java.lang.Exception\n", "Stack trace:\n");
        var bTrace = StringClass.$new(trace).getBytes('utf-8');
        var b64Msg = Base64Class.encodeToString(bTrace, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        return b64Msg

    } catch (err) {
        fusion_sendMessage("W", `Error: ${err}`)
        return '';
    }
}

function fusion_printMethods(targetClass)
{
  var hook = Java.use(targetClass);
  var ownMethods = hook.class.getDeclaredMethods();
  ownMethods.forEach(function(s) {
    fusion_sendMessage('I', s);
  });
}


//java.lang.Class
function fusion_getClassName(obj)
{
  if (obj === null || obj === undefined) return "";

  try {
        // Caso seja um objeto Java real
        if (obj.$className !== undefined) {
            // Objetos instanciados via Java.use
            var name = obj.$className;
            if (name == "java.lang.Class") return obj.getName();
            return name;
        }

        // Caso seja uma instância Java (não necessariamente via Java.use)
        if (typeof obj === 'object' && typeof obj.getClass === 'function') {
            var name = obj.getClass().getName();
            if (name == "java.lang.Class" && typeof obj.getClass === 'function') return obj.getName();
            return name;
        }

        // Caso seja uma classe Java carregada (Java.use)
        if (typeof obj === 'object' && obj.class !== undefined ) {
            var name = obj.class.getName();
            if (name == "java.lang.Class" && typeof obj.getClass === 'function') return obj.getName();
            return name;
        }

        // Se for algo não Java, apenas retorna tipo do JS
        return typeof obj;
    } catch (err) {
        fusion_sendMessage("W", `Error: ${err}\n${err.stack}`)
        return '';
    }

}

function fusion_getFieldValue(obj, fieldName) {
  if (obj === null || obj === undefined) return "";
  try {
    var cls = obj.getClass();
    while (cls != null) {
      try {
        var f = cls.getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(obj);
      } catch (e) {
        cls = cls.getSuperclass();
      }
    }
  } catch (err) {
      fusion_sendMessage("W", `Error: ${err}`)
      return '';
  }
}


function fusion_getReadableRange(p) {
  try { p = ptr(p); } catch (_) { return null; }
  const range = Process.findRangeByAddress(p); // não lança exceção
  if (!range) return null;
  // range.protection exemplo: 'r-x', 'rw-'
  return range.protection.indexOf('r') !== -1 ? range : null;
}

function fusion_isAddressReadable(p) {
  const r = fusion_getReadableRange(p);
  if (!r) return false;
  // tenta ler 1 byte para confirmar acessibilidade
  try { Memory.readU8(ptr(p)); return true; }
  catch (_) { return false; }
}

function fusion_describeAddress(p) {
  try { p = ptr(p); } catch (_) { return { ok:false, reason:'not a pointer' }; }
  if (Process.arch === 'arm64') p = p.and('0x00FFFFFFFFFFFFFF'); // remove top byte
  if (!fusion_isAddressReadable(p)) return { ok:false, reason:'invalid pointer' };
  const range = Process.findRangeByAddress(p);
  if (!range) return { ok:false, reason:'unmapped' };
  return {
    ok: true,
    base: range.base,
    size: range.size,
    protection: range.protection,
    file: range.file ? range.file.path : null
  };
}


Java.perform(function () {
  const Thread = Java.use('java.lang.Thread');
  const UEH = Java.registerClass({
    name: 'br.com.sec4us.UehProxy',
    implements: [Java.use('java.lang.Thread$UncaughtExceptionHandler')],
    methods: {
      uncaughtException: [{
        returnType: 'void',
        argumentTypes: ['java.lang.Thread', 'java.lang.Throwable'],
        implementation: function (t, e) {
          try {
            const Throwable = Java.use('java.lang.Throwable');
            const sw = Java.use('java.io.StringWriter').$new();
            const pw = Java.use('java.io.PrintWriter').$new(sw);
            Throwable.$new(e).printStackTrace(pw);
            send({ type: 'java-uncaught', thread: t.getName(), stack: sw.toString() });
          } catch (err) { send({ type: 'java-uncaught-error', err: err+'' }); }
          // Opcional: impedir que o app morra? Não é garantido; normalmente o processo cai.
        }
      }]
    }
  });

  // Define globalmente
  Thread.setDefaultUncaughtExceptionHandler(UEH.$new());
});

function fusion_formatBacktrace(frames) {
  return frames.map((addr, i) => {
    const sym = DebugSymbol.fromAddress(addr);
    const mod = Process.findModuleByAddress(addr);
    const off = (mod && addr.sub(mod.base)) ? "0x" + addr.sub(mod.base).toString(16) : String(addr);
    const name = (sym && sym.name) ? sym.name : "<unknown>";
    const modname = mod ? mod.name : "<unknown>";
    return `${i.toString().padStart(2)}  ${name} (${modname}+${off})`;
  });
}

Process.setExceptionHandler(function (details) {
  let frames;
  try {
    frames = Thread.backtrace(details.context, Backtracer.ACCURATE);
  } catch (e) {
    frames = Thread.backtrace(details.context, Backtracer.FUZZY);
  }

  const pretty = fusion_formatBacktrace(frames);

  send({
    type: "native-exception",
    details: {
      message: details.message,
      type: details.type,
      address: String(details.address),
      memory: details.memory,
      context: details.context,
      nativeContext: String(details.nativeContext),
      backtrace: pretty,                 // <— pilha simbólica
      backtrace_raw: frames.map(String)  // <— opcional: endereços puros
    }
  });

  // true = tenta engolir a exceção; se quiser ver o processo cair, retorne false
  return false;
});

fusion_sendMessage("W", "Helper functions have been successfully initialized.")