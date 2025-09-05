/*  Frida Fusion helper functions
    Author: Helvio Junior - M4v3r1ck
*/

function fusion_Send(payload1, payload2){
    const info = fusion_getCallerInfo();
    send({
      payload: payload1,
      location: info
    }, payload2);
}

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
        fusion_sendMessage("W", err)
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
        fusion_sendMessage("W", err)
    }
}

function fusion_sendError(error) {
    try{
        fusion_sendMessage("E", error + '\n' + error.stack);
    } catch (err) {
        fusion_sendMessage("W", err)
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
        fusion_sendMessage("W", err);
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

function fusion_getClassName(obj)
{
  if (obj === null || obj === undefined) return "";

  try {
        // Caso seja um objeto Java real
        if (obj.$className !== undefined) {
            // Objetos instanciados via Java.use
            return obj.$className;
        }

        // Caso seja uma instância Java (não necessariamente via Java.use)
        if (Java.isJavaObject(obj)) {
            return obj.getClass().getName();
        }

        // Caso seja uma classe Java carregada (Java.use)
        if (Java.isJavaClass(obj)) {
            return obj.class.getName();
        }

        // Se for algo não Java, apenas retorna tipo do JS
        return typeof obj;
    } catch (err) {
        fusion_sendMessage("W", err);
        return '';
    }

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