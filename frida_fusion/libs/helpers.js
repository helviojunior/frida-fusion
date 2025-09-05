/*  Android Scripts
    Author: Hélvio - M4v3r1ck
*/


function waitForClass(name, onReady) {
    var intv = setInterval(function () {
      try {
        var C = Java.use(name);
        clearInterval(intv);
        onReady(C);
      } catch (e) { /* ainda não carregou */ }
    }, 100);
}

function printStackTrace(){
    var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    trace = trace.replace("java.lang.Exception\n", "Stack trace:\n");
    sendMessage("*", trace);
}

function toBytes(message){
    try{
        const StringClass = Java.use('java.lang.String');
        var bTxt = StringClass.$new(message).getBytes('utf-8');

        return bTxt;
    } catch (err) {
        sendMessage("*", err)
    }
}

function toBase64(message){
    try{
        const StringClass = Java.use('java.lang.String');
        const Base64Class = Java.use('android.util.Base64');
        var bTxt = StringClass.$new(message).getBytes('utf-8');
        var b64Msg = Base64Class.encodeToString(bTxt, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        return b64Msg;
    } catch (err) {
        sendMessage("*", err)
    }
}

function bytesToBase64(message){

    if (message === null || message === undefined) return "IA==";
    try {
        // 1) Confirma tipo byte[], se não tenta converter em string
        message = Java.array('byte', message);

        // 2) Tem 'length' numérico
        const len = message.length;
        if (typeof len !== "number") return "IA==";

        // 3) (opcional) Exigir conteúdo
        if (len === 0) return "IA==";

    } catch (e) {
        return "IA==";
    }

    try{
        
        const Base64Class = Java.use('android.util.Base64');
        var b64Msg = Base64Class.encodeToString(message, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        return b64Msg;
    } catch (err) {
        sendMessage("*", err)
        return "IA==";
    }
}

function getCallerInfo() {
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

        // Ignora funções cujo nome comece com "send" (qualquer case)
        if (/^send/i.test(func)) continue;
        if (/^isend/i.test(func)) continue;

        return { file_name: file, function_name: func, line: ln };
      }
    }
  } catch (err) {
    console.log(`Error: ${err}`)
  }
  return null;
}

function iSend(payload1, payload2){
    try{
        const info = getCallerInfo();
        send({
          payload: payload1,
          location: info
        }, payload2);
    } catch (err) {
        //sendMessage("*", err)
        console.log(`Error: ${err}`)
    }
}

function sendData(mType, jData, bData){
    //iSend('{"type" : "'+ mType +'", "jdata" : "'+ jData +'"}', bData);
    iSend({
      type: mType,
      jdata: jData
    }, bData)
}

function sendKeyValueData(module, items) {
    var st = getB64StackTrace();

    var data = [];

    // Force as String
    for (let i = 0; i < items.length; i++) {
        data = data.concat([{key: `${items[i].key}`, value:`${items[i].value}`}]);
    }

    iSend({
      type: "key_value_data",
      module: module,
      data: data,
      stack_trace: st
    }, null);


    /*
    var jData = `{"type" : "key_value_data", "module": "${module}", "data": [`;
    for (let i = 0; i < items.length; i++) {
        if (i > 0) {
            jData += `, `
        }
        jData += `{"key": "${items[i].key}", "value": "${items[i].value}"}`
    }
    jData += `], "stack_trace": "${st}"}`;
    iSend(jData, "");
    */
}

function sendMessage(level, message){
    try{
        const StringClass = Java.use('java.lang.String');
        const Base64Class = Java.use('android.util.Base64');
        var bTxt = StringClass.$new(message).getBytes('utf-8');
        var b64Msg = Base64Class.encodeToString(bTxt, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        //send('{"type" : "message", "level" : "'+ level +'", "message" : "'+ b64Msg +'"}');
        iSend({
          type: "message",
          level: level,
          message: b64Msg
        }, null)
    } catch (err) {
        sendMessage("*", err)
        //sendMessage('-', 'secret_key_spec.$init.overload error: ' + err + '\n' + err.stack);
    }
}

function sendError(error) {
    try{
        sendMessage("-", error + '\n' + error.stack);
    } catch (err) {
        sendMessage("*", err)
    }
}

function encodeHex(byteArray) {
    
    const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
    const StringClass = Java.use('java.lang.String');
    const hexChars = HexClass.encodeHex(byteArray);
    //sendMessage("*", StringClass.$new(hexChars).toString());
    //Buffer.from(bufStr, 'utf8');
    //sendMessage("*", new Uint8Array(byteArray));
    return StringClass.$new(hexChars).toString();
    
}

function getB64StackTrace(){

    try{
        const StringClass = Java.use('java.lang.String');
        const Base64Class = Java.use('android.util.Base64');
        var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        trace = trace.replace("java.lang.Exception\n", "Stack trace:\n");
        var bTrace = StringClass.$new(trace).getBytes('utf-8');
        var b64Msg = Base64Class.encodeToString(bTrace, 0x00000002); //Base64Class.NO_WRAP = 0x00000002

        return b64Msg

    } catch (err) {
        sendMessage("*", err);
        return '';
    }
}

function enumMethods(targetClass)
{
  var hook = Java.use(targetClass);
  var ownMethods = hook.class.getDeclaredMethods();
  hook.$dispose;

  return ownMethods;
}

function printMethods(hook)
{
  var ownMethods = hook.class.getDeclaredMethods();
  ownMethods.forEach(function(s) { 
    //sendMessage(s);
    sendMessage('*', s);
  });

}

function intToHex(intVal)
{
    return intVal.toString(16);
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

function formatBacktrace(frames) {
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

  const pretty = formatBacktrace(frames);

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

sendMessage("W", "Helper functions have been successfully initialized.")