const OKHTTP_LOGGING_DATA = {
    CURRENT_LEVEL: 'BODY',
    headersToRedact: new Set(),     // ex: Authorization, Cookie
    queryParamsToRedact: new Set(), // ex: token, password
    OkioTypes: null,
    __gateMap: null,
};

setTimeout(function() { // avoid java.lang.ClassNotFoundException

    /*
    // ---------- RPC para controle em runtime ----------
    rpc.exports = {
      setlevel: function(lvl) {
        const L = String(lvl || '').toUpperCase();
        if (['NONE','BASIC','HEADERS','BODY','STREAMING'].indexOf(L) >= 0) {
          OKHTTP_LOGGING_DATA.CURRENT_LEVEL = L;
          fusion_sendMessage('I', 'Level = ' + OKHTTP_LOGGING_DATA.CURRENT_LEVEL);
          return true;
        }
        return false;
      },
      redactheader: function(name) {
        if (!name) return false;
        OKHTTP_LOGGING_DATA.headersToRedact.add(String(name));
        fusion_sendMessage('I', 'Header redatado: ' + name);
        return true;
      },
      clearredactheaders: function() {
        OKHTTP_LOGGING_DATA.headersToRedact.clear();
        fusion_sendMessage('I', 'Headers a redatar: limpos');
        return true;
      },
      redactqueryparams: function(arr) {
        try {
          if (Array.isArray(arr)) {
            arr.forEach(n => OKHTTP_LOGGING_DATA.queryParamsToRedact.add(String(n)));
            fusion_sendMessage('I', 'Query params redatados: ' + arr.join(', '));
            return true;
          }
        } catch (_) {}
        return false;
      },
      clearredactqueryparams: function() {
        OKHTTP_LOGGING_DATA.queryParamsToRedact.clear();
        fusion_sendMessage('I', 'Query params a redatar: limpos');
        return true;
      }
    };
    */

    Java.perform(() => {

        if (FF_OKHTTP_LOGGING_LEVEL != null && FF_OKHTTP_LOGGING_LEVEL != undefined) {
            const L = String(FF_OKHTTP_LOGGING_LEVEL || '').toUpperCase();
            if (['NONE', 'BASIC', 'HEADERS', 'BODY', 'STREAMING'].indexOf(L) >= 0) {
                OKHTTP_LOGGING_DATA.CURRENT_LEVEL = L;
            }
        }

        OKHTTP_LOGGING_DATA.__gateMap = Java.use('java.util.WeakHashMap').$new();

        function firstTimeForCall(chain) {
          try {
            if (!chain.call) return true; // OkHttp 2 fallback
            const call = chain.call();
            const Bool = Java.use('java.lang.Boolean');
            if (OKHTTP_LOGGING_DATA.__gateMap.containsKey(call)) return false;
            OKHTTP_LOGGING_DATA.__gateMap.put(call, Bool.$new(true));
            return true;
          } catch (_) { return true; }
        }

        // ---------- MAIN ----------
        const Ok3Request = fusion_useOrNull('okhttp3.Request');
        const Ok2Request = fusion_useOrNull('com.squareup.okhttp.Request');
        const Ok3RequestBody = fusion_useOrNull('okhttp3.RequestBody');
        const Ok2RequestBody = fusion_useOrNull('com.squareup.okhttp.RequestBody');
        const Ok3Response = fusion_useOrNull('okhttp3.Response');
        const Ok2Response = fusion_useOrNull('com.squareup.okhttp.Response');
        const Ok3Headers = fusion_useOrNull('okhttp3.Headers');
        const Ok2Headers = fusion_useOrNull('com.squareup.okhttp.Headers');
        const Ok3MediaType = fusion_useOrNull('okhttp3.MediaType');
        const Ok2MediaType = fusion_useOrNull('com.squareup.okhttp.MediaType');

        const Ok3HttpUrl = fusion_useOrNull('okhttp3.HttpUrl');
        const Ok2HttpUrl = fusion_useOrNull('com.squareup.okhttp.HttpUrl');

        const Ok3Interceptor = fusion_useOrNull('okhttp3.Interceptor');
        const Ok2Interceptor = fusion_useOrNull('com.squareup.okhttp.Interceptor');

        const Ok3ClientBuilder = fusion_useOrNull('okhttp3.OkHttpClient$Builder');
        const Ok2ClientBuilder = fusion_useOrNull('com.squareup.okhttp.OkHttpClient');

        const isOkHttp3 = !!Ok3Request && !!Ok3Interceptor;
        const isOkHttp2 = !!Ok2Request && !!Ok2Interceptor;

        const OkioBuffer =
          fusion_useOrNull('okio.Buffer') ||
          fusion_useOrNull('com.android.okhttp.okio.Buffer');

        const OkioBufferedSink =
          fusion_useOrNull('okio.BufferedSink') ||
          fusion_useOrNull('com.android.okhttp.okio.BufferedSink');

        const OkioGzipSource =
          fusion_useOrNull('okio.GzipSource') ||
          fusion_useOrNull('com.android.okhttp.okio.GzipSource');

        const OkioBufferedSource =
          fusion_useOrNull('okio.BufferedSource') ||
          fusion_useOrNull('com.android.okhttp.okio.BufferedSource');

        if (!OkioBuffer) {
            fusion_sendMessageWithTrace('E', 'Erro: okio.Buffer não encontrado.');
            return;
        }

        if (!isOkHttp3 && !isOkHttp2) {
            fusion_sendMessageWithTrace('E', 'Erro: nenhuma variante do OkHttp encontrada (v2 ou v3/4).');
            return;
        }

        const OKIO_SINK_SIG = OkioBufferedSink
          ? OkioBufferedSink.$className // "okio.BufferedSink" ou "com.android.okhttp.okio.BufferedSink"
          : 'okio.BufferedSink';

        const Request = Ok3Request || Ok2Request;
        const RequestBody = Ok3RequestBody || Ok2RequestBody;
        const Response = Ok3Response || Ok2Response;
        const Headers = Ok3Headers || Ok2Headers;
        const MediaType = Ok3MediaType || Ok2MediaType;
        const HttpUrl = Ok3HttpUrl || Ok2HttpUrl;
        const Interceptor = Ok3Interceptor || Ok2Interceptor;

        // ---------- Nosso Interceptor em JS ----------
        const MyInterceptor = Java.registerClass({
            name: 'com.stratasec.HttpLoggingInterceptor',
            implements: [Interceptor],
            methods: {
                // OkHttp: Response intercept(Interceptor.Chain)
                intercept: function(chain) {
                    const level = OKHTTP_LOGGING_DATA.CURRENT_LEVEL;
                    let response;
                    let proceeded = false;
                    try {
                        // Usage in your intercept(chain):
                        const first = firstTimeForCall(chain);
                        if (!first) return chain.proceed(chain.request());

                        const request = chain.request();
                        if (level === Level.NONE) {
                            return chain.proceed(request);
                        }

                        // ... do your logging once ...

                        const TimeUnit = Java.use('java.util.concurrent.TimeUnit');
                        const System   = Java.use('java.lang.System');

                        const logHeaders = shouldLogHeaders(level);
                        const reqBody = (request.body ? request.body() : request.body) || null;
                        const conn = (chain.connection ? chain.connection() : null);
                        const proto = (conn && conn.protocol) ? (' ' + conn.protocol()) : '';

                        var requestBodyOk = true;

                        var data = [
                            {key: "Method", value: request.method()},
                            {key: "Url", value: redactUrl(request.url())},
                            {key: "Protocol", value: (proto || '')}
                        ];

                        let ok = resolveOkioTypes(reqBody);

                        if (level !== Level.BASIC) {
                            // headers de request
                            if (logHeaders) {
                                var headerText = '';
                                try {
                                    const headers = request.headers();
                                    if (reqBody) {
                                        // Content-Type/Length forçados se ausentes
                                        try {
                                            const ct = reqBody.contentType ? reqBody.contentType() : null;
                                            if (ct && headers.get && headers.get('Content-Type') === null) {
                                                headerText += 'Content-Type: ' + ct.toString() + '\r\n';
                                            }
                                        } catch (_) {}
                                        try {
                                            const cl = reqBody.contentLength ? reqBody.contentLength() : -1;
                                            if (cl !== -1 && headers.get && headers.get('Content-Length') === null) {
                                                headerText += 'Content-Length: ' + cl + '\r\n';
                                            }
                                        } catch (_) {}
                                    }
                                    const size = headers.size ? headers.size() : 0;
                                    for (let i = 0; i < size; i++) {
                                        headerText += headers.name(i) + ': ' + headerValue(headers, i) + '\r\n';
                                    }
                                } catch (e) {
                                    fusion_sendMessage('I', `Error reading request headers: ${e}`);
                                }
                                data = data.concat([
                                    {key: "Request-Header", value: headerText}
                                ]);
                            }

                            if (level === Level.BODY) {
                                try {
                                    const h = request.headers ? request.headers() : null;
                                    let encoding = null;
                                    try {
                                        encoding = h ? h.get('Content-Encoding') : null;
                                    } catch (_) {}

                                    data = data.concat([
                                        {key: "Request-Content-Encoding", value: encoding}
                                    ]);

                                    const out = dumpRequestBody(reqBody);
                                    if (out.err) {
                                        //fusion_sendMessageWithTrace('W', 'Erro dumpRequestBody: ' + out.err);
                                        requestBodyOk = false;
                                    }

                                    if (out.b64_data) {
                                        let cl = -1;
                                        try {
                                            cl = reqBody.contentLength();
                                        } catch (_) {}

                                        data = data.concat([
                                            {key: "Request-Content-Length", value: cl},
                                            {key: "Request-Body", value: out.b64_data}
                                        ]);
                                    }
                                
                                } catch (e) {
                                    fusion_sendMessage('I', 'Falha BODY request: ' + e);
                                }
                            }
                        }

                        const start = Java.use('java.lang.System').nanoTime();
                        
                        try {
                            proceeded = true;
                            response = chain.proceed(request);
                        } catch (ex) {

                            if (!requestBodyOk) {
                                const out = dumpRequestBody(reqBody);
                                if (out.b64_data) {
                                    let cl = -1;
                                    try {
                                        cl = reqBody.contentLength();
                                    } catch (_) {}

                                    data = data.concat([
                                        {key: "Request-Content-Length", value: cl},
                                        {key: "Request-Body", value: out.b64_data}
                                    ]);
                                }
                            }

                            const elapsed = TimeUnit.toMillis.overload('long')
                              .call(TimeUnit.NANOSECONDS.value, System.nanoTime() - start);

                            data = data.concat([
                                {key: "Error", value: `${ex}`},
                                {key: "Elapsed-Time", value: elapsed}
                            ]);

                            fusion_sendKeyValueData("okhttp!intercept", data);
                            throw ex;
                        }

                        if (!requestBodyOk) {
                            const out = dumpRequestBody(reqBody);
                            if (out.b64_data) {
                                let cl = -1;
                                try {
                                    cl = reqBody.contentLength();
                                } catch (_) {}

                                data = data.concat([
                                    {key: "Request-Content-Length", value: cl},
                                    {key: "Request-Body", value: out.b64_data}
                                ]);
                            }
                        }

                        if (!OKHTTP_LOGGING_DATA.OkioTypes) {
                            ok = resolveOkioTypes(reqBody);
                        }

                        const tookMs = TimeUnit.toMillis.overload('long')
                          .call(TimeUnit.NANOSECONDS.value, System.nanoTime() - start);

                        const respBody = response.body();
                        let contentLength = -1;
                        try {
                            contentLength = respBody ? respBody.contentLength() : -1;
                        } catch (_) {}

                        data = data.concat([
                            {key: "Response-Content-Length", value: contentLength},
                            {key: "Response-Code", value: response.code()},
                            {key: "Elapsed-Time", value: tookMs}
                        ]);

                        try {
                            const msg = response.message ? response.message() : '';
                            data = data.concat([
                                {key: "Response-Status", value: msg}
                            ]);
                        } catch (_) {}

                        if (level !== Level.BASIC) {
                            // headers de response
                            if (logHeaders) {
                                var headerText = '';
                                try {
                                    const rh = response.headers();
                                    const rsize = rh.size ? rh.size() : 0;
                                    for (let i = 0; i < rsize; i++) {
                                        headerText += rh.name(i) + ': ' + headerValue(rh, i) + "\r\n";
                                    }
                                } catch (e) {
                                    fusion_sendMessage('I', 'Fail reading response header: ' + e);
                                }
                                data = data.concat([
                                    {key: "Response-Header", value: headerText}
                                ]);
                            }

                            // BODY / STREAMING
                            if (level === Level.BODY) {
                                try {
                                    // Event-stream?
                                    try {
                                        const ct = respBody && respBody.contentType ? respBody.contentType() : null;
                                        if (ct && ct.type && ct.subtype &&
                                            ct.type().toString() === 'text' &&
                                            ct.subtype().toString() === 'event-stream') {
                                            fusion_sendKeyValueData("okhttp!intercept", data);
                                            return response;
                                        }
                                    } catch (_) {}

                                    // unknown encoded?
                                    let enc = null;
                                    try {
                                        enc = response.header ? response.header('Content-Encoding') : null;
                                    } catch (_) {}
                                    
                                    data = data.concat([
                                        {key: "Response-Content-Encoding", value: enc}
                                    ]);

                                    const out = dumpResponseBody(response);
                                    if (out.err) {
                                        fusion_sendMessageWithTrace('W', 'Erro dumpRequestBody: ' + out.err);
                                        data = data.concat([
                                            {key: "Error", value: `Erro dumpResponseBody: ${out.err}`}
                                        ]);
                                    }

                                    if (out.b64_data) {
                                        data = data.concat([
                                            {key: "Response-Body", value: out.b64_data}
                                        ]);
                                    }

                                    //Create new response
                                    ok = OKHTTP_LOGGING_DATA.OkioTypes;
                                    fusion_sendKeyValueData("okhttp!intercept", data);
                                    return ok.buildNewResponseWithBody(response, out.bytes);

                                } catch (e) {
                                    fusion_sendMessage('I', `Response body fail: ${e} \n${e.stack}`)
                                }
                            }
                        }

                        fusion_sendKeyValueData("okhttp!intercept", data);

                        return response;
                    } catch (e) {
                        fusion_sendMessage("W", `Interceptor error: ${e} \n${e.stack}`)
                        throw e;
                    }
                }
            }
        });
        // ---------- Final interceptor ----------

        // ---------- Injeção no OkHttpClient.Builder ----------
        if (isOkHttp3 && Ok3ClientBuilder) {
            // Hook build(): antes de construir, adiciona nosso interceptor app-level e network-level
            Ok3ClientBuilder.build.implementation = function() {
                try {
                    const list = this.interceptors();
                    // Evita duplicar
                    let has = false;
                    for (let i = 0; i < list.size(); i++) {
                        const it = list.get(i);
                        if (it && String(it.$className) === 'com.stratasec.HttpLoggingInterceptor') {
                            has = true;
                            //break;
                        }else{
                            fusion_sendKeyValueData("okhttp!intercept!interceptors", [
                                {key: "Index", value: i},
                                {key: "Type", value: "interceptor"},
                                {key: "InterceptorClass", value: fusion_getClassName(it)},
                            ]);
                        }
                    }
                    if (!has){
                        // addInterceptor
                        try {
                            //this.addInterceptor(MyInterceptor.$new());
                        } catch (_) {}
                    }

                } catch (e) {
                    fusion_sendMessageWithTrace("E", `Error creating app-level interceptor (OkHttp3): ${e}`)
                }

                try {
                    
                    const list = this.networkInterceptors();
                    // Evita duplicar
                    let has = false;
                    for (let i = 0; i < list.size(); i++) {
                        const it = list.get(i);
                        if (it && String(it.$className) === 'com.stratasec.HttpLoggingInterceptor') {
                            has = true;
                            //break;
                        }else{
                            fusion_sendKeyValueData("okhttp!intercept!interceptors", [
                                {key: "Index", value: i},
                                {key: "Type", value: "networkInterceptor"},
                                {key: "InterceptorClass", value: fusion_getClassName(it)},
                            ]);
                        }
                    }
                    if (!has){
                        // addNetworkInterceptor (se quiser também no nível de rede)
                        try {
                            this.addNetworkInterceptor(MyInterceptor.$new());
                        } catch (_) {}
                    }

                } catch (e) {
                    fusion_sendMessageWithTrace("E", `Error creating network-level interceptor (OkHttp3): ${e}`)
                }
                return this.build.call(this);
            };
            fusion_sendMessage("W", `Interceptor injected OkHttpClient$Builder.build()`)
        }

        if (isOkHttp2 && Ok2ClientBuilder) {
            // OkHttp2 não tem Builder da mesma forma; injete no cliente quando instanciado ou antes da call
            // Ex.: interceptar new OkHttpClient() e set interceptors; aqui usamos um truque comum:
            try {
                // Intercepta chamadas ao método 'open' de com.squareup.okhttp.OkHttpClient? (não ideal)
                // Alternativa: interceptar 'newCall' e, antes da call, garantir presence do interceptor.
                const Call = fusion_useOrNull('com.squareup.okhttp.Call');
                const OkHttpClient = Ok2ClientBuilder;

                // Sobrescreve newCall para forçar adicionar interceptors antes
                if (OkHttpClient && OkHttpClient.newCall) {
                    OkHttpClient.newCall.overload('com.squareup.okhttp.Request').implementation = function(req) {
                        try {
                            const list = this.interceptors();
                            // Evita duplicar
                            let has = false;
                            for (let i = 0; i < list.size(); i++) {
                                const it = list.get(i);
                                if (it && String(it.$className) === 'com.stratasec.HttpLoggingInterceptor') {
                                    has = true;
                                    break;
                                }
                            }
                            if (!has) list.add(myInterceptorInstance);
                        } catch (e) {
                            fusion_sendMessageWithTrace("E", `Error creating interceptor (OkHttp2): ${e}`)
                        }
                        return this.newCall.call(this, req);
                    };
                    fusion_sendMessage("W", `Interceptor injected at OkHttp2 via OkHttpClient.newCall()`);
                }
            } catch (e) {
                fusion_sendMessageWithTrace("E", `Error injecting (OkHttp2): ${e}`)
            }
        }

        // Internal functions

        // ---------- Níveis ----------
        const Level = {
            NONE: 'NONE',
            BASIC: 'BASIC',
            HEADERS: 'HEADERS',
            BODY: 'BODY',
            STREAMING: 'STREAMING'
        };

        // ---------- Heurística simples: conteúdo provavelmente UTF-8? ----------
        function isProbablyUtf8(fridaString) {
            // Se já veio como JS string, assumimos OK.
            // Em caso binário, você pode implementar checagens extras se necessário.
            if (typeof fridaString !== 'string') return false;
            return true;
        }

        // ---------- Util: leitura de RequestBody ----------
        function dumpRequestBody(body) {
            try {
                if (!body) return {
                    text: null,
                    size: -1
                };

                const ok = resolveOkioTypes(body);

                const RB = fusion_useOrNull(fusion_getClassName(body)) ||
                   fusion_useOrNull('okhttp3.RequestBody') ||
                   fusion_useOrNull('com.squareup.okhttp.RequestBody') ||
                   fusion_useOrNull('com.android.okhttp.RequestBody');

                const { out, bsink } = ok.makeBufferedSink();

                const paramSig = Java.cast(ok.BufferedSinkClass, Java.use('java.lang.Class')); // já é Class
                RB.writeTo.overload(paramSig.getName()).call(Java.cast(body, RB), bsink);

                // Flush antes de ler
                try { bsink.flush(); } catch (_) {}
                const bytes = out.toByteArray();
                const size = bytes.length;
                // Tenta charset via contentType
                let charset = 'UTF-8';
                try {
                    const ct = body.contentType ? body.contentType() : null;
                    if (ct && ct.toString && ct.toString().toLowerCase().indexOf('charset=') >= 0) {
                        // contentType().toString() geralmente contém "type/subtype; charset=xxx"
                        const m = /charset=([^;]+)/i.exec(ct.toString());
                        if (m && m[1]) charset = m[1].trim();
                    }
                } catch (_) {}

                return {
                    b64_data: fusion_bytesToBase64(bytes),
                    size: size
                };
            } catch (e) {
                return {
                    b64_data: null,
                    size: -1,
                    err: String(e) + '\n' + String(e.stack)
                };
            }
        }

        // ---------- Util: leitura de ResponseBody ----------
        function dumpResponseBody(resp) {
            try {
                const rb = resp.body();
                if (!rb) return {
                    b64_data: null,
                    size: -1,
                    replacer: null,
                };

                const ok = resolveOkioTypes(null, resp);
                if (!ok) return {
                    b64_data: null,
                    size: -1,
                    err: 'OKHTTP_LOGGING_DATA.OkioTypes is empty'
                };

                const buffer = ok.getBufferFromSource(rb.source());
                
                if (!buffer || buffer.used == 'none') return {
                    b64_data: null,
                    size: -1,
                    replacer: null,
                    err: 'Return buffer is empty'
                };

                return {
                    bytes: buffer.bytes,
                    b64_data: fusion_bytesToBase64(buffer.bytes),
                    size: buffer.bytes.length,
                };
            } catch (e) {

                return {
                    b64_data: null,
                    size: -1,
                    replacer: null,
                    err: String(e) + '\n' + String(e.stack)
                };
            }
        }

        // ---------- Redação de URL (query params) ----------
        function redactUrl(urlObj) {
            try {
                if (!urlObj) return '';
                if (OKHTTP_LOGGING_DATA.queryParamsToRedact.size === 0) return urlObj.toString();
                const builder = urlObj.newBuilder();
                // zera query e reinsere
                builder.query(null);
                const qs = urlObj.querySize ? urlObj.querySize() : 0;
                for (let i = 0; i < qs; i++) {
                    const name = urlObj.queryParameterName(i);
                    const val = urlObj.queryParameterValue(i);
                    const redact = OKHTTP_LOGGING_DATA.queryParamsToRedact.has(String(name));
                    builder.addEncodedQueryParameter(name, redact ? '██' : val);
                }
                return builder.toString();
            } catch (e) {
                // fallback bruto: substitui valores por regex simples
                try {
                    const s = urlObj ? urlObj.toString() : '';
                    if (OKHTTP_LOGGING_DATA.queryParamsToRedact.size === 0) return s;
                    let redacted = s;
                    OKHTTP_LOGGING_DATA.queryParamsToRedact.forEach(n => {
                        const re = new RegExp('([?&])(' + n + ')=([^&#]*)', 'ig');
                        redacted = redacted.replace(re, '$1$2=██');
                    });
                    return redacted;
                } catch (_) {
                    return String(urlObj);
                }
            }
        }

        // ---------- Redação de headers ----------
        function headerValue(headers, i) {
            const name = headers.name(i);
            const val = headers.value(i);
            return (OKHTTP_LOGGING_DATA.headersToRedact.has(String(name))) ? '***' : String(val);
        }

        function shouldLogHeaders(level) {
            return level === Level.BODY || level === Level.HEADERS;
        }


    });
}, 0);

// -------- resolver principal --------
function resolveOkioTypes(requestBody, responseBody) {
    const Result = {
        Okio: null,
        BufferedSinkClass: null, // ex.: "okio.g"
        BufferedSourceClass: null, // ex.: "okio.h"
        RealBufferedSourceClass: null, // ex.: "okio.x"
        BufferClass: null, // ex.: "okio.a"
        SourceIfaceClass: null, // iface interna, p/ ajudar a achar GzipSource
        SinkIfaceClass: null, // iface interna, opcional
        // factories prontos p/ criar instâncias coerentes com os tipos reais:
        makeBufferedSink: null,
        makeBufferedSource: null,
        getBufferedSourceFromSource: null,
        buildNewResponseWithBody: null,
    };

    if (OKHTTP_LOGGING_DATA.OkioTypes !== null) return OKHTTP_LOGGING_DATA.OkioTypes;

    if ((requestBody === null || requestBody === undefined) && (responseBody === null || responseBody === undefined)) return Result;

    const Obj = Java.use('java.lang.Object');
    const Cls = Java.use('java.lang.Class');
    const Method = Java.use('java.lang.reflect.Method');
    const ArrayRef = Java.use('java.lang.reflect.Array');
    const Modifier  = Java.use('java.lang.reflect.Modifier');
    const Arrays = Java.use('java.util.Arrays');
    const BAIS = Java.use('java.io.ByteArrayInputStream');
    const BAOS = Java.use('java.io.ByteArrayOutputStream');
    const JClass = Java.use('java.lang.Class');
    const getDeclaredConstructors = Cls.getDeclaredConstructors.overload();
    const isAssignableFrom = JClass.isAssignableFrom.overload('java.lang.Class');

    function withLoaderOf(obj, fn) {
        if (!obj) return null;
        const loader = Cls.getClassLoader.call(Obj.getClass.call(obj));
        const old    = Java.classFactory.loader;
        if (loader) Java.classFactory.loader = loader;
        try { return fn(); } finally { Java.classFactory.loader = old; }
    }

    function hasFieldAssignableTo(K, TargetClass /* java.lang.Class */) {
        if (!TargetClass) return false;
        try {
            const fs = Cls.getDeclaredFields.call(K);
            for (let i = 0; i < fs.length; i++) {
                const ft = fs[i].getType();
                if (ft.equals(TargetClass) || isAssignableFrom.call(TargetClass, ft) || isAssignableFrom.call(ft, TargetClass)) {
                    return true;
                }
            }
        } catch (_) {}
        return false;
    }

    // Chama um método sem argumentos via reflection e retorna o objeto Java resultante
    function callNoArgViaReflection(targetObj, methodName) {
        try {
            const Obj = Java.use('java.lang.Object');
            const Cls = Java.use('java.lang.Class');
            const RMethod = Java.use('java.lang.reflect.Method');

            // targetObj.getClass()
            const clazz = Obj.getClass.call(targetObj);

            // Tenta getMethod (público). Se falhar, tenta getDeclaredMethod + setAccessible(true)
            const getMethod = Cls.getMethod.overload('java.lang.String', '[Ljava.lang.Class;');
            const getDeclaredMethod = Cls.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;');
            let m;
            try {
                m = getMethod.call(clazz, methodName, Java.array('java.lang.Class', []));
            } catch (_) {
                m = getDeclaredMethod.call(clazz, methodName, Java.array('java.lang.Class', []));
                m.setAccessible(true);
            }

            // Method.invoke(target, Object... args) com zero args
            const invoke = RMethod.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');
            return invoke.call(m, targetObj, Java.array('java.lang.Object', [])); // pode retornar null
        } catch (e) {
            // seu logger aqui
            // slog('Reflection ' + methodName + ' falhou: ' + e);
            return null;
        }
    }

    function isStatic(m)      { return Modifier.isStatic(m.getModifiers()); }
    function params(m)        { return m.getParameterTypes(); }
    function returnOf(m)      { return m.getReturnType(); }
    function startsOkio(name) { return name && name.startsWith('okio.'); }
    function getMethodName(m) { try { return Java.cast(m.getName(), Java.use('java.lang.String')).toString(); } catch (_) { return '<n/a>'; } }

    function hasNoArgCtor(wrappedUse) {
        try {
            const k = wrappedUse.class;
            const ctors = getDeclaredConstructors.call(k);
            for (let i = 0; i < ctors.length; i++) {
                if (ctors[i].getParameterTypes().length === 0) return true;
            }
        } catch (_) {}
        return false;
    }

    function hasZeroArgClone(K) {
        try {
            const className = fusion_getClassName(K);
            const methods = Cls.getDeclaredMethods.call(Java.use(className).class);
            let mSameClass = false;
            for (let i = 0; i < methods.length; i++) {
                const m = methods[i];
                if (!m || !m.getParameterTypes) continue;
                const ps = params(m);
                if (ps.length !== 0) continue;
                if (isStatic(m)) continue;
                const r0 = fusion_getClassName(returnOf(m));
                const name = getMethodName(m);
                if (name === 'clone') return true; // metodo forte 'clone'
                if (r0 == className) mSameClass = true; // Metodo que retorne uma instancia da mesma classe
            }
            return mSameClass;
        } catch (_) {}
        return false;
    }

    //  ------------- 1) Liste classes okio.* -------------
    const okioClasses = Java.enumerateLoadedClassesSync().filter(n => n.startsWith('okio.'));

    //  ------------- 2) Resolve parameter -------------
    //  ---- 2.a) RequestBody.writeTo(...)
    function resolveWriteToParam(body) {
        return withLoaderOf(body, function () {
          const RB = Java.use('okhttp3.RequestBody')
                 || Java.use('com.squareup.okhttp.RequestBody')
                 || Java.use('com.android.okhttp.RequestBody');
          // pega o nome de classe do único parâmetro do overload writeTo
          for (const ov of RB.writeTo.overloads) {
            if (ov.argumentTypes.length === 1) {
              return ov.argumentTypes[0].className; // ex.: "okio.g" (BufferedSink ofuscado)
            }
          }
          return null;
        });
    }

    //  ---- 2.b) ResponseBody.source()
    function resolveSourceParam(body) {
        return withLoaderOf(body, function () {
          const RB = Java.use('okhttp3.ResponseBody')
                 || Java.use('com.squareup.okhttp.ResponseBody')
                 || Java.use('com.android.okhttp.ResponseBody');
          // pega o nome de classe do único parâmetro do overload source
          for (const ov of RB.source.overloads) {
            if (ov.argumentTypes.length === 0 && ov.returnType && ov.returnType.className) {
                return ov.returnType.className; // ex.: "okio.x" (BufferedSource ofuscado)
            }
          }
          return null;
        });
    }

    //  ------------- 3) Resolve okio.Okio -------------
    let Okio = fusion_useOrNull('okio.Okio')

    if (Okio == null) {
        // Ache a "Okio" (ofuscada): precisa ter métodos estáticos
        //    source(InputStream)->okio.*, sink(OutputStream)->okio.*, (Socket)->okio.*, (File)->okio.*
        //    e também ter 2 métodos estáticos 1-parâmetro que aceitam tipos okio.* e retornam okio.* (buffer de Source/Sink).
        let okioKlass = null, bufferedFromSource = null, bufferedFromSink = null;
        const okioCandidateClasses = new Set();
        const okioReturnOfSinkClasses = new Set();
        const okioReturnOfSourceClasses = new Set();

        // Try to resolve using RequestBody object
        if (Okio == null && (requestBody !== null || requestBody !== undefined)) {

            const writeToParamClassName = resolveWriteToParam(requestBody);
            if (!writeToParamClassName) fusion_sendMessage("D", 'RequestBody.writeTo(...) not found!')

            if (writeToParamClassName){

                for (const name of okioClasses) {
                    try {
                        //fusion_sendMessage('W', `name: ${name}`);

                        const W = Java.use(name); // wrapper
                        const K = W.class;
                        const methods = Cls.getDeclaredMethods.call(K);

                        for (let i = 0; i < methods.length; i++) {
                            const m = methods[i];

                            if (!isStatic(m)) continue;
                            const ps = params(m);
                            if (ps.length !== 1) continue;

                            const p0 = fusion_getClassName(ps[0]);
                            const r0 = fusion_getClassName(returnOf(m));

                            if (r0 == writeToParamClassName && startsOkio(p0)) {
                                okioCandidateClasses.add(name);
                                okioReturnOfSinkClasses.add(p0);
                            }
                        }

                    } catch (_) {}
                }

            }
        }

        // Try to resolve using ResponseBody object
        if (Okio == null && (responseBody !== null || responseBody !== undefined)) {
            const sourceReturnClassName = resolveSourceParam(responseBody);
            if (!sourceReturnClassName) fusion_sendMessage("D", 'ResposeBody.source() not found!')

            if (sourceReturnClassName) {

                for (const name of okioClasses) {
                    try {

                        const W = Java.use(name); // wrapper
                        const K = W.class;
                        const methods = Cls.getDeclaredMethods.call(K);

                        for (let i = 0; i < methods.length; i++) {
                            const m = methods[i];

                            if (!isStatic(m)) continue;
                            const ps = params(m);
                            if (ps.length !== 1) continue;

                            const p0 = fusion_getClassName(ps[0]);
                            const r0 = fusion_getClassName(returnOf(m));

                            if (r0 == sourceReturnClassName && startsOkio(p0)) {
                                okioCandidateClasses.add(name);
                                okioReturnOfSourceClasses.add(p0);
                            }
                        }

                    } catch (_) {}
                }

            }
        }

        for (const name of okioCandidateClasses) {
            try {
                const W = Java.use(name); // wrapper
                const K = W.class;
                const methods = Cls.getDeclaredMethods.call(K);

                // candidatos mínimos
                let candSource = null,
                    candSink = null;

                for (let i = 0; i < methods.length; i++) {
                    const m = methods[i];

                    if (!isStatic(m)) continue;
                    const ps = params(m);
                    if (ps.length !== 1) continue;

                    const p0 = fusion_getClassName(ps[0]);
                    const r0 = fusion_getClassName(returnOf(m));

                    if (p0 === 'java.io.InputStream' && startsOkio(r0)) {
                        if (okioReturnOfSourceClasses.size == 0 && okioReturnOfSinkClasses.size > 0) candSource = m;
                        okioReturnOfSourceClasses.forEach(n => {
                            if (r0 == n) candSource = m;
                        });
                    }
                    if (p0 === 'java.io.OutputStream' && startsOkio(r0)) {
                        if (okioReturnOfSourceClasses.size > 0 && okioReturnOfSinkClasses.size == 0) candSink = m;
                        okioReturnOfSinkClasses.forEach(n => {
                            if (r0 == n) candSink = m;
                        });
                    }

                }

                if (!candSource || !candSink) continue;

                // agora procure "buffer" equivalente: método estático 1-parâmetro
                // que aceite o TIPO de retorno de source/sink, e retorne okio.*
                const srcRet = returnOf(candSource);
                const snkRet = returnOf(candSink);

                for (let i = 0; i < methods.length; i++) {
                    const m = methods[i];
                    if (!isStatic(m)) continue;
                    const ps = params(m);
                    if (ps.length !== 1) continue;
                    const p0 = ps[0];
                    const r0 = returnOf(m);

                    if (!startsOkio(fusion_getClassName(r0))) continue;

                    try {
                        if (p0.isAssignableFrom(srcRet)) bufferedFromSource = m;
                    } catch (_) {}
                    try {
                        if (p0.isAssignableFrom(snkRet)) bufferedFromSink = m;
                    } catch (_) {}
                }

                if (bufferedFromSource && bufferedFromSink) {
                    okioKlass = K;
                    break;
                }

            } catch (_) {}
        }

        if (okioKlass) Okio = okioKlass
    }

    if (!Okio) throw new Error('Okio util class (ofuscada) não encontrada.');

    const okioClassName = fusion_getClassName(Okio);
    Result.Okio = Java.use(okioClassName);

    // ------------- 4) descobrir iface Source/Sink reais via métodos estáticos -------------
    // source(InputStream) -> Source (iface ofuscada)
    // sink(OutputStream)  -> Sink   (iface ofuscada)
    const dummyIn = BAIS.$new(Java.array('byte', []));
    const dummyOut = BAOS.$new();

    // ache qualquer método estático 1-parâmetro que aceite InputStream e retorne algo de okio.*
    const methods = Cls.getDeclaredMethods.call(Result.Okio.class); // [Method...]

    let sourceFactory = null; // Method
    let sinkFactory = null; // Method
    let bufferedFromSource = null; // Method (buffer(Source) -> BufferedSource)
    let bufferedFromSink = null; // Method (buffer(Sink)   -> BufferedSink)

    // 4.a) procure 'source(InputStream)'
    for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        try {
            if (!m || !m.getParameterTypes) continue;
            const ps = params(m);
            if (ps.length !== 1) continue;
            const p0 = fusion_getClassName(ps[0]);
            if (p0 === 'java.io.InputStream') {
                const ret = fusion_getClassName(returnOf(m));
                if (startsOkio(ret)) {
                    sourceFactory = m; // candidato
                    break;
                }
            }
        } catch (_) {}
    }

    // 4.b) procure 'sink(OutputStream)'
    for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        try {
            if (!m || !m.getParameterTypes) continue;
            const ps = params(m);
            if (ps.length !== 1) continue;
            const p0 = fusion_getClassName(ps[0]);
            if (p0 === 'java.io.OutputStream') {
                const ret = fusion_getClassName(returnOf(m));
                if (startsOkio(ret)) {
                    sinkFactory = m;
                    break;
                }
            }
        } catch (_) {}
    }

    if (!sourceFactory || !sinkFactory) {
        throw new Error('Não foi possível resolver Okio.source/sink por reflection.');
    }

    // 4.c) instancie um Source/Sink reais
    const Method_invoke = Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');
    const srcObj = Method_invoke.call(sourceFactory, null, Java.array('java.lang.Object', [dummyIn])); // okio.Source impl
    const sinkObj = Method_invoke.call(sinkFactory, null, Java.array('java.lang.Object', [dummyOut])); // okio.Sink impl

    const srcKlass = Java.use('java.lang.Object').getClass.call(srcObj); // java.lang.Class
    const sinkKlass = Java.use('java.lang.Object').getClass.call(sinkObj);

    // 4.d) agora ache os "buffer(...)" correspondentes
    for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        const ps = params(m);
        if (ps.length !== 1) continue;
        const p0 = ps[0];
        // testamos se aceita Source
        try {
            if (p0.isAssignableFrom(srcKlass)) {
                bufferedFromSource = m;
            }
        } catch (_) {}
        // testamos se aceita Sink
        try {
            if (p0.isAssignableFrom(sinkKlass)) {
                bufferedFromSink = m;
            }
        } catch (_) {}
    }

    if (!bufferedFromSource || !bufferedFromSink) {
        throw new Error('Não foi possível achar Okio.buffer(Source|Sink) dinamicamente.');
    }

    // 4.e) tipos de retorno dessas chamadas são as ifaces BufferedSource / BufferedSink (ofuscadas)
    Result.BufferedSourceClass = returnOf(bufferedFromSource); // java.lang.Class
    Result.BufferedSinkClass = returnOf(bufferedFromSink); // java.lang.Class

    // 4.f) derive também as ifaces brutas Source / Sink (tipos de retorno de source()/sink())
    Result.SourceIfaceClass = returnOf(sourceFactory); // java.lang.Class de okio.Source (ofuscado)
    Result.SinkIfaceClass = returnOf(sinkFactory); // java.lang.Class de okio.Sink   (ofuscado)

    // ------------- 5) resolver okio.Buffer -------------
    // okio.Buffer é a classe que IMPLEMENTA tanto BufferedSource quanto BufferedSink e possui ctor vazio.
    const loaded = Java.enumerateLoadedClassesSync().filter(n => n.startsWith('okio.'));

    for (const name of loaded) {
        //try {
            const W = Java.use(name);
            const K = W.class;

            // deve implementar as duas ifaces (BufferedSource e BufferedSink)
            const implSource = isAssignableFrom.call(Result.BufferedSourceClass, K);
            const implSink   = isAssignableFrom.call(Result.BufferedSinkClass,   K);
            if (!implSource || !implSink) continue;

            // precisa de construtor vazio
            if (!hasNoArgCtor(W)) continue;

            // heurística extra útil: ter clone()
            if (!hasZeroArgClone(K)) {
                // não é obrigatório em todos os builds, mas ajuda a evitar falsos positivos;
                // comente este 'continue' se quiser ser menos restritivo:
                continue;
            }

            // bingo: é o Buffer
            Result.BufferClass = K;         // java.lang.Class de okio.Buffer (ofuscado)
            fusion_sendMessage('D', `Resolved BufferClass: ${name}`);
            break;
        //} catch (_) {}
    }

    if (!Result.BufferClass) {
        fusion_sendMessage('D', 'Aviso: BufferClass não encontrado (pode não estar carregado ainda).');
        throw new Error('BufferClass não encontrado dinamicamente.');
    }

    // ------------- 6) resolver RealBufferedSource -------------
    for (const name of loaded) {
        try {
            const W = Java.use(name);
            const K = W.class;

            // deve implementar BufferedSource...
            const isBufferedSource = isAssignableFrom.call(Result.BufferedSourceClass, K);
            if (!isBufferedSource) continue;

            // ...e NÃO implementar BufferedSink (para não pegar okio.Buffer)
            const isAlsoBufferedSink = isAssignableFrom.call(Result.BufferedSinkClass, K);
            if (isAlsoBufferedSink) continue;

            // requer ctor(Source)
            if (hasNoArgCtor(W)) continue;

            // heurísticas extras úteis em builds ofuscados:
            const hasSourceField = hasFieldAssignableTo(K, Result.SourceIfaceClass);
            const hasBufferField = hasFieldAssignableTo(K, Result.BufferClass || null);

            if (hasSourceField || hasBufferField) {
                Result.RealBufferedSourceClass = K;           // java.lang.Class de okio.RealBufferedSource (ofuscado)
                fusion_sendMessage('D', `Resolved RealBufferedSource: ${name}`);
                break;
            }
        } catch (_) {}
    }

    if (!Result.RealBufferedSourceClass) {
        fusion_sendMessage('D', 'Aviso: RealBufferedSource não encontrado (pode não estar carregado ainda).');
        throw new Error('RealBufferedSource não encontrado dinamicamente.');
    }

    fusion_sendMessage('D', 'Resolved BufferClass        :     ' + fusion_getClassName(Result.BufferClass));
    fusion_sendMessage('D', 'Resolved BufferedSourceClass:     ' + fusion_getClassName(Result.BufferedSourceClass));
    fusion_sendMessage('D', 'Resolved RealBufferedSourceClass: ' + fusion_getClassName(Result.RealBufferedSourceClass));
    fusion_sendMessage('D', 'Resolved BufferedSinkClass:       ' + fusion_getClassName(Result.BufferedSinkClass));
    fusion_sendMessage('D', 'Resolved SourceIfaceClass:        ' + fusion_getClassName(Result.SourceIfaceClass));
    fusion_sendMessage('D', 'Resolved SinkIfaceClass:          ' + fusion_getClassName(Result.SinkIfaceClass));

    // ------------- 8) factories p/ criar instâncias coerentes -------------
    // Sempre retornam um objeto + estado para leitura posterior (bytes/string)

    const MethodBufferFromSource = bufferedFromSource; // Okio.buffer(Source)->BufferedSource
    const MethodBufferFromSink = bufferedFromSink; // Okio.buffer(Sink)->BufferedSink

    function readJavaInputStreamFully(is, size) {

        if (size === null || size === undefined || size <= 0) size = 8192;

        const BAIS = Java.use('java.io.ByteArrayInputStream');
        const baos = BAOS.$new(); // presume BAOS = Java.use('java.io.ByteArrayOutputStream')
        const bufArr = Java.array('byte', new Array(size).fill(0));

        const W = Java.use(fusion_getClassName(is));
        const K = W.class;

        // 1) se possível, marque o início
        let marked = false;
        try {
            if (is.markSupported && is.markSupported()) {
                // readlimit grande para permitir reset após leitura completa
                is.mark(0x7fffffff); // Integer.MAX_VALUE
                marked = true;
            }
        } catch (_) {}

        // 2) drena todo o stream (mantendo-o aberto)
        const readB = is.read.overload('[B');
        const writeB = baos.write.overload('[B', 'int', 'int');
        let n;
        while ((n = readB.call(is, bufArr)) !== -1) {
            writeB.call(baos, bufArr, 0, n);
        }

        const bytes = baos.toByteArray();

        // 3) tentar retroceder o ponteiro para o início
        let rewound = false;

        // 3.a) reset() se marcamos
        if (marked) {
            try {
                is.reset();
                rewound = true;
                return { bytes: bytes, stream: is, rewound: true, replaced: false };
            } catch (_) {}
        }

        // 3.b) FileInputStream: usar channel.position(0)
        if (!rewound) {
            try {
                const FIS = Java.use('java.io.FileInputStream');
                if (isAssignableFrom.call(FIS.class, K)) {
                    const ch = Java.cast(is, FIS).getChannel();
                    ch.position(0);
                    return { bytes: bytes, stream: is, rewound: true, replaced: false };
                }
            } catch (_) {}
        }

        // 3.c) ByteArrayInputStream: reset para o início (mark inicial é 0)
        if (!rewound) {
            try {
                const BAIS = Java.use('java.io.ByteArrayInputStream');
                if (isAssignableFrom.call(BAIS.class, K)) {
                    is.reset(); // volta ao mark inicial (0)
                    return { bytes: bytes, stream: is, rewound: true, replaced: false };
                }
            } catch (_) {}
        }

        // 4) Caso genérico sem seek: substitui por um novo stream
        const replacement = BAIS.$new(bytes);
        return { bytes, stream: replacement, rewound: false, replaced: true };

    }

    Result.makeBufferedSink = function() {
        // ByteArrayOutputStream -> sink(out) -> buffer(sink) -> BufferedSink
        const out = BAOS.$new();
        const sinkObj2 = Method_invoke.call(sinkFactory, null, Java.array('java.lang.Object', [out]));
        const bsink = Method_invoke.call(MethodBufferFromSink, null, Java.array('java.lang.Object', [sinkObj2]));
        return {
            out,
            bsink
        }; // bsink é instância do tipo BufferedSinkClass
    };

    Result.makeBufferedSource = function(bytes) {
        // ByteArrayInputStream(bytes) -> source(in) -> buffer(source) -> BufferedSource
        const b = Java.array('byte', bytes || []);
        const inStream = BAIS.$new(b);
        const srcObj2 = Method_invoke.call(sourceFactory, null, Java.array('java.lang.Object', [inStream]));
        const bsource = Method_invoke.call(MethodBufferFromSource, null, Java.array('java.lang.Object', [srcObj2]));
        return {
            inStream,
            bsource
        }; // bsource é instância do tipo BufferedSourceClass
    };

    /**
    * Constrói um novo Response a partir de 'response', trocando o body por 'newBody'.
    * - Não altera outros campos: status, protocolo, request, mensagens, etc. (usa newBuilder()).
    * - Usa reflexão para evitar problemas de overload/obfuscação.
    *
    * @param {java.lang.Object} response   okhttp3|square|android Response
    * @param {java.lang.Object} newBody    okhttp3|square|android ResponseBody (ou wrapper seu)
    * @return {java.lang.Object}           novo Response
    */
    Result.buildNewResponseWithBody = function(response, bytes /* optional byte[] */ ) {
        return withLoaderOf(response, function() {

            const rClass = Obj.getClass.call(response); // java.lang.Class de Response
            const mInvoke = Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');
            const emptySig = Java.array('java.lang.Class', []);

            const responseBody = response.body();

            // ---- 1) response.newBuilder() ----
            let nb; // método newBuilder()
            try {
                nb = Cls.getMethod.overload('java.lang.String', '[Ljava.lang.Class;')
                    .call(rClass, 'newBuilder', emptySig);
            } catch (_) {
                nb = Cls.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;')
                    .call(rClass, 'newBuilder', emptySig);
                nb.setAccessible(true);
            }
            const builder = mInvoke.call(nb, response, Java.array('java.lang.Object', [])); // Response$Builder
            const bClass = Obj.getClass.call(builder);

            // ---- 2) builder.body(newBody) ----
            // Tenta achar método 'body' com 1 parâmetro compatível com ResponseBody
            const methods = Cls.getDeclaredMethods.overload().call(bClass);

            // Descobrir a classe ResponseBody do runtime atual
            const RB =
                Java.use('okhttp3.ResponseBody') ||
                Java.use('com.squareup.okhttp.ResponseBody') ||
                Java.use('com.android.okhttp.ResponseBody');

            const rbClass = RB.class;

            let bodySetter = null;
            for (let i = 0; i < methods.length; i++) {
                const m = methods[i];
                const ps = m.getParameterTypes();
                if (ps.length !== 1) continue;

                // nome do método (se disponível) — preferimos 'body'
                let isBodyName = false;
                try {
                    const nm = getMethodName(m);
                    isBodyName = (nm === 'body');
                } catch (_) {}

                // compatibilidade do parâmetro com ResponseBody
                const p0 = ps[0];
                const paramOk = p0.equals(rbClass) ||
                    p0.isAssignableFrom(rbClass) ||
                    rbClass.isAssignableFrom(p0);

                if (paramOk && (isBodyName || !bodySetter)) {
                    bodySetter = m; // guarda o melhor candidato
                    if (isBodyName) break; // achamos 'body' exato, pode parar
                }
            }

            if (!bodySetter) {
                throw new Error('Response.Builder.body(ResponseBody) não encontrado por reflexão.');
            }

            bodySetter.setAccessible(true);

            // 1) criar novo BufferedSource
            const payload = bytes || Java.array('byte', []); // se quiser, passe os bytes reais
            const made = Result.makeBufferedSource(payload); // { inStream, bsource }
            const newSrc = made.bsource;

            //    - obtém contentType() do original (via reflection)
            const mt = callNoArgViaReflection(responseBody, 'contentType'); // okhttp3.MediaType | null
            let contentLength = payload.length;

            let mtSigName = fusion_getClassName(returnOf(Cls.getMethod.overload('java.lang.String', '[Ljava.lang.Class;')
                    .call(rbClass, 'contentType', emptySig)));

            let sourceSigName = fusion_getClassName(returnOf(Cls.getMethod.overload('java.lang.String', '[Ljava.lang.Class;')
                    .call(rbClass, 'source', emptySig)));

            const Wrapper = Java.registerClass({
                name: 'com.stratasec.ResponseBodyWrapper',
                superClass: RB,
                methods: {
                    // MediaType contentType()
                    contentType: [{
                        returnType: mtSigName,
                        argumentTypes: [],
                        implementation: function() {
                            return mt; // pode ser null em alguns fluxos
                        }
                    }],
                    // long contentLength()
                    contentLength: [{
                        returnType: 'long',
                        argumentTypes: [],
                        implementation: function() {
                            return fusion_toLongPrimitive(contentLength);
                        }
                    }],
                    // BufferedSource source()  (nome ofuscado real, ex.: "okio.h")
                    source: [{
                        returnType: sourceSigName,
                        argumentTypes: [],
                        implementation: function() {
                            return newSrc; // instância da iface okio.* do mesmo loader
                        }
                    }]
                }

            });

            const newBody = Wrapper.$new();

            // garante que 'newBody' é do tipo certo (cast no wrapper da classe base)
            const castedBody = Java.cast(newBody, RB);
            mInvoke.call(bodySetter, builder, Java.array('java.lang.Object', [newBody]));

            // ---- 3) builder.build() ----
            let buildM;
            try {
                buildM = Cls.getMethod.overload('java.lang.String', '[Ljava.lang.Class;')
                    .call(bClass, 'build', emptySig);
            } catch (_) {
                buildM = Cls.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;')
                    .call(bClass, 'build', emptySig);
                buildM.setAccessible(true);
            }

            const newResponse = mInvoke.call(buildM, builder, Java.array('java.lang.Object', []));

            return newResponse;
        });
    }


    Result.getBufferFromSource = function(source) {
        
        // ---------- 1) Convert to  RealBufferedSource ----------
        const W = Java.use(fusion_getClassName(source));
        const K = W.class;

        let realBufferedSource = null;
        let bufferedSource = null;
        try {
            if (isAssignableFrom.call(Result.RealBufferedSourceClass, K)) realBufferedSource = Java.cast(source, Java.use(fusion_getClassName(Result.RealBufferedSourceClass)));
        } catch (_) {}

        if (realBufferedSource === null) {

            try {
                if (isAssignableFrom.call(Result.BufferedSourceClass, K)) bufferedSource = Java.cast(source, Java.use(fusion_getClassName(Result.BufferedSourceClass)));
            } catch (_) {}

            if (bufferedSource !== null) {
                realBufferedSource = Method_invoke.call(MethodBufferFromSource, null, Java.array('java.lang.Object', [bufferedSource]));
            }
        }

        if (realBufferedSource === null) return null;
        const methods             = Cls.getDeclaredMethods.overload().call(K);
        const buffer              = realBufferedSource;

        /*
        // Cannot use this
        // ---------- 2) Resolve and get Buffer object ----------
        const StringK           = Java.use('java.lang.String');
        const bufferName        = fusion_getClassName(Result.BufferClass);
        const buffermethods     = Cls.getDeclaredMethods.overload().call(Result.BufferClass);
        let methods             = Cls.getDeclaredMethods.overload().call(K);
        let buffer              = null;

        for (let i = 0; i < methods.length; i++) {
            const m = methods[i];
            if (!m || !m.getParameterTypes) continue;
            const ps = params(m);
            if (ps.length !== 0) continue;
            const r0 = returnOf(m);

            const r0name = fusion_getClassName(r0);
            if (r0name !== bufferName) continue;

            m.setAccessible(true);
            buffer = Method_invoke.call(m, realBufferedSource, Java.array('java.lang.Object', []));

        }

        let tstName = fusion_getClassName(buffer);
        fusion_sendMessage('I', `buffer 1: ${buffer}, name: ${tstName}, size: ${buffer.size}`);
        if (buffer === null) return null;
        methods = Cls.getDeclaredMethods.overload().call(Result.BufferClass);

        for (let i = 0; i < methods.length; i++) {
            const m = methods[i];
            if (!m || !m.getParameterTypes) continue;
            const ps = params(m);
            if (ps.length !== 0) continue;
            if (isStatic(m)) continue;

            fusion_sendMessage('I', `M: ${m}`);

            const name = getMethodName(m);
            if (name === 'size') {
                let s1 = Method_invoke.call(m, buffer, Java.array('java.lang.Object', []));
                fusion_sendMessage('I', `Size: ${s1}`);
            }
        }


        // ---------- 3) Resolve Buffer.clone() method ----------
        let cloneCandidate = null;
        for (let i = 0; i < methods.length; i++) {
            const m = methods[i];
            if (!m || !m.getParameterTypes) continue;
            const ps = params(m);
            if (ps.length !== 0) continue;
            if (isStatic(m)) continue;

            const r0name = fusion_getClassName(returnOf(m));
            if (r0name !== bufferName) continue;

            cloneCandidate = m;
            const name = getMethodName(m);
            if (name === 'clone') break; // metodo forte 'clone'
        }

        //Try to clone
        if (cloneCandidate !== null) {
            //Make object clone
            buffer = Method_invoke.call(cloneCandidate, buffer, Java.array('java.lang.Object', []));
        }

        fusion_sendMessage('I', `buffer 2: ${buffer}, size: ${buffer.size}`);
        */

        if (buffer === null) return null;

        // ---------- A) tentar inputStream(): InputStream ----------
        try{
            for (let i = 0; i < methods.length; i++) {
                const m = methods[i];
                const ps = m.getParameterTypes();
                if (ps.length !== 0) continue;
                const ret = m.getReturnType();
                const rname = fusion_getClassName(ret); // "java.io.InputStream" ?
                if (rname === 'java.io.InputStream') {
                    m.setAccessible(true);

                    const inStream = Java.cast(Method_invoke.call(m, buffer, Java.array('java.lang.Object', [])), Java.use('java.io.InputStream'));
                    if (inStream){
                        const r = readJavaInputStreamFully(inStream);
                        return {
                            bytes: r.bytes,
                            used: 'inputStream'
                        };
                    }
                }
            }
        } catch (_) {}

        // ---------- B) tentar readAll(BufferedSink): long ----------
        try {
            // 1) resolva/prepare um BufferedSink compatível com Okio
            let bufferedSinkName = fusion_getClassName(Result.BufferedSinkClass);
            const {
                out,
                bsink
            } = Result.makeBufferedSink();

            // 2) ache método com 1 parâmetro do tipo BufferedSink (nome ofuscado, ex.: "a")
            for (let i = 0; i < methods.length; i++) {
                const m = methods[i];
                const ps = m.getParameterTypes();
                if (ps.length !== 1) continue;
                const p0name = fusion_getClassName(ps[0]);
                if (p0name !== bufferedSinkName) continue;

                // retorno costuma ser long (mas não exigimos)
                m.setAccessible(true);
                Method_invoke.call(m, buffer, Java.array('java.lang.Object', [bsink]));

                // flush() do sink (nome geralmente preservado)
                try {
                    const flushM = Cls.getMethod.overload('java.lang.String', '[Ljava.lang.Class;')
                        .call(Obj.getClass.call(bsink), 'flush', Java.array('java.lang.Class', []));
                    Method_invoke.call(flushM, bsink, Java.array('java.lang.Object', []));
                } catch (_) {}

                const bytes = out.toByteArray();
                return {
                    bytes: bytes,
                    used: 'readAll'
                };
            }
        } catch (_) {}

        // ---------- C) fallback: método zero-args que retorna byte[] ----------
        try {
            for (let i = 0; i < methods.length; i++) {
                const m = methods[i];
                const ps = m.getParameterTypes();
                if (ps.length !== 0) continue;
                const ret = m.getReturnType();
                const rname = fusion_getClassName(ret); // "[B" é byte[]
                if (rname === '[B') {
                    m.setAccessible(true);
                    const bytes = Method_invoke.call(m, buffer, Java.array('java.lang.Object', []));
                    return {
                        bytes: bytes,
                        used: 'retByteArray'
                    };
                }
            }
        } catch (_) {}

        // Se nada funcionar:
        return {
            bytes: Java.array('byte', []),
            used: 'none'
        };
    };

    OKHTTP_LOGGING_DATA.OkioTypes = Result;
    return Result;
}
