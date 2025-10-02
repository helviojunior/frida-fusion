Java.perform(function() {

	const timeout = 15000;
    let hermes_js = "";
    
	var likelyRN = fusion_isReactNativeApp();
    if (!likelyRN) {
        fusion_sendMessage("E", "App does not looks like React Native, exiting...");
        return;
    }

    if (FUSION_HERMES_JS !== null && FUSION_HERMES_JS !== undefined) hermes_js = fusion_base64ToString(FUSION_HERMES_JS);

    if (hermes_js === null || hermes_js === undefined || hermes_js == "") {
    	fusion_sendMessage("E", "Hermes script is empty, exiting...");
        return;
    }

    // ------ Log catcher
    /*
    var PREFIX = '[FUSION] '; // <-- igual ao do JS
    var levels = {
        v: 0,
        d: 0,
        i: 0,
        w: 1,
        e: 2
    }; // mapeia Log.* -> (0=log,1=warn,2=error)

    // 1) classe “receptora” para você manipular os logs
    var FusionLogSink = Java.registerClass({
        name: 'com.stratasec.FusionLogSink',
        methods: {
            // static void ingest(int level, String msg)
            ingest: [{
                returnType: 'void', 
                argumentTypes: ['int', 'java.lang.String'], 
                implementation: function(lvl, msg) {
                    //fusion_sendMessage(lvl === 2 ? 'E' : (lvl === 1 ? 'W' : 'I'), msg);
                    fusion_sendMessage('W', msg);
                }
            }]
        }
    });

    // 2) intercepta android.util.Log.*(String tag, String msg)
    var Log = Java.use('android.util.Log');
    ['v', 'd', 'i', 'w', 'e'].forEach(function(fn) {
        try {
            var ov = Log[fn].overload('java.lang.String', 'java.lang.String');
            ov.implementation = function(tag, msg) {
                var ret = ov.call(this, tag, msg);
                try {
                    if (msg && msg.indexOf(PREFIX) === 0) {
                        // remove prefixo antes de enviar (opcional)
                        var clean = msg.substring(PREFIX.length);
                        FusionLogSink.ingest(levels[fn], clean);
                    }
                } catch (_) {}
                return ret;
            };
            fusion_sendMessage('D', `Hook em android.util.Log.${fn}(String,String)`);
        } catch (e) {
            // algumas OEMs têm variações; tudo bem se algum overload não existir
        }
    });
    */
    // ---- Injector section

    // Descobre o overload (String, String, boolean)
    function getLoadScriptOverload(inst) {
        const ovs = inst.loadScriptFromFile.overloads;
        for (let i = 0; i < ovs.length; i++) {
            const ov = ovs[i];
            if (!ov || !ov.argumentTypes) continue;
            const sig = ov.argumentTypes.map(t => t.className).join(', ');
            if (sig.indexOf('java.lang.String, java.lang.String') >= 0) return ovs[i];
        }
        throw new Error('Overload de loadScriptFromFile compatível não encontrado');
    }

	function fusion_waitForInitialization(onReady) {
	    const BooleanCls = Java.use('java.lang.Boolean');
        let start = Date.now();
	    let waitIntv = setInterval(function() {
	        try {
	            const ReactApp = Java.use('com.facebook.react.ReactApplication');
                const ActivityThread = Java.use('android.app.ActivityThread');
                const app = ActivityThread.currentApplication();
                const host = Java.cast(app, ReactApp).getReactNativeHost();
                const rim = host.getReactInstanceManager();

                const rc = rim.getCurrentReactContext();
                if (rc && rc.hasActiveCatalystInstance()) {

                    var SoLoader = Java.use('com.facebook.soloader.SoLoader');

                    // Reflection: pegar a Class e o método estático sem parâmetros
                    const clazz = SoLoader.class; // java.lang.Class<com.facebook.soloader.SoLoader>
                    const paramTypes = Java.array('java.lang.Class', []); // nenhum parâmetro
                    const m = clazz.getDeclaredMethod('isInitialized', paramTypes);
                    m.setAccessible(true);

                    // Invocar método estático: primeiro arg é null (static), depois args[]
                    const resObj = m.invoke(null, Java.array('java.lang.Object', []));
                    const isInit = Java.cast(resObj, BooleanCls).booleanValue();

                    if (isInit !== true) throw new Error('SoLoader.init() not yet called');
                }else{ 
                    throw new Error('ReactContext not yet already') }

	            clearInterval(waitIntv);
	            onReady();
	        } catch (e) {
                // not found yet -> check timeout
                if (Date.now() - start >= timeout) {
                    clearInterval(waitIntv);
                    fusion_sendMessage("E", `Timeout (${timeout}ms) reached waiting 'com.facebook.soloader.SoLoader' class.`);
                    return;
                }
            }
	    }, 100);
	}

    // Chama loadScriptFromFile na instância fornecida
    function injectOnInstance(catalystImpl, filePath) {
        const lsf = getLoadScriptOverload(catalystImpl);
        lsf.call(catalystImpl, filePath, filePath, false); // (fileName, sourceURL, sync=false)
        fusion_sendMessage("I", `loadScriptFromFile OK -> ${filePath}`);
    }

    fusion_waitForInitialization(function(SoLoader) {
        fusion_sendMessage("D", "SoLoader loaded!")

        var ActivityThread = Java.use("android.app.ActivityThread");
        var PackageManager = Java.use("android.content.pm.PackageManager");

        // Get the current application context
        var context = ActivityThread.currentApplication().getApplicationContext();
        var packageName = context.getPackageName();

        // Write the hermes-hook.js payload to file
        const fPath = `/data/data/${packageName}/files/hermes-hook.js`;
        fusion_sendMessage("I", `Sending JS script to android at ${fPath}`);

        try {
            const f = new File(fPath, 'w');
            f.write(hermes_js);
            f.close();
        } catch (e) {
            fusion_sendMessage("E", `Error sending JS file to device: ${e}\n${e.stack}`);
            return;
        }

        fusion_sendMessage("I", `JS sent to android at ${fPath}`);

        let injected = false;
        let start = Date.now();
        let intv = setInterval(function() {
            try {
                Java.choose('com.facebook.react.bridge.CatalystInstanceImpl', {
                    onMatch: function(inst) {
                        try {
                            injectOnInstance(inst, fPath);
                            injected = true;
                        } catch (e) {
                            fusion_sendMessage("E", `Error injecting JS script: ${e}\n${e.stack}`);
                        }
                    },
                    onComplete: function() { }
                });

                if (!injected) throw new Error('None CatalystInstanceImpl instance found!');

                clearInterval(intv);
                fusion_sendMessage("I", `Hermes JS injected`);
            } catch (e) {
                fusion_sendError(e);  /* ainda não carregou */ 

                // not found yet -> check timeout
                if (Date.now() - start >= timeout) {
                    clearInterval(intv);
                    fusion_sendMessage("E", `Timeout (${timeout}ms) reached waiting 'com.facebook.react.bridge.CatalystInstanceImpl' class.`);
                    return;
                }
            }
        }, 100);

    });

});