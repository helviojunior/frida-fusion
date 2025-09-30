setTimeout(function() { // avoid java.lang.ClassNotFoundException

    Java.perform(() => {

        const Ok3Request = fusion_useOrNull('okhttp3.Request');
        const Ok2Request = fusion_useOrNull('com.squareup.okhttp.Request');
        const Ok3RequestBody = fusion_useOrNull('okhttp3.RequestBody');
        const Ok2RequestBody = fusion_useOrNull('com.squareup.okhttp.RequestBody');
        const Ok3Interceptor = fusion_useOrNull('okhttp3.Interceptor');
        const Ok2Interceptor = fusion_useOrNull('com.squareup.okhttp.Interceptor');
        const OkioBuffer1 = fusion_useOrNull('okio.Buffer');
        const OkioBuffer2 = fusion_useOrNull("com.android.okhttp.okio.Buffer");

        const Request = Ok3Request || Ok2Request;
        const RequestBody = Ok3RequestBody || Ok2RequestBody;
        const Interceptor = Ok3Interceptor || Ok2Interceptor;
        const OkioBuffer = OkioBuffer1 ||  OkioBuffer2;

        if (!Request || !RequestBody || !Interceptor || !OkioBuffer) {
          fusion_sendMessage("E", "OkHttp/Okio classes não encontradas (v2/v3/v4).");
          return;
        }

        //Create a new instance of HttpLoggingInterceptor class
        function getInterceptor() {
            try {

                var ByteString = Java.use("com.android.okhttp.okio.ByteString");
                var Buffer = Java.use("com.android.okhttp.okio.Buffer");
                var MyLogger = Java.registerClass({
                    name: "okhttp3.MyLogger",
                    implements: [Interceptor],
                    methods: {
                        intercept: function(chain) {
                            var request = chain.request();

                            
                            
                            try {
                                fusion_sendMessageWithTrace("W", `MyLogger.intercept onEnter: ${request}\nrequest headers:\n ${request.headers()}`);
                                var b1 = null;
                                try { b1 = request.body ? request.body() : request.body; } catch (_) {}
                                if (b1) {
                                  var cName = fusion_getClassName(b1);
                                  fusion_sendMessageWithTrace("W", `Class: ${cName}`);
                                  var requestBody = Java.cast(b1, RequestBody);
                                  var contentLength = -1;
                                  try{
                                      contentLength = requestBody.contentLength();
                                  } catch (_) { }
                                  if (contentLength != 0) {
                                      var BufferObj = Buffer.$new();
                                      requestBody.writeTo(BufferObj);
                                      try {
                                          fusion_sendMessageWithTrace("W", `request body String:\n ${BufferObj.readString()}\n`);
                                      } catch (error) {
                                          try {
                                              fusion_sendMessageWithTrace("W", `request body ByteString:\n ${ByteString.of(BufferObj.readByteArray()).hex()}\n`);
                                          } catch (error) {
                                              fusion_sendMessageWithTrace("W", `Error 1: ${error}`)
                                          }
                                      }
                                  }
                                }
                            } catch (error) {
                                fusion_sendMessageWithTrace("W", `Error 2: ${error}`)
                                fusion_sendError(error);
                                
                            }
                            var response = chain.proceed(request);
                            try {
                                fusion_sendMessageWithTrace("W", `MyLogger.intercept onLeave: ${response}\nresponse headers:\n ${response.headers()}`);
                                var responseBody = response.body();
                                var contentLength = responseBody ? responseBody.contentLength() : 0;
                                if (contentLength > 0) {
                                    fusion_sendMessageWithTrace("W", `responsecontentLength: ${contentLength} \nresponseBody: ${responseBody}\n`);

                                    var ContentType = response.headers().get("Content-Type");
                                    fusion_sendMessageWithTrace("W", `ContentType: ${ContentType}`);
                                    if (ContentType.indexOf("video") == -1) {
                                        if (ContentType.indexOf("application") == 0) {
                                            var source = responseBody.source();
                                            if (ContentType.indexOf("application/zip") != 0) {
                                                try {
                                                    fusion_sendMessageWithTrace("W", `\nresponse.body StringClass\n ${source.readUtf8()}\n`);
                                                } catch (error) {
                                                    try {
                                                        fusion_sendMessageWithTrace("W", `\nresponse.body ByteString\n ${source.readByteString().hex()}\n`);
                                                    } catch (error) {
                                                        fusion_sendMessageWithTrace("W", `Error 4: ${error}`)
                                                    }
                                                }
                                            }
                                        }

                                    }

                                }

                            } catch (error) {
                                fusion_sendMessageWithTrace("W", `Error 3: ${error}`)
                            }
                            return response;
                        }
                    }
                });

                var logInstance = MyLogger.$new();

                return logInstance;

            } catch (err) {
                fusion_sendMessageWithTrace("W", `Error creating interceptor: ${err}`)
                return null;
            }
        }

        try {
            var Builder = Java.use('okhttp3.OkHttpClient$Builder')
            var build = Builder.build.overload();
            var addInterceptor = Builder.addInterceptor.overload('okhttp3.Interceptor');

            var interceptorObj = getInterceptor();

            build.implementation = function() {
                fusion_sendMessageWithTrace("W", 'OkHttpClient$Builder ==> Adding log interceptor')
                this.interceptors().clear();

                //Add the new interceptor before call the 'build' function
                try {
                    this.interceptors().add(interceptorObj);
                } catch (err) {
                    fusion_sendMessageWithTrace("W", `OkHttpClient$Builder.addInterceptor error: ${err}`);
                }

                return build.call(this);
            }

            addInterceptor.implementation = function(interceptor) {
                fusion_sendMessageWithTrace("W", 'OkHttpClient$Builder->addInterceptor ==> Adding log interceptor')

                this.interceptors().clear();
                this.interceptors().add(interceptorObj);
                return this;
                //return this.addInterceptor(interceptor);
            };

        } catch (err) {
            fusion_sendMessageWithTrace("W", `OkHttpClient$Builder error: ${err}`);
            //console.log(err);
        }


    });


}, 0);
